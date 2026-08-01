"""Egress probes and their paired positive controls (the *measurement* half of
the proof harness; ``evidence.py`` is the *judgment* half).

Every probe runs in a **fresh child interpreter** with the guard installed there,
for the same reason the security tests do (`tests/security/`): ``sys.addaudithook``
is process-permanent, so the only honest way to run N different guard
configurations is N processes — which is also exactly how the guard runs in
production (installed once at process start, never disarmed).

A probe reports one of three outcomes and the guard's violation count:

* ``blocked``  — an ``EgressViolation`` was raised.
* ``allowed``  — the body ran to completion with no exception.
* ``error``    — some other exception (an assertion inside the body, a missing
  dependency): the caller decides whether that fails the assertion.

An **egress probe** is expected to be ``blocked``; a **positive control** is
expected to be ``allowed`` — a companion that proves the assertion *can* pass when
it should, so a green result is never just the network being absent. The judging
of outcome→ok lives in ``verify_airgap.py``, not here: this module reports facts.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from dataclasses import dataclass

# --- reusable setup snippets (run BEFORE the guard is installed) --------------

_LOOPBACK_TCP = """
import threading
_srv = socket.socket(); _srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
_srv.bind(("127.0.0.1", 0)); _srv.listen(); _PORT = _srv.getsockname()[1]
def _serve():
    try:
        conn, _ = _srv.accept(); conn.sendall(conn.recv(64) or b"x"); conn.close()
    except OSError:
        pass
threading.Thread(target=_serve, daemon=True).start()
"""

_LOOPBACK_HTTP = """
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
class _H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a):
        pass
_hsrv = HTTPServer(("127.0.0.1", 0), _H); _HPORT = _hsrv.server_address[1]
threading.Thread(target=_hsrv.serve_forever, daemon=True).start()
"""

_LOOPBACK_UNIX = """
import tempfile, threading
_SOCK = os.path.join(tempfile.mkdtemp(), "s")  # short path (AF_UNIX ~104-char cap)
_usrv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); _usrv.bind(_SOCK); _usrv.listen()
def _uaccept():
    try:
        conn, _ = _usrv.accept(); conn.close()
    except OSError:
        pass
threading.Thread(target=_uaccept, daemon=True).start()
"""


@dataclass(frozen=True)
class Probe:
    name: str
    body: str
    setup: str = ""
    install: str = "install_egress_guard()"


@dataclass
class ProbeResult:
    name: str
    outcome: str  # blocked | allowed | error
    violations: int
    elapsed_ms: float
    detail: str = ""


# Egress probes — each MUST be blocked. External hosts (1.1.1.1, huggingface.co,
# example.com) and docker.sock are never allowlisted.
EGRESS_PROBES: dict[str, Probe] = {
    "l1_tcp": Probe("l1_tcp", "socket.create_connection(('1.1.1.1', 443), timeout=2)"),
    "l2_raw_socket": Probe(
        "l2_raw_socket",
        "import _socket\n_socket.socket().connect(('1.1.1.1', 443))",
    ),
    "getaddrinfo": Probe("getaddrinfo", "socket.getaddrinfo('huggingface.co', 443)"),
    "httpx": Probe("httpx", "import httpx\nhttpx.get('https://huggingface.co', timeout=2)"),
    "subprocess_curl": Probe(
        "subprocess_curl", "subprocess.Popen(['curl', 'https://example.com'])"
    ),
    "af_unix_docker": Probe(
        "af_unix_docker",
        "socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect('/var/run/docker.sock')",
    ),
}

# Positive controls — each MUST be allowed (run to completion). They prove the
# guard permits the traffic it is supposed to, so a blocked egress probe is not
# just "the network is gone".
POSITIVE_CONTROLS: dict[str, Probe] = {
    "loopback_tcp": Probe(
        "loopback_tcp",
        "c = socket.create_connection(('127.0.0.1', _PORT), timeout=2)\n"
        "c.sendall(b'ping'); assert c.recv(16); c.close()",
        setup=_LOOPBACK_TCP,
    ),
    "loopback_getaddrinfo": Probe(
        "loopback_getaddrinfo", "assert socket.getaddrinfo('localhost', 80)"
    ),
    "loopback_httpx": Probe(
        "loopback_httpx",
        "import httpx\nr = httpx.get(f'http://127.0.0.1:{_HPORT}/healthz', timeout=2)\n"
        "assert r.status_code == 200",
        setup=_LOOPBACK_HTTP,
    ),
    "loopback_unix": Probe(
        "loopback_unix",
        "c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); c.connect(_SOCK); c.close()",
        setup=_LOOPBACK_UNIX,
        install="install_egress_guard(allow_unix=[_SOCK])",
    ),
    "subprocess_ollama": Probe(
        "subprocess_ollama",
        "import shutil\n"
        "if shutil.which('ollama') is None:\n"
        "    raise RuntimeError('ollama not on PATH')\n"
        "subprocess.run(['ollama', '--version'], capture_output=True, timeout=15)",
    ),
}


def _child_source(probe: Probe) -> str:
    body = textwrap.indent(textwrap.dedent(probe.body).strip(), "    ")
    setup = textwrap.dedent(probe.setup).strip()
    return textwrap.dedent(
        """
        import json, time, socket, subprocess, os, sys
        {setup}
        from sagp.netguard.egress import install_egress_guard, EgressViolation, violations
        {install}
        _t0 = time.perf_counter()
        _outcome, _detail = "allowed", ""
        try:
        {body}
        except EgressViolation as _e:
            _outcome, _detail = "blocked", str(_e)[:200]
        except Exception as _e:
            _outcome, _detail = "error", type(_e).__name__ + ": " + str(_e)[:200]
        _ms = (time.perf_counter() - _t0) * 1000
        print(json.dumps({{
            "outcome": _outcome, "elapsed_ms": round(_ms, 3),
            "detail": _detail, "violations": len(violations()),
        }}))
        """
    ).format(setup=setup, install=probe.install, body=body)


def run_probe(probe: Probe, *, timeout: float = 40.0) -> ProbeResult:
    """Execute ``probe`` in a fresh guarded interpreter and report the facts."""
    proc = subprocess.run(
        [sys.executable, "-c", _child_source(probe)],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    if not lines:
        return ProbeResult(probe.name, "error", 0, 0.0, (proc.stderr or "no output")[-200:])
    try:
        data = json.loads(lines[-1])
    except json.JSONDecodeError:
        return ProbeResult(probe.name, "error", 0, 0.0, lines[-1][:200])
    return ProbeResult(
        name=probe.name,
        outcome=str(data["outcome"]),
        violations=int(data["violations"]),
        elapsed_ms=float(data["elapsed_ms"]),
        detail=str(data["detail"]),
    )


# --- assertion 8: the sealed-email contrast (violation COUNT, not exception) ---
# tldextract swallows the raised EgressViolation and falls back to its snapshot,
# so the exception never propagates — but the guard still RECORDS the attempt in
# violations(). The proof is therefore the count: sealed == 0, stock > 0.

SEALED_EMAIL = Probe(
    "sealed_email",
    """
    import tempfile
    from sagp.guardrails.recognizers import SealedEmailRecognizer
    rec = SealedEmailRecognizer(cache_dir=tempfile.mkdtemp())
    res = rec.analyze("write to a.person@example.com please", ["EMAIL_ADDRESS"], None)
    assert any(r.entity_type == "EMAIL_ADDRESS" for r in res), "sealed recognizer missed the email"
    assert len(violations()) == 0, "sealed recognizer touched the network"
    """,
)

STOCK_EMAIL = Probe(
    "stock_email",
    """
    import tempfile, os
    os.environ["TLDEXTRACT_CACHE"] = tempfile.mkdtemp()  # cold cache -> forces a fetch attempt
    from presidio_analyzer.predefined_recognizers import EmailRecognizer
    rec = EmailRecognizer()
    rec.analyze("write to a.person@example.com please", ["EMAIL_ADDRESS"], None)
    """,
)
