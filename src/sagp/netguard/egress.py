"""The in-process egress guard (CLAUDE.md invariant 2).

Two layers, because one is not enough:

* **L1** — monkeypatch ``socket.socket.connect`` / ``socket.getaddrinfo``. Blocks
  the common path with a clear error, early.
* **L2** — ``sys.addaudithook`` on the PEP 578 events ``socket.connect``,
  ``socket.getaddrinfo`` and ``subprocess.Popen``. This is the real guarantee: a
  raw ``_socket.socket().connect()`` never touches the patched ``socket.socket``
  and so bypasses L1, but it still emits the ``socket.connect`` audit event.

Only loopback is allowed (127.0.0.0/8, ::1, localhost — Ollama on :11434, Qdrant
on :6333/6334). AF_UNIX is deny-by-default (``/var/run/docker.sock`` is never
allowlisted). Subprocesses are matched on **(resolved argv[0], exact argv tuple)**
— never path alone, since an allowlisted binary can egress via its own arguments
(``ollama pull``); the sole default entry is ``ollama --version``.

HONEST LIMITS (LIMITATIONS.md): neither layer sees native code that calls
``connect(2)`` without CPython's socket layer (grpcio's C core, ONNX Runtime,
ctypes) or a sibling process (the Ollama server, Docker). Only ``make seal-pf``
closes those, and only for UID-owned TCP/UDP.

An installed audit hook cannot be removed, by design — this module is meant to be
installed once at process start (the ``.pth`` bootstrap) and never disarmed.
"""

from __future__ import annotations

import os
import shutil
import socket
import sys
from collections import deque
from collections.abc import Iterable, Sequence

_LOOPBACK_NAMES = frozenset({"localhost", "127.0.0.1", "::1", "::ffff:127.0.0.1", ""})


class EgressViolation(Exception):
    """Raised when in-process code attempts a non-allowlisted network egress."""


def _is_loopback(host: object) -> bool:
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str):
        return False
    return host in _LOOPBACK_NAMES or host.startswith("127.")


def _subprocess_key(executable: object, argv: object) -> tuple[str, tuple[str, ...]]:
    exe = executable if isinstance(executable, str) else ""
    args: tuple[str, ...]
    if isinstance(argv, (list, tuple)) and argv:
        args = tuple(str(a) for a in argv)
        exe = exe or args[0]
    else:
        args = (exe,)
    resolved = os.path.realpath(shutil.which(exe) or exe)
    return (resolved, args)


def default_subprocess_allowlist() -> set[tuple[str, tuple[str, ...]]]:
    """The sole default: ``ollama --version`` (if ollama is on PATH)."""
    ollama = shutil.which("ollama")
    if ollama is None:
        return set()
    return {(os.path.realpath(ollama), ("ollama", "--version"))}


# Module state (install-once).
_installed = False
_allow_unix: frozenset[str] = frozenset()
_allow_subprocess: frozenset[tuple[str, tuple[str, ...]]] = frozenset()
_violations: deque[str] = deque(maxlen=1000)


def violations() -> list[str]:
    return list(_violations)


def _record(msg: str) -> EgressViolation:
    _violations.append(msg)
    return EgressViolation(msg)


def _check_address(address: object) -> None:
    if isinstance(address, str) and address not in _allow_unix:  # AF_UNIX
        raise _record(f"AF_UNIX egress blocked -> {address}")
    if isinstance(address, (tuple, list)) and address and not _is_loopback(address[0]):
        raise _record(f"egress blocked -> {address[0]}")


def _install_l1() -> None:
    orig_connect = socket.socket.connect
    orig_getaddrinfo = socket.getaddrinfo

    def guarded_connect(self: socket.socket, address: object) -> object:
        _check_address(address)
        return orig_connect(self, address)  # type: ignore[arg-type]

    def guarded_getaddrinfo(host: object, *args: object, **kwargs: object) -> object:
        if not _is_loopback(host):
            raise _record(f"getaddrinfo blocked -> {host!r}")
        return orig_getaddrinfo(host, *args, **kwargs)  # type: ignore[arg-type]

    socket.socket.connect = guarded_connect  # type: ignore[method-assign, assignment]
    socket.getaddrinfo = guarded_getaddrinfo  # type: ignore[assignment]


def _audit_hook(event: str, args: tuple[object, ...]) -> None:
    if event == "socket.connect":
        _check_address(args[1])
    elif event == "socket.getaddrinfo":
        if not _is_loopback(args[0]):
            raise _record(f"getaddrinfo blocked -> {args[0]!r}")
    elif event == "subprocess.Popen":
        key = _subprocess_key(args[0], args[1])
        if key not in _allow_subprocess:
            raise _record(f"subprocess egress blocked -> {key[1]}")


def install_egress_guard(
    *,
    allow_unix: Iterable[str] = (),
    allow_subprocess: Iterable[tuple[str, Sequence[str]]] | None = None,
) -> None:
    """Install L1 + L2. Idempotent; the audit hook is permanent once added."""
    global _installed, _allow_unix, _allow_subprocess
    if _installed:
        return
    _allow_unix = frozenset(allow_unix)
    if allow_subprocess is None:
        _allow_subprocess = frozenset(default_subprocess_allowlist())
    else:
        _allow_subprocess = frozenset((p, tuple(a)) for p, a in allow_subprocess)
    _install_l1()
    sys.addaudithook(_audit_hook)
    _installed = True
