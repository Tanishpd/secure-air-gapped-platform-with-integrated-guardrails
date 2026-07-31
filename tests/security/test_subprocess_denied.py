"""Subprocesses are denied unless (resolved argv[0], exact argv tuple) is allowlisted."""

from __future__ import annotations

import shutil

_ECHO = shutil.which("echo") or "/bin/echo"
_ALLOW = f"install_egress_guard(allow_subprocess=[(os.path.realpath({_ECHO!r}), ('echo', 'hi'))])"


def test_curl_is_blocked(run_guarded) -> None:  # type: ignore[no-untyped-def]
    assert run_guarded("subprocess.Popen(['curl', 'https://example.com'])") == "BLOCKED"


def test_default_allowlist_blocks_arbitrary_subprocess(run_guarded) -> None:  # type: ignore[no-untyped-def]
    assert run_guarded("subprocess.Popen(['ls', '-la', '/'])") == "BLOCKED"


def test_allowlisted_command_runs(run_guarded) -> None:  # type: ignore[no-untyped-def]
    assert run_guarded("subprocess.Popen(['echo', 'hi']).wait()", install=_ALLOW) == "ALLOWED"


def test_allowlisted_binary_wrong_argv_is_blocked(run_guarded) -> None:  # type: ignore[no-untyped-def]
    # Same binary, different arguments -> blocked (path alone is never enough:
    # `ollama --version` is allowed, `ollama pull` would egress).
    assert run_guarded("subprocess.Popen(['echo', 'DIFFERENT'])", install=_ALLOW) == "BLOCKED"
