"""AF_UNIX is deny-by-default; docker.sock is never allowlisted."""

from __future__ import annotations


def test_docker_sock_is_denied(run_guarded) -> None:  # type: ignore[no-untyped-def]
    verdict = run_guarded(
        "socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect('/var/run/docker.sock')"
    )
    assert verdict == "BLOCKED"


def test_arbitrary_unix_path_is_denied(run_guarded) -> None:  # type: ignore[no-untyped-def]
    verdict = run_guarded(
        "socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect('/tmp/whatever.sock')"
    )
    assert verdict == "BLOCKED"


def test_allowlisted_unix_path_connects(run_guarded) -> None:  # type: ignore[no-untyped-def]
    # Positive control: a listening unix socket whose path is transiently allowlisted.
    # A SHORT temp path (AF_UNIX has a ~104-char limit; pytest's tmp_path overflows it).
    setup = (
        "import tempfile, os\n"
        "sock = os.path.join(tempfile.mkdtemp(), 's')\n"
        "srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); srv.bind(sock); srv.listen()"
    )
    install = (
        "install_egress_guard(allow_unix=[sock])\n"
        "c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)"
    )
    assert run_guarded("c.connect(sock)", setup=setup, install=install) == "ALLOWED"
