import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Tests must not touch the network: any outbound socket connection fails the test."""

    def guard(self, address, *a, **k):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            raise AssertionError(f"network access attempted in tests: {address!r}")
        return real_connect(self, address, *a, **k)

    real_connect = socket.socket.connect
    monkeypatch.setattr(socket.socket, "connect", guard)
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("network access attempted in tests")))


@pytest.fixture(scope="session")
def locked_base(tmp_path_factory):
    """The benign demo workspace, locked once per test session (Phase 2 report tests)."""
    import harness as h

    ws = h.prepare_workspace(tmp_path_factory.mktemp("locked") / "base")
    code, out = h.run(["lock"] + h.cli_args(ws))
    assert code == 0, out
    return ws
