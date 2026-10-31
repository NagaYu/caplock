import json
import sys
import time
from pathlib import Path

import pytest

from caplock.enumerate import (
    EnumerationError,
    LEGACY_PROTOCOL_VERSIONS,
    enumerate_stdio,
    load_recorded_surface,
    minimal_env,
)

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "fixtures" / "servers" / "notes_server.py"
TOOLS = ROOT / "fixtures" / "servers" / "tools"
SURFACES = ROOT / "fixtures" / "surfaces"


def argv(*extra):
    return [sys.executable, str(SERVER), *extra]


def test_modern_discover_and_tools_list():
    s = enumerate_stdio(argv())  # default fixture is dual-era: the modern path is taken
    assert s.era == "modern" and s.protocol_version == "2026-07-28"
    assert [t["name"] for t in s.tools] == ["read_note", "write_note", "fetch_status"]
    assert s.server_info["name"] == "caplock-fixture-notes"
    assert s.resources == [{"uri": "notes://index", "name": "Notes index", "mimeType": "application/json"}]
    assert s.prompts and s.prompts[0]["name"] == "summarize_notes"
    assert s.method == "launch"


def test_modern_only_server():
    s = enumerate_stdio(argv("--era", "modern"))
    assert s.era == "modern" and len(s.tools) == 3


def test_legacy_fallback_when_discover_is_rejected():
    s = enumerate_stdio(argv("--era", "legacy"))
    assert s.era == "legacy" and s.protocol_version == LEGACY_PROTOCOL_VERSIONS[0]
    assert [t["name"] for t in s.tools] == ["read_note", "write_note", "fetch_status"]
    assert any("code -32601" in n for n in s.notes)


def test_legacy_fallback_when_discover_is_ignored():
    s = enumerate_stdio(argv("--era", "legacy-silent"), probe_timeout=0.3)
    assert s.era == "legacy" and len(s.tools) == 3
    assert any("unanswered" in n for n in s.notes)


def test_legacy_negotiation_accepts_older_supported_version():
    s = enumerate_stdio(argv("--era", "legacy", "--protocol-version", "2025-03-26"))
    assert s.protocol_version == "2025-03-26"


def test_unsupported_versions_fail():
    with pytest.raises(EnumerationError, match="no mutually supported"):
        enumerate_stdio(argv("--mode", "bad-version"))
    with pytest.raises(EnumerationError, match="unsupported protocol version"):
        enumerate_stdio(argv("--era", "legacy", "--mode", "bad-version"))


def test_modern_version_error_does_not_fall_back_to_initialize():
    # The dual-era fixture would answer initialize, but a recognized modern error
    # (-32022) must not trigger the legacy fallback.
    with pytest.raises(EnumerationError, match="no mutually supported"):
        enumerate_stdio(argv("--mode", "version-error"))


@pytest.mark.parametrize("era", ["dual", "legacy"])
def test_pagination_follows_next_cursor(era):
    s = enumerate_stdio(argv("--era", era, "--page-size", "1", "--tools", str(TOOLS / "D_tool_added.json")))
    assert [t["name"] for t in s.tools] == ["read_note", "write_note", "fetch_status", "run_command"]


def test_server_requests_and_notifications_are_handled():
    s = enumerate_stdio(argv("--era", "legacy", "--mode", "server-ping"))
    assert len(s.tools) == 3
    assert any("ping" in n for n in s.notes)


def test_aux_lists_absent_or_failing_are_not_fatal():
    s = enumerate_stdio(argv("--mode", "no-aux"))
    assert len(s.tools) == 3 and s.resources is None and s.prompts is None
    s = enumerate_stdio(argv("--mode", "aux-error"))
    assert len(s.tools) == 3 and s.resources is None
    assert any("resources/list skipped" in n for n in s.notes)


def test_timeout_is_an_error_not_an_empty_surface():
    t0 = time.monotonic()
    with pytest.raises(EnumerationError, match="timed out"):
        enumerate_stdio(argv("--mode", "hang"), timeout=0.5)
    assert time.monotonic() - t0 < 5


def test_timeout_during_tools_list():
    with pytest.raises(EnumerationError, match="tools/list: timed out"):
        enumerate_stdio(argv("--mode", "hang-tools"), timeout=0.5)


def test_crash_is_an_error():
    with pytest.raises(EnumerationError, match="exited"):
        enumerate_stdio(argv("--mode", "crash"))


def test_missing_command_is_an_error():
    with pytest.raises(EnumerationError, match="failed to start"):
        enumerate_stdio(["/nonexistent/caplock-test-binary"])


def test_duplicate_tool_names_fail(tmp_path):
    f = tmp_path / "dup.json"
    f.write_text(json.dumps({"tools": [{"name": "a"}, {"name": "a"}]}))
    with pytest.raises(EnumerationError, match="duplicate"):
        enumerate_stdio(argv("--tools", str(f)))


def test_minimal_env_drops_everything_else(monkeypatch):
    monkeypatch.setenv("CAPLOCK_TEST_SECRET", "x")
    monkeypatch.setenv("PATH", "/usr/bin")
    env = minimal_env()
    assert "CAPLOCK_TEST_SECRET" not in env and env["PATH"] == "/usr/bin"
    assert minimal_env(["CAPLOCK_TEST_SECRET"])["CAPLOCK_TEST_SECRET"] == "x"


def test_child_does_not_inherit_secrets(tmp_path, monkeypatch):
    # The child reports its environment keys via a tool name list.
    script = tmp_path / "envdump.py"
    script.write_text(
        "import json,os,sys\n"
        "for line in sys.stdin:\n"
        "  m=json.loads(line)\n"
        "  if m.get('method')=='initialize':\n"
        "    print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':{'protocolVersion':'2025-06-18','capabilities':{'tools':{}}}}),flush=True)\n"
        "  elif m.get('method')=='tools/list':\n"
        "    print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':{'tools':[{'name':k} for k in sorted(os.environ)]}}),flush=True)\n"
    )
    monkeypatch.setenv("CAPLOCK_TEST_SECRET", "x")
    s = enumerate_stdio([sys.executable, str(script)])
    names = {t["name"] for t in s.tools}
    assert "CAPLOCK_TEST_SECRET" not in names


def test_recorded_surface_jsonrpc_response():
    s = load_recorded_surface(SURFACES / "docs_remote.json")
    assert s.method == "recorded" and [t["name"] for t in s.tools] == ["search_docs"]


def test_recorded_surface_pages():
    s = load_recorded_surface(SURFACES / "paged_two_pages.json")
    assert [t["name"] for t in s.tools] == ["list_items", "delete_item"]


def test_recorded_surface_garbage(tmp_path):
    f = tmp_path / "x.json"
    f.write_text('{"nope": 1}')
    with pytest.raises(EnumerationError):
        load_recorded_surface(f)
