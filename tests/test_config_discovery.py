import json
import shutil
from pathlib import Path

from caplock.config_discovery import (
    REDACTED,
    discover,
    parse_server,
    ConfigSource,
    redact_args,
    redact_url,
    strip_jsonc,
)

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "configs"

DUMMY = "dummy-value-not-a-real-secret-7f3a9c"


def make_ws(tmp_path, vscode=None, portable=None):
    if vscode is not None:
        (tmp_path / ".vscode").mkdir()
        shutil.copy(FIX / vscode, tmp_path / ".vscode" / "mcp.json")
    if portable is not None:
        shutil.copy(FIX / portable, tmp_path / ".mcp.json")
    return tmp_path


def test_vscode_format_is_read(tmp_path):
    d = discover(make_ws(tmp_path, vscode="vscode_mcp.json"))
    assert d.errors == []
    assert set(d.entries) == {"filesystem", "github", "docs"}
    fs = d.entries["filesystem"]
    assert fs.transport == "stdio" and fs.command == "npx"
    assert fs.args == ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "${workspaceFolder}"]
    assert fs.source.path == ".vscode/mcp.json" and fs.source.format == "vscode"
    gh = d.entries["github"]
    assert gh.env_keys == ["GITHUB_PERSONAL_ACCESS_TOKEN"]
    assert gh.interactive_inputs == ["github-token"]
    assert gh.requires_interactive_input
    docs = d.entries["docs"]
    assert docs.transport == "http"
    assert docs.header_keys == ["Authorization"]
    assert docs.url == f"https://mcp.docs.example.com/mcp?tenant={REDACTED}"
    assert docs.env_refs == ["DOCS_TENANT"]
    assert docs.interactive_inputs == ["github-token"]


def test_portable_format_is_read(tmp_path):
    d = discover(make_ws(tmp_path, portable="portable_mcp.json"))
    assert d.errors == []
    assert set(d.entries) == {"filesystem", "fetch", "time", "custom", "remote-search"}
    assert d.entries["fetch"].transport == "stdio"  # type "local" -> stdio
    assert d.entries["remote-search"].transport == "http"
    assert d.entries["custom"].env_keys == ["LOG_LEVEL"]
    assert all(e.source.format == "portable" for e in d.entries.values())


def test_claude_desktop_file_given_explicitly(tmp_path):
    d = discover(tmp_path, extra_configs=[FIX / "claude_desktop_config.json"])
    assert set(d.entries) == {"memory", "sqlite"}
    assert d.entries["memory"].source.format == "portable"


def test_jsonc_comments_and_trailing_commas():
    text = '{ // c\n "a": "http://x//y", /* b */ "b": [1,2,], }'
    assert json.loads(strip_jsonc(text)) == {"a": "http://x//y", "b": [1, 2]}


def test_duplicate_entries_are_kept_and_drift_detected(tmp_path):
    d = discover(make_ws(tmp_path, vscode="vscode_mcp.json", portable="portable_mcp.json"))
    occ = d.occurrences["filesystem"]
    assert [e.source.path for e in occ] == [".vscode/mcp.json", ".mcp.json"]
    assert d.entries["filesystem"].source.path == ".vscode/mcp.json"  # first wins
    assert "filesystem" in d.drift  # pinned vs floating -> different content


def test_identical_duplicates_are_not_drift(tmp_path):
    cfg = {"mcpServers": {"x": {"command": "uvx", "args": ["a==1.0.0"]}}}
    (tmp_path / ".mcp.json").write_text(json.dumps(cfg))
    other = tmp_path / "other.json"
    other.write_text(json.dumps(cfg, indent=4))
    d = discover(tmp_path, extra_configs=[other])
    assert len(d.occurrences["x"]) == 2
    assert d.drift == {}


def test_env_header_query_values_never_appear(tmp_path):
    cfg = {
        "servers": {
            "s": {
                "command": "npx",
                "args": ["-y", "pkg@1.0.0", "--api-key", DUMMY, f"--token={DUMMY}"],
                "env": {"API_KEY": DUMMY, "OTHER": DUMMY},
            },
            "d": {
                "command": "docker",
                "args": ["run", "-i", "-e", f"SECRET={DUMMY}", f"--env=X={DUMMY}", "img:1.0"],
            },
            "h": {
                "type": "http",
                "url": f"https://user:{DUMMY}@host.example.com/mcp?key={DUMMY}&x=1#frag",
                "headers": {"Authorization": f"Bearer {DUMMY}"},
            },
        }
    }
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "mcp.json").write_text(json.dumps(cfg))
    d = discover(tmp_path)
    blob = json.dumps(
        {n: e.canonical() for n, e in d.entries.items()}
    ) + repr(d.entries)
    assert DUMMY not in blob
    assert d.entries["s"].env_keys == ["API_KEY", "OTHER"]
    assert d.entries["s"].args == ["-y", "pkg@1.0.0", "--api-key", REDACTED, f"--token={REDACTED}"]
    assert d.entries["d"].args == ["run", "-i", "-e", f"SECRET={REDACTED}", f"--env=X={REDACTED}", "img:1.0"]
    assert d.entries["h"].url == f"https://host.example.com/mcp?key={REDACTED}&x={REDACTED}"


def test_token_shaped_args_and_path_segments_are_redacted():
    tok = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2"
    assert redact_args(["--repo", "x", tok]) == ["--repo", "x", REDACTED]
    assert redact_args(["mcp-server-time==0.6.2", "/home/u1/p2/x"]) == ["mcp-server-time==0.6.2", "/home/u1/p2/x"]
    assert redact_url("https://a.example/mcp/sk-abcdefghijklmnop1234/sse") == f"https://a.example/mcp/{REDACTED}/sse"


def test_unresolved_variables_are_kept_not_resolved():
    e = parse_server(
        "x",
        {"command": "npx", "args": ["--token", "${input:tok}", "${env:HOME}"]},
        ConfigSource(".vscode/mcp.json", "vscode"),
    )
    assert e.args == ["--token", "${input:tok}", "${env:HOME}"]
    assert e.interactive_inputs == ["tok"]
    assert e.env_refs == ["HOME"]


def test_malformed_config_is_reported_not_crashing(tmp_path):
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {"x": {"type": "stdio"}}}')
    d = discover(tmp_path)
    assert d.entries == {}
    assert d.errors and "needs a command" in d.errors[0]
