import json
import shlex
import subprocess
import sys

import harness as h

DUMMY = "dummy-value-not-a-real-secret-7f3a9c"


def test_round_trip_lock_verify_mutate_relock(tmp_path):
    ws = h.prepare_workspace(tmp_path / "ws")
    base = h.cli_args(ws)
    assert h.run(["lock"] + base)[0] == 0
    assert h.run(["verify"] + base)[0] == 0

    mutated = h.cli_args(ws, notes_tools="C_readonly_flipped.json")
    code, out = h.run(["verify"] + mutated)
    assert code == 1 and "annotation_readonly_revoked" in out

    # Overwriting needs confirmation; without a TTY and without --yes nothing is written.
    before = (ws / "mcp-lock.json").read_text()
    code, out = h.run(["lock"] + mutated)
    assert code == 3 and "nothing written" in out
    assert (ws / "mcp-lock.json").read_text() == before

    code, out = h.run(["lock", "--yes"] + mutated)
    assert code == 0 and "annotation_readonly_revoked" in out  # summary shown before writing
    assert h.run(["verify"] + mutated)[0] == 0
    # Returning to readOnlyHint=true narrows capability: reported, but not high.
    code, out = h.run(["verify"] + base)
    assert code == 0 and "capability_reduced" in out and "NO HIGH-SEVERITY CHANGES" in out


def test_round_trip_through_floating_spec(tmp_path):
    ws = h.prepare_workspace(tmp_path / "ws")
    assert h.run(["lock"] + h.cli_args(ws))[0] == 0
    args = h.apply_scenario(ws, {"after": {"vscode_config": "G2_latest.json"}})
    assert h.run(["verify"] + args)[0] == 2
    code, out = h.run(["lock", "--yes"] + args)
    assert code == 2 and "unverifiable" in out  # written, but honestly not complete
    code, out = h.run(["verify"] + args)
    assert code == 2 and "floating_version" in out


def test_subprocess_entry_point(tmp_path):
    ws = h.prepare_workspace(tmp_path / "ws")
    env = {"PYTHONPATH": str(h.ROOT / "src"), "PATH": "/usr/bin:/bin"}
    cmd = [sys.executable, "-m", "caplock", "lock"] + h.cli_args(ws)
    assert subprocess.run(cmd, env=env, capture_output=True).returncode == 0
    r = subprocess.run([sys.executable, "-m", "caplock", "verify"] + h.cli_args(ws), env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0 and "MATCH (exit 0)" in r.stdout


def test_missing_lockfile_is_unverifiable(tmp_path):
    ws = h.prepare_workspace(tmp_path / "ws")
    code, out = h.run(["verify"] + h.cli_args(ws))
    assert code == 2 and "lockfile_missing" in out


def test_tampered_lockfile_is_unverifiable(tmp_path):
    ws = h.prepare_workspace(tmp_path / "ws")
    h.run(["lock"] + h.cli_args(ws))
    p = ws / "mcp-lock.json"
    lock = json.loads(p.read_text())
    lock["servers"]["notes"]["tools"]["read_note"]["definition"]["description"] = "edited by hand"
    p.write_text(json.dumps(lock))
    code, out = h.run(["verify"] + h.cli_args(ws))
    assert code == 2 and "lockfile_invalid" in out


def test_no_surface_source_is_unverifiable(tmp_path):
    ws = h.prepare_workspace(tmp_path / "ws")
    args = ["--workspace", str(ws), "--registry", str(h.REGISTRY)]
    code, out = h.run(["lock"] + args)
    assert code == 2 and "surface_not_enumerated" in out
    code, out = h.run(["verify"] + args)
    assert code == 2 and "surface_not_enumerated" in out


def test_offline_without_registry_is_unverifiable(tmp_path):
    ws = h.prepare_workspace(tmp_path / "ws")
    args = [a for a in h.cli_args(ws)]
    args = [a for i, a in enumerate(args) if a != "--registry" and (i == 0 or args[i - 1] != "--registry")]
    code, out = h.run(["lock"] + args)
    assert code == 2 and "integrity_unrecorded" in out and "offline" in out


def test_enumeration_timeout_is_unverifiable(tmp_path):
    ws = h.prepare_workspace(tmp_path / "ws")
    h.run(["lock"] + h.cli_args(ws))
    hang = " ".join(shlex.quote(p) for p in (sys.executable, str(h.SERVER), "--mode", "hang"))
    args = ["--workspace", str(ws), "--registry", str(h.REGISTRY), "--timeout", "0.5",
            "--launch", f"notes={hang}", "--launch", f"weather={h.server_cmd('weather.json')}"]
    code, out = h.run(["verify"] + args)
    assert code == 2 and "enumeration_failed" in out and "timed out" in out


def test_allow_launch_runs_configured_local_command(tmp_path):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"local": {
        "command": sys.executable, "args": [str(h.SERVER), "--tools", str(h.TOOLS / "weather.json")]}}}))
    code, out = h.run(["lock", "-w", str(tmp_path), "--allow-launch", "local"])
    assert "get_forecast" in out and "launch-config" in out
    assert code == 2 and "package_unresolvable" in out  # python is not npx/uvx/docker: honest manual


def test_allow_launch_refuses_redacted_args(tmp_path):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"x": {
        "command": sys.executable, "args": [str(h.SERVER), "--token", DUMMY]}}}))
    code, out = h.run(["lock", "-w", str(tmp_path), "--allow-launch", "x"])
    assert code == 2 and "redacted or unresolved" in out
    assert DUMMY not in out


def test_http_server_recorded_surface_and_host_change(tmp_path):
    cfg = {"servers": {"docs": {"type": "http", "url": "https://mcp.docs.example.com/mcp"}}}
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "mcp.json").write_text(json.dumps(cfg))
    args = ["-w", str(tmp_path), "--surface", f"docs={h.ROOT / 'fixtures/surfaces/docs_remote.json'}"]
    code, out = h.run(["lock"] + args)
    assert code == 2 and "remote_entity_unverifiable" in out and "search_docs" in out
    code, report = h.run_json(["verify"] + args)
    assert code == 2
    assert [f["code"] for f in report["findings"]] == ["remote_entity_unverifiable"]
    cfg["servers"]["docs"]["url"] = "https://mcp.docs.example.net/mcp"
    (tmp_path / ".vscode" / "mcp.json").write_text(json.dumps(cfg))
    code, report = h.run_json(["verify"] + args)
    assert ("remote_host_changed", "critical") in [(f["code"], f["severity"]) for f in report["findings"]]


def test_config_drift_is_shown(tmp_path):
    ws = h.prepare_workspace(tmp_path / "ws")
    (ws / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "notes": {"command": "npx", "args": ["-y", "@caplock-demo/notes-mcp@1.0.1"]},
        "weather": {"command": "uvx", "args": ["caplock-demo-weather==0.3.1"]}}}))
    code, out = h.run(["lock"] + h.cli_args(ws))
    assert code == 0 and "config_drift" in out
    lock = json.loads((ws / "mcp-lock.json").read_text())
    assert len(lock["servers"]["notes"]["configDrift"]) == 2
    assert lock["servers"]["notes"]["package"]["version"] == "1.0.0"  # first file wins


def test_secret_values_never_leave_the_config(tmp_path):
    cfg = {"servers": {
        "notes": {"type": "stdio", "command": "npx",
                  "args": ["-y", "@caplock-demo/notes-mcp@1.0.0", "--api-key", DUMMY],
                  "env": {"NOTES_TOKEN": DUMMY}},
        "docs": {"type": "http", "url": f"https://mcp.docs.example.com/mcp?token={DUMMY}",
                 "headers": {"Authorization": f"Bearer {DUMMY}"}},
    }}
    ws = h.prepare_workspace(tmp_path / "ws")
    (ws / ".vscode" / "mcp.json").write_text(json.dumps(cfg))
    args = h.cli_args(ws) + ["--surface", f"docs={h.ROOT / 'fixtures/surfaces/docs_remote.json'}"]
    outputs = [h.run(["lock"] + args)[1]]
    outputs.append(h.run(["verify"] + args)[1])
    outputs.append(h.run(["diff"] + args)[1])
    outputs.append(json.dumps(h.run_json(["verify"] + args)[1]))
    # mutate so diffs print before/after values too
    cfg["servers"]["notes"]["env"]["EXTRA"] = DUMMY
    (ws / ".vscode" / "mcp.json").write_text(json.dumps(cfg))
    outputs.append(h.run(["diff"] + args)[1])
    outputs.append(h.run(["lock", "--yes"] + args)[1])
    lock_text = (ws / "mcp-lock.json").read_text()
    for text in outputs + [lock_text]:
        assert DUMMY not in text
    assert '"NOTES_TOKEN"' in lock_text and '"Authorization"' in lock_text


def test_usage_error_exit_code(tmp_path):
    code, _ = h.run(["verify", "-w", str(tmp_path / "nope")])
    assert code == 3


def test_legacy_era_server_verifies_against_modern_lock(tmp_path):
    """The surface hash is era-independent: same tools via initialize or server/discover."""
    ws = h.prepare_workspace(tmp_path / "ws")
    assert h.run(["lock"] + h.cli_args(ws))[0] == 0
    lock = json.loads((ws / "mcp-lock.json").read_text())
    assert lock["servers"]["notes"]["surface"]["protocolVersion"] == "2026-07-28"
    legacy = h.server_cmd("benign.json") + " --era legacy"
    args = ["--workspace", str(ws), "--registry", str(h.REGISTRY),
            "--launch", f"notes={legacy}", "--launch", f"weather={h.server_cmd('weather.json')}"]
    code, out = h.run(["verify"] + args)
    assert code == 0, out
