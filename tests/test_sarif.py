"""SARIF 2.1.0 output: required structure, level mapping, fingerprints (all offline)."""

import json
import re
from pathlib import Path

import pytest

import harness as h
from caplock.diff import Finding
from caplock.report import build_context
from caplock.sarif import FINGERPRINT_KEY, LEVEL, RULES, SARIF_SCHEMA, fingerprint, to_sarif
from p2_common import scenario_ws

SCENARIO_IDS = [s["id"] for s in h.load_scenarios()]


def sarif_for(base, tmp_path, sid, *extra):
    ws, args = scenario_ws(base, tmp_path, sid)
    code, text = h.run(["verify", "--format", "sarif", *extra] + args)
    return code, json.loads(text), text


def check_structure(doc):
    assert doc["version"] == "2.1.0"
    assert doc["$schema"] == SARIF_SCHEMA
    assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "CapLock" and driver["version"]
    rules = driver["rules"]
    assert [r["id"] for r in rules] == sorted(RULES)
    for r in rules:
        assert r["name"] and r["shortDescription"]["text"] and r["fullDescription"]["text"]
        assert r["defaultConfiguration"]["level"] in ("error", "warning", "note")
    assert isinstance(run["results"], list)
    for res in run["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["level"] in ("error", "warning", "note")
        assert res["message"]["text"]
        [loc] = res["locations"]
        assert loc["physicalLocation"]["artifactLocation"]["uri"]
        assert "region" not in loc["physicalLocation"]
        assert re.fullmatch(r"[0-9a-f]{64}", res["partialFingerprints"][FINGERPRINT_KEY])
        assert isinstance(res["properties"]["unverifiable"], bool)


def test_every_emitted_code_has_a_rule():
    src = "".join(p.read_text() for p in (h.ROOT / "src" / "caplock").glob("*.py"))
    emitted = set(re.findall(r'(?:Finding|\bF)\(\s*"([a-z_]+)"', src)) | {"invisible_chars", "instruction_injection"}
    assert emitted and emitted <= set(RULES), emitted - set(RULES)


@pytest.mark.parametrize("sid", SCENARIO_IDS)
def test_structure_and_consistency_for_every_scenario(locked_base, tmp_path, sid):
    code, doc, _ = sarif_for(locked_base, tmp_path, sid)
    check_structure(doc)
    exp = next(s for s in h.load_scenarios() if s["id"] == sid)["expect"]
    run = doc["runs"][0]
    assert code == exp["exit"] == run["properties"]["exitCode"] == run["invocations"][0]["exitCode"]
    assert sorted({r["ruleId"] for r in run["results"]}) == sorted(exp["codes"])


@pytest.mark.parametrize("sid", SCENARIO_IDS)
def test_output_is_deterministic(locked_base, tmp_path, sid):
    _, _, a = sarif_for(locked_base, tmp_path / "a", sid)
    _, _, b = sarif_for(locked_base, tmp_path / "b", sid)
    strip = lambda t: re.sub(r'"uri": "[^"]*"', '"uri": "-"', t)  # workspaces differ only in path
    assert strip(a) == strip(b)


def test_scenario_F_integrity_mismatch_is_error(locked_base, tmp_path):
    code, doc, _ = sarif_for(locked_base, tmp_path, "F")
    [res] = doc["runs"][0]["results"]
    assert code == 1
    assert (res["ruleId"], res["level"]) == ("integrity_mismatch", "error")
    assert res["properties"]["unverifiable"] is False
    assert res["properties"]["severity"] == "critical"
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith(".vscode/mcp.json")
    assert "notes" in res["message"]["text"] and "package.integrity" in res["message"]["text"]


@pytest.mark.parametrize("sid", ["G1", "G2"])
def test_scenario_G_unverifiable_is_error_with_tag(locked_base, tmp_path, sid):
    code, doc, _ = sarif_for(locked_base, tmp_path, sid)
    [res] = doc["runs"][0]["results"]
    assert code == 2
    assert (res["ruleId"], res["level"]) == ("floating_version", "error")
    assert res["properties"]["unverifiable"] is True
    assert "unverifiable" in res["properties"]["tags"]
    assert doc["runs"][0]["properties"]["verdict"] == "UNVERIFIABLE"


def test_scenario_I_version_change_is_note_and_needs_review(locked_base, tmp_path):
    code, doc, _ = sarif_for(locked_base, tmp_path, "I")
    [res] = doc["runs"][0]["results"]
    assert code == 0 and (res["ruleId"], res["level"]) == ("version_changed", "note")
    assert res["properties"]["needsReview"] is True and "needs-review" in res["properties"]["tags"]


@pytest.mark.parametrize("sev, level", [("critical", "error"), ("high", "error"), ("medium", "warning"),
                                         ("info", "note"), ("unverifiable", "error")])
def test_level_mapping(sev, level):
    ctx = build_context([Finding("tool_added", sev, "m", server="s", tool="t")], 0, "high",
                        workspace=Path("."), lockfile_path=Path("mcp-lock.json"), state_servers=None,
                        lock_servers=None)
    [res] = to_sarif(ctx)["runs"][0]["results"]
    assert res["level"] == level == LEVEL[sev]
    assert res["properties"]["unverifiable"] is (sev == "unverifiable")


def test_fingerprint_is_stable_and_keyed_on_server_tool_code_field():
    a = Finding("tool_added", "high", "message one", server="s", tool="t", field="f")
    b = Finding("tool_added", "high", "different message", server="s", tool="t", field="f", after=[1])
    assert fingerprint(a) == fingerprint(b)
    for other in (Finding("tool_added", "high", "m", server="s2", tool="t", field="f"),
                  Finding("tool_added", "high", "m", server="s", tool="t2", field="f"),
                  Finding("tool_removed", "high", "m", server="s", tool="t", field="f"),
                  Finding("tool_added", "high", "m", server="s", tool="t", field="g")):
        assert fingerprint(other) != fingerprint(a)
    # pinned value: changing the canonicalization would silently reopen every alert
    assert fingerprint(Finding("integrity_mismatch", "critical", "m", server="notes", field="package.integrity")) \
        == "4beebaf7d637733d521b408adf7e145b1e7677564366febe32da61a9d3f1cab6"


def test_fingerprints_match_across_workspaces(locked_base, tmp_path):
    fp = lambda d: [r["partialFingerprints"][FINGERPRINT_KEY] for r in d["runs"][0]["results"]]
    _, a, _ = sarif_for(locked_base, tmp_path / "x", "B")
    _, b, _ = sarif_for(locked_base, tmp_path / "y", "B")
    assert fp(a) == fp(b) and len(fp(a)) == 2


def test_locations_are_repo_relative_when_inside_cwd(locked_base, tmp_path, monkeypatch):
    ws, args = scenario_ws(locked_base, tmp_path, "C")
    monkeypatch.chdir(tmp_path)
    args = [a if a != str(ws) else ws.name for a in args]
    code, text = h.run(["verify", "--format", "sarif"] + args)
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in json.loads(text)["runs"][0]["results"]}
    assert uris == {f"{ws.name}/.vscode/mcp.json"}


def test_lockfile_is_the_location_when_no_config_source(tmp_path, monkeypatch):
    ws = h.prepare_workspace(tmp_path / "ws")
    monkeypatch.chdir(tmp_path)
    code, text = h.run(["verify", "--format", "sarif", "--workspace", "ws"])
    [res] = json.loads(text)["runs"][0]["results"]
    assert code == 2 and res["ruleId"] == "lockfile_missing"
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "ws/mcp-lock.json"


def test_output_and_report_files(locked_base, tmp_path):
    ws, args = scenario_ws(locked_base, tmp_path, "F")
    out = tmp_path / "out.sarif"
    md = tmp_path / "out.md"
    code, stdout = h.run(["verify", "--format", "sarif", "--output", str(out), "--report", f"markdown={md}"] + args)
    assert code == 1 and stdout == ""
    check_structure(json.loads(out.read_text()))
    assert md.read_text().startswith("## CapLock verify")
