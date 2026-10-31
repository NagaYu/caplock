"""Scenarios A–I: lock the benign demo workspace, mutate, verify.

Expectations live in fixtures/scenarios/*.json so the demo and the tests
share one source of truth.
"""

import pytest

import harness as h
from caplock.diff import RANK

SCENARIOS = h.load_scenarios()


def test_all_required_scenarios_present():
    assert {s["id"] for s in SCENARIOS} == {"A", "B", "C", "D", "E", "F", "G1", "G2", "H", "I"}


@pytest.fixture
def locked_ws(tmp_path):
    ws = h.prepare_workspace(tmp_path / "ws")
    code, out = h.run(["lock"] + h.cli_args(ws))
    assert code == 0, out
    code, out = h.run(["verify"] + h.cli_args(ws))
    assert code == 0, out
    return ws


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
def test_scenario(locked_ws, scenario):
    args = h.apply_scenario(locked_ws, scenario)
    exp = scenario["expect"]
    for cmd in ("verify", "diff"):
        code, report = h.run_json([cmd] + args)
        codes = sorted({f["code"] for f in report["findings"]})
        assert codes == sorted(exp["codes"]), (cmd, report["findings"])
        assert code == exp["exit"] == report["exitCode"]
        sevs = [f["severity"] for f in report["findings"]]
        top = min(sevs, key=RANK.get) if sevs else None
        assert top == exp["maxSeverity"]
    # verify never reports a non-zero result as a match, and never 0 when unverifiable
    code, text = h.run(["verify"] + args)
    if code == 2:
        assert "UNVERIFIABLE (exit 2)" in text and "not a pass" in text
    if code == 0:
        assert "UNVERIFIABLE" not in text


def test_scenario_H_is_zero_diff_even_in_lock(locked_ws):
    """Re-locking after a formatting-only change leaves the lockfile untouched."""
    before = (locked_ws / "mcp-lock.json").read_bytes()
    scenario = next(s for s in SCENARIOS if s["id"] == "H")
    args = h.apply_scenario(locked_ws, scenario)
    code, out = h.run(["lock"] + args)
    assert code == 0 and "up to date" in out
    assert (locked_ws / "mcp-lock.json").read_bytes() == before


def test_scenario_F_tool_definitions_really_unchanged(locked_ws):
    import json

    lock = json.loads((locked_ws / "mcp-lock.json").read_text())
    scenario = next(s for s in SCENARIOS if s["id"] == "F")
    args = h.apply_scenario(locked_ws, scenario)
    code, report = h.run_json(["diff"] + args)
    assert code == 1
    assert all(f.get("tool") is None for f in report["findings"])
    assert lock["servers"]["notes"]["surface"]["hash"]  # surface recorded and unchanged
