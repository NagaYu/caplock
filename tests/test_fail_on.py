"""--fail-on only moves the threshold for exit 1; unverifiable is always 2."""

import pytest

import harness as h
from caplock.diff import Finding, exit_code
from p2_common import scenario_ws

THRESHOLDS = ("info", "medium", "high", "critical", "never")
# scenario -> expected exit for each threshold above
MATRIX = {
    "A": (1, 1, 1, 0, 0), "B": (1, 1, 1, 1, 0), "C": (1, 1, 1, 1, 0), "D": (1, 1, 1, 0, 0),
    "E": (1, 1, 0, 0, 0), "F": (1, 1, 1, 1, 0), "G1": (2, 2, 2, 2, 2), "G2": (2, 2, 2, 2, 2),
    "H": (0, 0, 0, 0, 0), "I": (1, 0, 0, 0, 0),
}


@pytest.mark.parametrize("sid", sorted(MATRIX))
def test_threshold_matrix(locked_base, tmp_path, sid):
    ws, args = scenario_ws(locked_base, tmp_path, sid)
    got = tuple(h.run_json(["verify", "--fail-on", t] + args)[0] for t in THRESHOLDS)
    assert got == MATRIX[sid]
    default = h.run_json(["verify"] + args)[0]
    assert default == MATRIX[sid][THRESHOLDS.index("high")]  # default == Phase 1 behavior


def test_never_still_returns_2_when_unverifiable(tmp_path):
    ws = h.prepare_workspace(tmp_path / "ws")
    code, text = h.run(["verify", "--fail-on", "never"] + h.cli_args(ws))  # no lockfile
    assert code == 2 and "UNVERIFIABLE (exit 2)" in text and "not a pass" in text


def test_exit_code_function_precedence():
    unv = Finding("floating_version", "unverifiable", "m")
    crit = Finding("integrity_mismatch", "critical", "m")
    for t in THRESHOLDS:
        assert exit_code([unv, crit], t) == 2
        assert exit_code([unv], t) == 2
    assert exit_code([crit], "never") == 0
    with pytest.raises(ValueError):
        exit_code([], "low")


def test_text_result_names_the_threshold(locked_base, tmp_path):
    ws, args = scenario_ws(locked_base, tmp_path, "E")
    code, text = h.run(["verify", "--fail-on", "medium"] + args)
    assert code == 1 and "CHANGED (exit 1): 1 'medium'-or-above finding(s) need review." in text


@pytest.mark.parametrize("argv", [["verify", "--fail-on", "low"], ["lock", "--fail-on", "high"]])  # verify only
def test_invalid_threshold_is_usage_error(tmp_path, argv):
    with pytest.raises(SystemExit) as e:
        h.run(argv + ["-w", str(tmp_path)])
    assert e.value.code == 3
