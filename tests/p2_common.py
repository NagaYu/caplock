"""Shared fixtures for Phase 2 report tests: scenario A–I workspaces, locked once."""

import shutil

import harness as h


def scenario_ws(base, tmp_path, sid):
    ws = tmp_path / f"ws-{sid}"
    shutil.copytree(base, ws)
    sc = next(s for s in h.load_scenarios() if s["id"] == sid)
    return ws, h.apply_scenario(ws, sc)
