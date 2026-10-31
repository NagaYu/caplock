#!/usr/bin/env python3
"""CapLock Phase 1 demo: lock → mutate → detect, entirely offline.

  python scripts/demo.py            # full walkthrough
  python scripts/demo.py --brief    # summary table only

Works on a temporary copy of examples/demo-workspace. The only process that
is launched is the local fixture server (fixtures/servers/notes_server.py);
registry data comes from fixtures/registry.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import harness as h  # noqa: E402
from caplock.diff import RANK  # noqa: E402


def banner(text: str) -> None:
    print("\n" + "=" * 78)
    print(text)
    print("=" * 78)


def show(cmd: list[str], brief: bool) -> int:
    code, out = h.run(cmd)
    if not brief:
        print(f"$ caplock {cmd[0]} …\n")
        # drop the long temp-path header line for readability
        print("\n".join(out.splitlines()[1:]))
    return code


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--brief", action="store_true")
    brief = ap.parse_args().brief

    tmp = Path(tempfile.mkdtemp(prefix="caplock-demo-"))
    try:
        base = h.prepare_workspace(tmp / "base")
        if not brief:
            banner("1. caplock lock — bind config → package (version+integrity) → surface → capabilities")
        code = show(["lock"] + h.cli_args(base), brief)
        assert code == 0, "lock of the benign workspace should succeed"
        if not brief:
            banner("2. caplock verify — nothing changed")
        show(["verify"] + h.cli_args(base), brief)

        results = []
        for sc in h.load_scenarios():
            ws = tmp / f"scenario-{sc['id']}"
            shutil.copytree(base, ws)
            args = h.apply_scenario(ws, sc)
            if not brief:
                banner(f"Scenario {sc['id']}: {sc['title']}")
                applied = ", ".join(f"{k}={v}" for k, v in sc["after"].items())
                print(f"(mutation applied to a copy of the locked workspace: {applied})")
            code = show(["diff"] + args, brief)
            _, report = h.run_json(["verify"] + args)
            exp = sc["expect"]
            codes = sorted({f["code"] for f in report["findings"]})
            sevs = [f["severity"] for f in report["findings"]]
            top = min(sevs, key=RANK.get) if sevs else None
            ok = code == exp["exit"] and codes == sorted(exp["codes"]) and top == exp["maxSeverity"]
            results.append((sc["id"], top or "-", code, ", ".join(codes) or "(none)", ok))

        banner("Summary")
        print(f"{'id':<4} {'top severity':<13} {'exit':<5} {'as expected':<12} findings")
        for sid, sev, code, codes, ok in results:
            print(f"{sid:<4} {sev:<13} {code:<5} {'yes' if ok else 'NO':<12} {codes}")
        print("\nExit codes: 0 = no differences / info-medium only, 1 = high or critical, 2 = unverifiable.")
        print("CapLock pins the declared surface and package identity; it does not attest to server behavior.")
        return 0 if all(r[-1] for r in results) else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
