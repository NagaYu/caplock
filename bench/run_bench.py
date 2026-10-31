#!/usr/bin/env python3
"""Score CapLock on the Bench v0 corpus and write bench/results.json + bench/RESULTS.md.

For every case: copy the locked base workspace, apply the mutation, run
``caplock verify --json`` (in process, default ``--fail-on high``) and compare
with the case labels. Only the synthetic fixture server is launched and only
recorded registry metadata is read, so this needs no network.

    python bench/run_bench.py [--split dev|holdout] [--no-write]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shlex
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

BENCH = Path(__file__).resolve().parent
ROOT = BENCH.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

import harness as h  # noqa: E402
from caplock import LIMITATION_NOTICE, __version__  # noqa: E402
from caplock.diff import RANK  # noqa: E402
from caplock.sarif import RULE_CATALOG_VERSION  # noqa: E402

BENCH_VERSION = "0.1.0"
CASES = BENCH / "cases"
SPLITS = ("dev", "holdout")
CLASSES = ("unverifiable", "critical", "high", "medium", "info")
DOCKER_CONFIG = {"servers": {"notes": {"type": "stdio", "command": "docker",
                                       "args": ["run", "-i", "--rm", "ghcr.io/caplock-demo/notes-mcp:1.0.0"],
                                       "env": {"NOTES_TOKEN": "${env:NOTES_TOKEN}"}}}}

# Other tools: only measured if they run fully locally AND never send tool descriptions to an
# external API. Filled from public documentation; never from guesses. See RESULTS.md.
OTHER_TOOLS_FILE = BENCH / "other_tools.json"


# --------------------------------------------------------------------------- corpus


def load_cases(split: str | None = None) -> list[dict]:
    splits = [split] if split else list(SPLITS)
    out = []
    for s in splits:
        out += [json.loads(p.read_text(encoding="utf-8")) for p in sorted((CASES / s).glob("*.json"))]
    return out


def corpus_digest(cases: list[dict]) -> str:
    blob = json.dumps(sorted(cases, key=lambda c: c["id"]), sort_keys=True, ensure_ascii=True).encode()
    return "sha256:" + hashlib.sha256(blob).hexdigest()


# --------------------------------------------------------------------------- running


def prepare_bases(tmp: Path) -> dict[str, Path]:
    bases = {}
    for name in ("demo", "docker"):
        ws = h.prepare_workspace(tmp / f"base-{name}")
        if name == "docker":
            (ws / ".vscode" / "mcp.json").write_text(json.dumps(DOCKER_CONFIG, indent=2) + "\n")
        code, out = h.run(["lock", "--yes"] + h.cli_args(ws))
        if code != 0:
            raise RuntimeError(f"locking base {name} failed (exit {code}):\n{out}")
        bases[name] = ws
    return bases


def _server_cmd(tools_path: Path, extra: list[str]) -> str:
    parts = [sys.executable, str(h.SERVER), "--tools", str(tools_path), *extra]
    return " ".join(shlex.quote(p) for p in parts)


def case_args(case: dict, ws: Path, scratch: Path) -> list[str]:
    """Apply the mutation to the workspace copy and return the verify arguments."""
    m = case["mutation"]
    if "vscode_config" in m:
        (ws / ".vscode" / "mcp.json").write_text(m["vscode_config"], encoding="utf-8")
    if "portable_config" in m:
        (ws / ".mcp.json").write_text(m["portable_config"], encoding="utf-8")
    tools = {}
    for server, default in (("notes", h.TOOLS / "benign.json"), ("weather", h.TOOLS / "weather.json")):
        if f"{server}_tools" in m:
            p = scratch / f"{server}-tools.json"
            p.write_text(json.dumps(m[f"{server}_tools"], ensure_ascii=False), encoding="utf-8")
            tools[server] = p
        else:
            tools[server] = default
    args = ["--workspace", str(ws)]
    if m.get("registry_overlay"):
        overlay = scratch / "registry-overlay"
        for rel, doc in m["registry_overlay"].items():
            (overlay / rel).parent.mkdir(parents=True, exist_ok=True)
            (overlay / rel).write_text(json.dumps(doc), encoding="utf-8")
        args += ["--registry", str(overlay)]
    args += ["--registry", str(h.REGISTRY)]
    args += ["--launch", f"notes={_server_cmd(tools['notes'], m.get('notes_server_args', []))}"]
    args += ["--launch", f"weather={_server_cmd(tools['weather'], [])}"]
    return args


def run_case(case: dict, bases: dict[str, Path], tmp: Path) -> dict:
    work = tmp / case["id"]
    ws = work / "ws"
    shutil.copytree(bases[case["base"]], ws)
    args = case_args(case, ws, work)
    code, out = h.run(["verify"] + args + ["--json"])
    findings = json.loads(out)["findings"]
    shutil.rmtree(work, ignore_errors=True)
    return observed_from(code, findings)


def observed_from(code: int, findings: list[dict]) -> dict:
    sev = min((f["severity"] for f in findings), key=lambda s: RANK[s], default=None)
    return {
        "exit": code,
        "codes": sorted({f["code"] for f in findings}),
        "maxSeverity": sev,
        "findings": [{k: f[k] for k in ("code", "severity", "server", "tool", "field") if k in f} for f in findings],
    }


# --------------------------------------------------------------------------- scoring (pure)


def score_case(labels: dict, observed: dict) -> dict:
    exp_codes, obs_codes = set(labels["codes"]), set(observed["codes"])
    exp_sev, obs_sev = labels["maxSeverity"], observed["maxSeverity"]
    s = {
        "exitMatch": observed["exit"] == labels["exit"],
        "codesExact": obs_codes == exp_codes,
        "severityExact": obs_sev == exp_sev,
        "missingCodes": sorted(exp_codes - obs_codes),
        "extraCodes": sorted(obs_codes - exp_codes),
        "codeHits": len(exp_codes & obs_codes),
        "codeTotal": len(exp_codes),
    }
    if labels["benign"]:
        # a false positive is anything beyond the expected (info-level) findings, or a non-zero exit
        s["falsePositive"] = bool(obs_codes - exp_codes) or observed["exit"] != labels["exit"]
    else:
        # detected = alerted at the labeled class or more severe
        s["detected"] = obs_sev is not None and RANK[obs_sev] <= RANK[exp_sev]
    return s


def _rate(k: int, n: int) -> float | None:
    return round(k / n, 4) if n else None


def aggregate(rows: list[dict]) -> dict:
    """rows: [{"case": case, "observed": ..., "score": ...}]"""
    attack = [r for r in rows if not r["case"]["labels"]["benign"]]
    benign = [r for r in rows if r["case"]["labels"]["benign"]]
    by_class = {}
    for cls in CLASSES:
        rs = [r for r in attack if r["case"]["labels"]["maxSeverity"] == cls]
        k = sum(r["score"]["detected"] for r in rs)
        by_class[cls] = {"cases": len(rs), "detected": k, "rate": _rate(k, len(rs))}
    unv = [r for r in rows if r["case"]["labels"]["maxSeverity"] == "unverifiable"]
    floating = [r for r in unv if r["case"]["axis"] == "floating"]
    hits = sum(r["score"]["codeHits"] for r in rows)
    total = sum(r["score"]["codeTotal"] for r in rows)
    fam: dict[str, dict] = {}
    for r in rows:
        f = fam.setdefault(r["case"]["family"], {"cases": 0, "exitMatch": 0, "codesExact": 0, "axis": r["case"]["axis"]})
        f["cases"] += 1
        f["exitMatch"] += r["score"]["exitMatch"]
        f["codesExact"] += r["score"]["codesExact"]
    n = len(rows)
    return {
        "cases": n,
        "attackCases": len(attack),
        "benignCases": len(benign),
        "detectionByClass": by_class,
        "detection": {"cases": len(attack), "detected": sum(r["score"]["detected"] for r in attack),
                      "rate": _rate(sum(r["score"]["detected"] for r in attack), len(attack))},
        "falsePositive": {"cases": len(benign), "falsePositives": sum(r["score"]["falsePositive"] for r in benign),
                          "rate": _rate(sum(r["score"]["falsePositive"] for r in benign), len(benign))},
        "exitMatch": {"matched": sum(r["score"]["exitMatch"] for r in rows), "rate": _rate(
            sum(r["score"]["exitMatch"] for r in rows), n)},
        "codesExact": {"matched": sum(r["score"]["codesExact"] for r in rows), "rate": _rate(
            sum(r["score"]["codesExact"] for r in rows), n)},
        "severityExact": {"matched": sum(r["score"]["severityExact"] for r in rows), "rate": _rate(
            sum(r["score"]["severityExact"] for r in rows), n)},
        "codeRecall": {"hits": hits, "expected": total, "rate": _rate(hits, total)},
        "unverifiableExit2": {"cases": len(unv), "exit2": sum(r["observed"]["exit"] == 2 for r in unv),
                              "rate": _rate(sum(r["observed"]["exit"] == 2 for r in unv), len(unv))},
        "floatingExit2": {"cases": len(floating), "exit2": sum(r["observed"]["exit"] == 2 for r in floating),
                          "rate": _rate(sum(r["observed"]["exit"] == 2 for r in floating), len(floating))},
        "families": dict(sorted(fam.items())),
        "misses": [r["case"]["id"] for r in rows if not r["score"]["exitMatch"]
                   or not r["score"].get("detected", True) or r["score"].get("falsePositive")],
    }


def build_results(rows: list[dict], cases: list[dict], generated_at: str) -> dict:
    other = json.loads(OTHER_TOOLS_FILE.read_text(encoding="utf-8")) if OTHER_TOOLS_FILE.exists() else []
    return {
        "bench": "CapLock Bench v0",
        "benchVersion": BENCH_VERSION,
        "corpusVersion": cases[0]["corpusVersion"] if cases else None,
        "corpusDigest": corpus_digest(cases),
        "caplockVersion": __version__,
        "ruleCatalogVersion": RULE_CATALOG_VERSION,
        "failOn": "high",
        "generatedAt": generated_at,
        "environment": {"python": platform.python_version(), "platform": platform.system()},
        "notice": LIMITATION_NOTICE,
        "splits": {s: aggregate([r for r in rows if r["case"]["split"] == s]) for s in SPLITS},
        "all": aggregate(rows),
        "otherTools": other,
        "cases": [{"id": r["case"]["id"], "split": r["case"]["split"], "family": r["case"]["family"],
                   "axis": r["case"]["axis"], "labels": r["case"]["labels"], "observed": r["observed"],
                   "score": r["score"]} for r in rows],
    }


# --------------------------------------------------------------------------- RESULTS.md


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.1f}%"


def _frac(k: int, n: int, rate) -> str:
    return f"{k}/{n} ({_pct(rate)})" if n else "0/0 (n/a)"


def render_md(res: dict) -> str:
    d, ho = res["splits"]["dev"], res["splits"]["holdout"]
    L = [
        "# CapLock Bench v0 — results",
        "",
        f"CapLock {res['caplockVersion']} · rule catalog {res['ruleCatalogVersion']} · corpus {res['corpusVersion']} "
        f"(`{res['corpusDigest'][:23]}…`) · `--fail-on {res['failOn']}` · generated {res['generatedAt']}",
        "",
        "> Synthetic corpus, scored by its author's own tool. Read the methodology and limits below before "
        "quoting any number. " + res["notice"],
        "",
        "## Headline numbers (dev and holdout reported separately)",
        "",
        "| metric | dev | holdout |",
        "|---|---|---|",
    ]
    for cls in CLASSES:
        a, b = d["detectionByClass"][cls], ho["detectionByClass"][cls]
        L.append(f"| detection, {cls} class | {_frac(a['detected'], a['cases'], a['rate'])} | "
                 f"{_frac(b['detected'], b['cases'], b['rate'])} |")
    for key, label, k1, k2 in (("detection", "detection, all non-benign", "detected", "cases"),
                               ("falsePositive", "false positives on benign controls", "falsePositives", "cases"),
                               ("exitMatch", "exit code matches label", "matched", None),
                               ("codesExact", "finding-code set matches label exactly", "matched", None),
                               ("severityExact", "max severity matches label exactly", "matched", None),
                               ("codeRecall", "expected codes reported (micro recall)", "hits", "expected"),
                               ("unverifiableExit2", "unverifiable cases returned exit 2", "exit2", "cases"),
                               ("floatingExit2", "floating-spec cases returned exit 2", "exit2", "cases")):
        a, b = d[key], ho[key]
        na = a[k2] if k2 else d["cases"]
        nb = b[k2] if k2 else ho["cases"]
        L.append(f"| {label} | {_frac(a[k1], na, a['rate'])} | {_frac(b[k1], nb, b['rate'])} |")
    L += ["", f"Cases: dev {d['cases']} ({d['benignCases']} benign), holdout {ho['cases']} ({ho['benignCases']} benign).", ""]

    L += ["## Cases that did not match", ""]
    missed = [c for c in res["cases"] if not c["score"]["exitMatch"] or not c["score"]["codesExact"]
              or not c["score"].get("detected", True) or c["score"].get("falsePositive")]
    if not missed:
        L.append("_None: every case matched its labels exactly._")
    else:
        L += ["| case | label (sev / exit) | observed (sev / exit) | missing codes | extra codes | detected / FP |",
              "|---|---|---|---|---|---|"]
        for c in missed:
            lab, obs, sc = c["labels"], c["observed"], c["score"]
            flag = ("FP" if sc.get("falsePositive") else "ok") if lab["benign"] else (
                "detected" if sc["detected"] else "**missed**")
            L.append(f"| `{c['id']}` | {lab['maxSeverity']} / {lab['exit']} | {obs['maxSeverity']} / {obs['exit']} | "
                     f"{', '.join(sc['missingCodes']) or '-'} | {', '.join(sc['extraCodes']) or '-'} | {flag} |")
    L += ["", "No case was removed from the corpus; every generated case is scored above.", ""]

    L += ["## Per family", "", "| split | family | axis | cases | exit match | exact codes |", "|---|---|---|---|---|---|"]
    for split in SPLITS:
        for fam, f in res["splits"][split]["families"].items():
            L.append(f"| {split} | {fam} | {f['axis']} | {f['cases']} | {f['exitMatch']}/{f['cases']} | "
                     f"{f['codesExact']}/{f['cases']} |")
    L += ["", "## Other tools", ""]
    if not res["otherTools"]:
        L.append("_Not attempted._")
    for t in res["otherTools"]:
        L += [f"### {t['name']}", "", f"- Status: **{t['status']}**", f"- Checked: {t['checkedAt']} "
              f"(public documentation only; the tool was not installed or run)"]
        L += [f"- {r}" for r in t["reasons"]]
        L += [f"- Source: {s}" for s in t["sources"]]
        L.append("")
    L += METHODOLOGY
    return "\n".join(L) + "\n"


METHODOLOGY = [
    "## Methodology",
    "",
    "- **Corpus.** 90 cases generated by `bench/make_corpus.py` from the Phase 1 scenarios A–I and the Phase 2 "
    "PyPI variant of F. Each case locks the demo workspace against benign synthetic fixtures, applies one "
    "mutation operator (or two, for the compound family) and runs `caplock verify --json`.",
    "- **Labels.** Written in the generator from the operator's meaning and committed before the first "
    "scoring run. `maxSeverity` is the threat class a reviewer should be alerted at (so a paraphrased injection "
    "is labeled `high` even though CapLock's patterns do not cover it). `codes` uses CapLock's own taxonomy, so "
    "exact-code agreement measures spec conformance, not ground truth. Labels were not edited after scoring.",
    "- **Split.** Whole operator families go to dev or holdout. holdout holds pattern variants absent from dev "
    "and is used for scoring only. Phase 3 changed no detection logic, so neither split was used for tuning.",
    "- **Metrics.** *Detection*: for a non-benign case, CapLock reported at least one finding at the labeled "
    "class or more severe (for `unverifiable`, exit 2). *False positive*: on a benign control, any finding code "
    "beyond the expected ones (only `version_changed` for version-only bumps) or a non-zero exit. *Exit match*: "
    "exit code equals the label (`--fail-on high`). *Exact codes*: the set of finding codes equals the label.",
    "",
    "## Limits (read before quoting)",
    "",
    "- **Synthetic.** Two tiny fixture servers (4 tools), synthetic packages, hand-written mutations. Real "
    "servers have larger surfaces, real registries have edge cases this corpus does not model.",
    "- **Self-authored operators.** The operators and labels were written by the same project that wrote the "
    "detector, with the detector's rules in view. Over-fitting to its own operators is likely; dev numbers in "
    "particular say little about unseen attacks. holdout reduces, but does not remove, this bias.",
    "- **Small denominators.** Several classes have only a handful of cases (for example 13 benign controls in "
    "total), so one case moves a rate by several points.",
    "- **What is measured.** Whether CapLock reports a declared change to config, package identity or tool "
    "surface. Nothing here measures runtime behavior, and a matching lockfile does not mean a server is safe.",
    "- **Not measured.** Mid-session `list_changed` swaps, servers that answer differently per client, "
    "http servers, and real-world drift (see `bench/drift/`).",
]


# --------------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--split", choices=SPLITS)
    ap.add_argument("--no-write", action="store_true", help="print the summary only")
    args = ap.parse_args(argv)
    missing = [s for s in SPLITS if not (CASES / s).is_dir()]
    if args.split in missing:
        print(f"split {args.split!r} is not present in this tree (see bench/cases/HOLDOUT.md)")
        return 3
    if missing and not args.split:
        print(f"split(s) not present in this tree: {', '.join(missing)} (see bench/cases/HOLDOUT.md). "
              "Scoring the present split(s) only; results.json and RESULTS.md record the full-corpus run "
              "and are not rewritten.")
    cases = load_cases(args.split)
    rows = []
    with tempfile.TemporaryDirectory(prefix="caplock-bench-") as t:
        tmp = Path(t)
        bases = prepare_bases(tmp)
        for c in cases:
            obs = run_case(c, bases, tmp)
            rows.append({"case": c, "observed": obs, "score": score_case(c["labels"], obs)})
    res = build_results(rows, cases, datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    for split in ([args.split] if args.split else [s for s in SPLITS if s not in missing]):
        a = res["splits"][split]
        print(f"{split}: {a['cases']} cases, detection {_pct(a['detection']['rate'])}, "
              f"FP {_pct(a['falsePositive']['rate'])}, exit match {_pct(a['exitMatch']['rate'])}, "
              f"exact codes {_pct(a['codesExact']['rate'])}, misses {a['misses']}")
    if not args.no_write and not args.split and not missing:
        (BENCH / "results.json").write_text(json.dumps(res, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
                                            encoding="utf-8")
        (BENCH / "RESULTS.md").write_text(render_md(res), encoding="utf-8")
        print("wrote bench/results.json and bench/RESULTS.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
