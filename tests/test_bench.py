"""CapLock Bench v0: corpus schema, label/output agreement on a dev subset, scoring logic, results.json shape.

The full scoring run and the drift fetch are not part of the tests (time / network).
"""

import json
import re
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bench"))
sys.path.insert(0, str(ROOT / "bench" / "drift"))

import make_corpus  # noqa: E402
import run_bench as rb  # noqa: E402
from caplock.diff import RANK  # noqa: E402
from caplock.sarif import RULES  # noqa: E402

HOLDOUT_PRESENT = (ROOT / "bench" / "cases" / "holdout").is_dir()
RAW_PRESENT = (ROOT / "bench" / "drift" / "raw").is_dir()
PUBLISH_PRESENT = (ROOT / "publish").is_dir()
needs_holdout = pytest.mark.skipif(not HOLDOUT_PRESENT, reason="holdout cases are withheld from this tree")
needs_raw = pytest.mark.skipif(not RAW_PRESENT, reason="bench/drift/raw is not distributed")
needs_publish = pytest.mark.skipif(not PUBLISH_PRESENT, reason="publish/ drafts are not part of this tree")
CASES = rb.load_cases()
RESULTS = json.loads((ROOT / "bench" / "results.json").read_text(encoding="utf-8"))
RECORDED = {c["id"]: c for c in RESULTS["cases"]}
CASE_KEYS = {"id", "corpusVersion", "split", "family", "axis", "seed", "base", "description", "mutation", "labels"}
MUTATION_KEYS = {"notes_tools", "weather_tools", "vscode_config", "portable_config", "registry_overlay",
                 "notes_server_args"}


# --------------------------------------------------------------------------- corpus schema


@needs_holdout
def test_corpus_size_and_split():
    assert 60 <= len(CASES) <= 100
    counts = {s: sum(c["split"] == s for c in CASES) for s in rb.SPLITS}
    assert counts["dev"] > 0 and counts["holdout"] > 0
    assert json.loads((ROOT / "bench" / "cases" / "INDEX.json").read_text())["counts"] == counts


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_case_schema(case):
    assert set(case) == CASE_KEYS
    assert re.fullmatch(rf"{case['split']}-{re.escape(case['family'])}-\d\d", case["id"])
    assert (ROOT / "bench" / "cases" / case["split"] / f"{case['id']}.json").is_file()
    assert case["base"] in ("demo", "docker")
    assert case["mutation"] and set(case["mutation"]) <= MUTATION_KEYS
    lab = case["labels"]
    assert set(lab) == {"codes", "maxSeverity", "exit", "benign"}
    assert lab["codes"] == sorted(set(lab["codes"])) and all(c in RULES for c in lab["codes"])
    assert lab["maxSeverity"] in (*RANK, None)
    assert lab["exit"] == make_corpus.EXIT_OF[lab["maxSeverity"]]
    if lab["benign"]:
        assert lab["maxSeverity"] in (None, "info") and lab["exit"] == 0
    else:
        assert lab["codes"] and lab["maxSeverity"] is not None
        # the labeled class is the most severe default severity among the labeled codes
        assert min(RANK[RULES[c][1]] for c in lab["codes"]) == RANK[lab["maxSeverity"]]


@needs_holdout
def test_families_never_straddle_splits():
    split_of = {}
    for c in CASES:
        assert split_of.setdefault(c["family"], c["split"]) == c["split"], c["family"]
    axes = {s: {c["axis"] for c in CASES if c["split"] == s} for s in rb.SPLITS}
    # every attack axis and the benign controls are represented in both splits
    assert axes["dev"] == axes["holdout"]


def test_committed_corpus_is_what_the_generator_produces():
    assert sorted(make_corpus.build(), key=lambda c: c["id"]) == sorted(CASES, key=lambda c: c["id"])


def test_corpus_is_synthetic_only():
    blob = json.dumps(CASES)
    for pkg in re.findall(r"(@[\w.-]+/[\w.-]+|ghcr\.io/[\w./-]+)", blob):
        assert pkg.startswith(("@caplock-demo/", "ghcr.io/caplock-demo/")), pkg
    for c in CASES:
        if "portable_config" in c["mutation"]:
            for spec in json.loads(c["mutation"]["portable_config"])["mcpServers"]["weather"]["args"]:
                assert spec.startswith("caplock-demo-weather"), spec


# --------------------------------------------------------------------------- labels vs CapLock output (dev subset)


DEV_SUBSET = sorted({c["family"]: c for c in reversed(CASES) if c["split"] == "dev"}.values(), key=lambda c: c["id"])


@pytest.fixture(scope="module")
def bases():
    with tempfile.TemporaryDirectory(prefix="bench-test-") as t:
        yield rb.prepare_bases(Path(t)), Path(t)


@pytest.mark.parametrize("case", DEV_SUBSET, ids=[c["id"] for c in DEV_SUBSET])
def test_dev_subset_reproduces_recorded_result(case, bases):
    base_dirs, tmp = bases
    obs = rb.run_case(case, base_dirs, tmp)
    rec = RECORDED[case["id"]]
    assert {k: obs[k] for k in ("exit", "codes", "maxSeverity")} == \
        {k: rec["observed"][k] for k in ("exit", "codes", "maxSeverity")}
    assert rb.score_case(case["labels"], obs) == rec["score"]
    assert obs["codes"] == case["labels"]["codes"] and obs["exit"] == case["labels"]["exit"]


# --------------------------------------------------------------------------- scoring logic


def lab(codes, sev, benign=False):
    return {"codes": codes, "maxSeverity": sev, "exit": make_corpus.EXIT_OF[sev], "benign": benign}


def obs(codes, sev, code):
    return {"exit": code, "codes": codes, "maxSeverity": sev, "findings": []}


def test_detection_counts_more_severe_as_detected_and_less_severe_as_missed():
    assert rb.score_case(lab(["tool_added"], "high"), obs(["capability_expanded"], "critical", 1))["detected"]
    s = rb.score_case(lab(["description_changed", "instruction_injection"], "high"),
                      obs(["description_changed"], "medium", 0))
    assert not s["detected"] and not s["exitMatch"] and s["missingCodes"] == ["instruction_injection"]
    assert s["codeHits"] == 1 and s["codeTotal"] == 2
    assert not rb.score_case(lab(["floating_version"], "unverifiable"), obs([], None, 0))["detected"]


def test_benign_false_positive_rules():
    assert not rb.score_case(lab([], None, True), obs([], None, 0))["falsePositive"]
    assert not rb.score_case(lab(["version_changed"], "info", True), obs(["version_changed"], "info", 0))["falsePositive"]
    assert rb.score_case(lab([], None, True), obs(["description_changed"], "medium", 0))["falsePositive"]
    assert rb.score_case(lab([], None, True), obs([], None, 2))["falsePositive"]


def test_aggregate_counts():
    rows = []
    for cid, l, o in (("a", lab(["tool_added"], "high"), obs(["tool_added"], "high", 1)),
                      ("b", lab(["instruction_injection"], "high"), obs([], None, 0)),
                      ("c", lab([], None, True), obs(["schema_changed"], "medium", 0)),
                      ("d", lab(["floating_version"], "unverifiable"), obs(["floating_version"], "unverifiable", 2))):
        case = {"id": cid, "split": "dev", "family": "f", "axis": "floating" if cid == "d" else "x", "labels": l}
        rows.append({"case": case, "observed": o, "score": rb.score_case(l, o)})
    a = rb.aggregate(rows)
    assert a["detectionByClass"]["high"] == {"cases": 2, "detected": 1, "rate": 0.5}
    assert a["detection"] == {"cases": 3, "detected": 2, "rate": 0.6667}
    assert a["falsePositive"] == {"cases": 1, "falsePositives": 1, "rate": 1.0}
    assert a["exitMatch"]["matched"] == 3 and a["floatingExit2"] == {"cases": 1, "exit2": 1, "rate": 1.0}
    assert a["misses"] == ["b", "c"]
    assert a["detectionByClass"]["info"]["rate"] is None  # no case: reported as n/a, never as 100%


# --------------------------------------------------------------------------- results.json / RESULTS.md


def test_results_cover_every_case_and_match_the_corpus():
    if HOLDOUT_PRESENT:
        assert sorted(RECORDED) == sorted(c["id"] for c in CASES)  # nothing dropped
        assert RESULTS["corpusDigest"] == rb.corpus_digest(CASES)
    else:  # withheld holdout: every present case is recorded; the digest is checkable on disclosure
        assert {c["id"] for c in CASES} == {i for i, r in RECORDED.items() if r["split"] == "dev"}
        assert RESULTS["splits"]["holdout"]["cases"] == sum(r["split"] == "holdout" for r in RECORDED.values())
    for c in CASES:
        assert RECORDED[c["id"]]["labels"] == c["labels"]


def test_results_structure_and_aggregates_recompute():
    for key in ("bench", "benchVersion", "corpusVersion", "caplockVersion", "ruleCatalogVersion", "failOn",
                "generatedAt", "notice", "splits", "all", "otherTools", "cases"):
        assert key in RESULTS
    by_id = {c["id"]: c for c in CASES}
    for split in rb.SPLITS:
        if split == "holdout" and not HOLDOUT_PRESENT:  # rebuild case stubs from the recorded rows
            src = {r["id"]: {k: r[k] for k in ("id", "split", "family", "axis", "labels")} for r in RESULTS["cases"]}
        else:
            src = by_id
        rows = [{"case": src[r["id"]], "observed": r["observed"], "score": r["score"]}
                for r in RESULTS["cases"] if r["split"] == split]
        assert rb.aggregate(rows) == RESULTS["splits"][split]
        agg = RESULTS["splits"][split]
        for metric in ("detection", "falsePositive", "exitMatch", "codesExact", "unverifiableExit2", "floatingExit2"):
            assert metric in agg
        assert set(agg["detectionByClass"]) == set(rb.CLASSES)


def test_other_tools_are_unmeasured_with_reasons_and_no_numbers():
    assert RESULTS["otherTools"]
    for t in RESULTS["otherTools"]:
        assert t["status"] == "unmeasured" and t["reasons"] and t["sources"]
        assert not ({"detection", "rate", "score", "results"} & set(t))


def test_results_md_is_rendered_from_results_json():
    md = (ROOT / "bench" / "RESULTS.md").read_text(encoding="utf-8")
    assert md == rb.render_md(RESULTS)
    for text in ("| metric | dev | holdout |", "## Limits", "Synthetic", "Over-fitting",
                 "unmeasured", "does not attest to the runtime behavior"):
        assert text in md


# --------------------------------------------------------------------------- drift survey (saved data only; no fetch)


DRIFT = ROOT / "bench" / "drift"


@needs_raw
def test_drift_raw_files_match_their_manifest():
    import hashlib

    man = json.loads((DRIFT / "raw" / "MANIFEST.json").read_text())
    assert man["entries"]
    on_disk = {str(p.relative_to(DRIFT / "raw")) for p in (DRIFT / "raw").rglob("*") if p.is_file()} - {"MANIFEST.json"}
    assert on_disk == {e["path"] for e in man["entries"]}
    for e in man["entries"]:
        data = (DRIFT / "raw" / e["path"]).read_bytes()
        assert "sha256:" + hashlib.sha256(data).hexdigest() == e["sha256"], e["path"]
        assert e["fetchedAt"] and e["url"] and e["status"] == 200


def test_drift_summary_scope_decision_follows_kill_rule():
    s = json.loads((DRIFT / "summary.json").read_text())
    surf = s["surfaces"]
    assert surf["top30"]["items"] == 30 and surf["killThreshold"] == 0.10
    assert surf["coverage"] == round(surf["top30"]["withToolList"] / 30, 4)
    assert ("OUT OF SCOPE" in surf["decision"]) == (surf["coverage"] < 0.10)
    assert s["npmTop30"]["packages"] == 30 and len(s["npmTop30"]["perPackage"]) == 30
    assert s["fetchWindow"]["first"] <= s["fetchWindow"]["last"]
    assert s["notMeasured"]


@needs_raw
def test_drift_selection_is_reproducible_from_raw():
    import fetch  # bench/drift/fetch.py; only reads saved files here

    sel = json.loads((DRIFT / "selection.json").read_text())
    top, pypi = fetch.select()
    assert [c["package"] for c in top] == [c["package"] for c in sel["npm"]]
    assert [c["package"] for c in pypi] == [c["package"] for c in sel["pypi"]]


# --------------------------------------------------------------------------- publish/ packet (local drafts)


PUBLISH = ROOT / "publish"


def publish_files():
    return [p for p in PUBLISH.rglob("*") if p.is_file() and p.name != "build_publish.py" and "__pycache__" not in p.parts]


@needs_publish
def test_publish_packet_is_complete_and_marked_draft():
    rel = {str(p.relative_to(PUBLISH)) for p in publish_files()}
    assert rel == {"README.md", "hf-dataset/README.md", "hf-dataset/data/dev.jsonl", "hf-space/README.md",
                   "hf-space/index.html", "github/README-head.md", "issues/vscode-pinning.md",
                   "issues/registry-integrity-surface.md"}
    for p in publish_files():
        if p.suffix != ".jsonl":
            assert "DRAFT — NOT PUBLISHED" in p.read_text(encoding="utf-8"), p


@needs_publish
def test_dataset_is_the_dev_split_only():
    sys.path.insert(0, str(PUBLISH))
    import build_publish

    lines = (PUBLISH / "hf-dataset" / "data" / "dev.jsonl").read_text(encoding="utf-8").splitlines()
    rows = [json.loads(x) for x in lines]
    assert rows == build_publish.dataset_rows("dev")
    assert {r["id"] for r in rows} == {c["id"] for c in CASES if c["split"] == "dev"}
    card = (PUBLISH / "hf-dataset" / "README.md").read_text(encoding="utf-8")
    assert "All Rights Reserved" in card and "license: other" in card


@needs_publish
def test_space_is_static_and_offline():
    html = (PUBLISH / "hf-space" / "index.html").read_text(encoding="utf-8")
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    assert not re.search(r"""(?:src|href)\s*=\s*["']?(?:https?:)?//""", html)
    assert "fetch(" not in html and "XMLHttpRequest" not in html and "WebSocket" not in html
    data = json.loads(html.split('<script id="data" type="application/json">', 1)[1].split("</script>", 1)[0])
    assert [d["id"] for d in data] == [s["id"] for s in __import__("harness").load_scenarios()]
    assert all({"surface", "text", "sarif", "markdown", "exit"} <= set(d) for d in data)
    assert "sdk: static" in (PUBLISH / "hf-space" / "README.md").read_text(encoding="utf-8")


@needs_publish
def test_publish_packet_leaks_no_local_paths_or_overclaims():
    for p in publish_files():
        text = p.read_text(encoding="utf-8")
        assert str(Path.home()) not in text and "/private/var/" not in text and "/tmp/" not in text, p
        low = text.lower()
        assert "guarantee" not in low and "certified" not in low, p


@needs_publish
def test_issue_drafts_are_outlines_with_cited_sources():
    for name in ("vscode-pinning.md", "registry-integrity-surface.md"):
        text = (PUBLISH / "issues" / name).read_text(encoding="utf-8")
        assert "Outline only" in text and "Not posted" in text and "Evidence to cite" in text
        assert "bench/" in text
