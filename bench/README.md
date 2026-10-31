# CapLock Bench v0

A synthetic mutation corpus and a scoring harness that measure what CapLock's
`verify` reports for known kinds of change to an approved MCP setup.

```
bench/
  make_corpus.py     generates cases/ (deterministic; labels are written here)
  cases/
    INDEX.json       families, split assignment, counts
    dev/*.json       development split
    holdout/*.json   holdout split: scoring only
  run_bench.py       runs CapLock on every case, writes results.json and RESULTS.md
  results.json       scored results (per case + aggregates per split)
  RESULTS.md         numbers, methodology and limits
  other_tools.json   other tools: measurability check (public docs only)
  drift/             drift-corpus feasibility survey + package drift (registry metadata only)
```

## What a case is

Each case is one JSON file:

| field | meaning |
|---|---|
| `id` | `<split>-<family>-<nn>` |
| `split` | `dev` or `holdout` |
| `family` / `axis` | the mutation operator family and its axis (instruction_injection, invisible_chars, schema, annotations, tool_set, integrity, floating, benign, compound) |
| `seed` | the Phase 1/2 scenario the operator generalizes (A–I, F-pypi) |
| `base` | `demo` (notes over `npx`, weather over `uvx`) or `docker` (notes over `docker run`) |
| `mutation` | what changes after the lock: `notes_tools` / `weather_tools` (full tools/list documents served by the synthetic fixture server), `vscode_config` / `portable_config` (config file text), `registry_overlay` (recorded registry metadata that shadows `fixtures/registry`), `notes_server_args` |
| `labels` | `codes` (expected finding code set), `maxSeverity`, `exit` (with `--fail-on high`), `benign` |

The base workspace is always locked against the benign fixtures first; the
mutation is applied afterwards and `caplock verify --json` is run.

## Labels

Labels are written in `make_corpus.py` from what each operator means, and were
committed before the first scoring run (see the git history of `bench/cases/`).

- `maxSeverity` is the threat class a reviewer should be alerted at. For a
  paraphrased instruction this is `high` even though CapLock's patterns are not
  expected to match it.
- `codes` uses CapLock's own finding taxonomy (the rule catalog). Agreement on
  codes therefore measures conformance to CapLock's spec, not ground truth.

## Split

Whole operator families are assigned to one split; no family appears in both.
holdout therefore contains pattern variants that dev does not, e.g. concealment
and sensitive-file injections, paraphrased injections, tag-character smuggling,
destination parameters on local tools, docker integrity, PyPI file-set changes,
other floating spec shapes, and number/whitespace/order/transport benign controls.

holdout is used for scoring only. Phase 3 made no change to CapLock's detection
logic, so neither split was used for tuning; dev is the split that future
detector work may look at.

## Scope

- Everything is synthetic: the `caplock-demo` packages and the tool definitions
  derived from `fixtures/servers/tools/`. No real server's tool definitions are
  used, and only the local fixture server is launched.
- Running the bench needs no network.

```bash
.venv/bin/python bench/make_corpus.py   # regenerate cases (no change expected)
.venv/bin/python bench/run_bench.py     # score; rewrites results.json and RESULTS.md
```
