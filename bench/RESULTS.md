# CapLock Bench v0 — results

CapLock 0.1.0 · rule catalog 1.0.0 · corpus 0.1.0 (`sha256:45d8a333cd01d9e3…`) · `--fail-on high` · generated 2026-10-31T09:10:53Z

> Synthetic corpus, scored by its author's own tool. Read the methodology and limits below before quoting any number. CapLock pins the declared tool surface and the package identity. It does not attest to the runtime behavior or safety of any server.

## Headline numbers (dev and holdout reported separately)

| metric | dev | holdout |
|---|---|---|
| detection, unverifiable class | 4/4 (100.0%) | 10/10 (100.0%) |
| detection, critical class | 11/11 (100.0%) | 16/16 (100.0%) |
| detection, high class | 16/16 (100.0%) | 12/15 (80.0%) |
| detection, medium class | 5/5 (100.0%) | 0/0 (n/a) |
| detection, info class | 0/0 (n/a) | 0/0 (n/a) |
| detection, all non-benign | 36/36 (100.0%) | 38/41 (92.7%) |
| false positives on benign controls | 0/6 (0.0%) | 0/7 (0.0%) |
| exit code matches label | 42/42 (100.0%) | 45/48 (93.8%) |
| finding-code set matches label exactly | 42/42 (100.0%) | 45/48 (93.8%) |
| max severity matches label exactly | 42/42 (100.0%) | 45/48 (93.8%) |
| expected codes reported (micro recall) | 58/58 (100.0%) | 64/67 (95.5%) |
| unverifiable cases returned exit 2 | 4/4 (100.0%) | 10/10 (100.0%) |
| floating-spec cases returned exit 2 | 4/4 (100.0%) | 8/8 (100.0%) |

Cases: dev 42 (6 benign), holdout 48 (7 benign).

## Cases that did not match

| case | label (sev / exit) | observed (sev / exit) | missing codes | extra codes | detected / FP |
|---|---|---|---|---|---|
| `holdout-inj-paraphrase-01` | high / 1 | medium / 0 | instruction_injection | - | **missed** |
| `holdout-inj-paraphrase-02` | high / 1 | medium / 0 | instruction_injection | - | **missed** |
| `holdout-inj-paraphrase-03` | high / 1 | medium / 0 | instruction_injection | - | **missed** |

No case was removed from the corpus; every generated case is scored above.

## Per family

| split | family | axis | cases | exit match | exact codes |
|---|---|---|---|---|---|
| dev | ann-destructive | annotations | 2 | 2/2 | 2/2 |
| dev | ann-minor | annotations | 1 | 1/1 | 1/1 |
| dev | ann-readonly-false | annotations | 2 | 2/2 | 2/2 |
| dev | ben-format | benign | 3 | 3/3 | 3/3 |
| dev | ben-nfc | benign | 1 | 1/1 | 1/1 |
| dev | ben-version | benign | 2 | 2/2 | 2/2 |
| dev | combo-rugpull | compound | 1 | 1/1 | 1/1 |
| dev | float-npm-basic | floating | 3 | 3/3 | 3/3 |
| dev | float-pypi | floating | 1 | 1/1 | 1/1 |
| dev | inj-ignore | instruction_injection | 3 | 3/3 | 3/3 |
| dev | inj-invisible-zw | invisible_chars | 2 | 2/2 | 2/2 |
| dev | inj-param-desc | instruction_injection | 2 | 2/2 | 2/2 |
| dev | inj-tag | instruction_injection | 4 | 4/4 | 4/4 |
| dev | int-npm | integrity | 2 | 2/2 | 2/2 |
| dev | int-pypi-wheel | integrity | 2 | 2/2 | 2/2 |
| dev | sch-constraint | schema | 2 | 2/2 | 2/2 |
| dev | sch-desc-host | schema | 1 | 1/1 | 1/1 |
| dev | sch-dest-required | schema | 2 | 2/2 | 2/2 |
| dev | sch-opt2req | schema | 2 | 2/2 | 2/2 |
| dev | tool-add | tool_set | 2 | 2/2 | 2/2 |
| dev | tool-remove | tool_set | 2 | 2/2 | 2/2 |
| holdout | ann-openworld | annotations | 2 | 2/2 | 2/2 |
| holdout | ann-readonly-absent | annotations | 2 | 2/2 | 2/2 |
| holdout | ben-number | benign | 2 | 2/2 | 2/2 |
| holdout | ben-order | benign | 2 | 2/2 | 2/2 |
| holdout | ben-transport | benign | 2 | 2/2 | 2/2 |
| holdout | ben-whitespace | benign | 1 | 1/1 | 1/1 |
| holdout | combo-mixed | compound | 2 | 2/2 | 2/2 |
| holdout | float-docker | floating | 2 | 2/2 | 2/2 |
| holdout | float-npm-other | floating | 4 | 4/4 | 4/4 |
| holdout | float-pypi-range | floating | 2 | 2/2 | 2/2 |
| holdout | inj-conceal | instruction_injection | 3 | 3/3 | 3/3 |
| holdout | inj-invisible-tag | invisible_chars | 2 | 2/2 | 2/2 |
| holdout | inj-paraphrase | instruction_injection | 3 | 0/3 | 0/3 |
| holdout | inj-sensitive | instruction_injection | 3 | 3/3 | 3/3 |
| holdout | int-docker | integrity | 1 | 1/1 | 1/1 |
| holdout | int-pypi-files | integrity | 3 | 3/3 | 3/3 |
| holdout | int-unrecorded | integrity | 2 | 2/2 | 2/2 |
| holdout | sch-default-host | schema | 2 | 2/2 | 2/2 |
| holdout | sch-dest-optional | schema | 2 | 2/2 | 2/2 |
| holdout | sch-exec | schema | 2 | 2/2 | 2/2 |
| holdout | tool-add-injected | tool_set | 2 | 2/2 | 2/2 |
| holdout | tool-rename | tool_set | 2 | 2/2 | 2/2 |

## Other tools

### Snyk Agent Scan (formerly Invariant Labs mcp-scan)

- Status: **unmeasured**
- Checked: 2026-10-31 (public documentation only; the tool was not installed or run)
- Condition (b) fails: the current README says scanning sends "tool names and descriptions" (with server configurations and signatures) to the analysis service, and a token must be set before any scan. Sending tool descriptions to an external API is incompatible with CapLock's product principle, so it was not run on the corpus.
- The README's `inspect` command ("Inspect components without analysis") gives no change verdict, so it is not a comparable detector; the README does not say whether it is network-free.
- Older Invariant documentation describes a `--local-only` flag that skips the Invariant API but runs an LLM-based check needing an OpenAI API key, i.e. still an external API; the flag is not in the current README. Either way condition (b) is not met.
- No number is reported for this tool. It was not installed or executed.
- Source: https://github.com/snyk/agent-scan (README, fetched 2026-10-31; github.com/invariantlabs-ai/mcp-scan now resolves there)
- Source: https://explorer.invariantlabs.ai/docs/mcp-scan/scanning (older docs describing --local-only)

### mcp-lock (@mcpguards/mcp-lock 0.1.2)

- Status: **unmeasured**
- Checked: 2026-10-31 (public documentation only; the tool was not installed or run)
- Condition (b) is met as far as the README shows: it records npm version and tarball integrity and does not read tool descriptions.
- Condition (a) fails for this corpus: verification resolves against the live npm registry (its exit code 3 is "Network / registry error") and the README documents no option for recorded registry metadata. The corpus packages (@caplock-demo/*) are synthetic and do not exist on npm, so the tool cannot run locally against these cases.
- Scope differs: npm packages only (the README shows a PyPI server as "not lockable"), no tool-surface or capability checks. Only the npm integrity and npm floating cases would be in its scope.
- No number is reported for this tool. It was not installed or executed.
- Source: https://registry.npmjs.org/@mcpguards%2fmcp-lock (package metadata and README, fetched 2026-10-31)

## Methodology

- **Corpus.** 90 cases generated by `bench/make_corpus.py` from the Phase 1 scenarios A–I and the Phase 2 PyPI variant of F. Each case locks the demo workspace against benign synthetic fixtures, applies one mutation operator (or two, for the compound family) and runs `caplock verify --json`.
- **Labels.** Written in the generator from the operator's meaning and committed before the first scoring run. `maxSeverity` is the threat class a reviewer should be alerted at (so a paraphrased injection is labeled `high` even though CapLock's patterns do not cover it). `codes` uses CapLock's own taxonomy, so exact-code agreement measures spec conformance, not ground truth. Labels were not edited after scoring.
- **Split.** Whole operator families go to dev or holdout. holdout holds pattern variants absent from dev and is used for scoring only. Phase 3 changed no detection logic, so neither split was used for tuning.
- **Metrics.** *Detection*: for a non-benign case, CapLock reported at least one finding at the labeled class or more severe (for `unverifiable`, exit 2). *False positive*: on a benign control, any finding code beyond the expected ones (only `version_changed` for version-only bumps) or a non-zero exit. *Exit match*: exit code equals the label (`--fail-on high`). *Exact codes*: the set of finding codes equals the label.

## Limits (read before quoting)

- **Synthetic.** Two tiny fixture servers (4 tools), synthetic packages, hand-written mutations. Real servers have larger surfaces, real registries have edge cases this corpus does not model.
- **Self-authored operators.** The operators and labels were written by the same project that wrote the detector, with the detector's rules in view. Over-fitting to its own operators is likely; dev numbers in particular say little about unseen attacks. holdout reduces, but does not remove, this bias.
- **Small denominators.** Several classes have only a handful of cases (for example 13 benign controls in total), so one case moves a rate by several points.
- **What is measured.** Whether CapLock reports a declared change to config, package identity or tool surface. Nothing here measures runtime behavior, and a matching lockfile does not mean a server is safe.
- **Not measured.** Mid-session `list_changed` swaps, servers that answer differently per client, http servers, and real-world drift (see `bench/drift/`).
