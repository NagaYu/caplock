# Drift corpus v0

Feasibility first, collection second. `DRIFT.md` has the results; `summary.json` the numbers.

```
fetch.py      network stages (registry → rank → packages → surfaces → compress); metadata only
analyze.py    offline: raw/ → summary.json + DRIFT.md
selection.json  the 30 npm (top by downloads) + 10 PyPI (random sample) registry entries
raw/          saved responses; raw/MANIFEST.json records url, fetchedAt, status and sha256 of each
```

- Network use: registry.modelcontextprotocol.io, api.npmjs.org, registry.npmjs.org (packuments and
  search), pypi.org JSON API, `git ls-remote` against github.com, raw.githubusercontent.com. GET only.
- Never fetched: package tarballs / wheels / images. No server was run.
- Stored with fields removed: npm `readme`, PyPI `info.description` (originalSha256 kept);
  npm search results reduced to name + downloads. Tool-definition file bodies are not stored.
- Large responses are gzip-compressed (`mtime=0`); the manifest keeps both digests.
- `raw/` is for reproducibility of this survey, not for redistribution; it is excluded from `publish/`.

Re-run (network): `python bench/drift/fetch.py registry && … rank && … rank-retry && … packages && … surfaces && … compress`,
then `python bench/drift/analyze.py` (offline).

**Public repository:** `raw/` is not included (not for redistribution). `summary.json` and `DRIFT.md` are the published results; `fetch.py` documents how the data was obtained, but a re-fetch returns today's registry state, not the 2026-10-31 snapshot.
