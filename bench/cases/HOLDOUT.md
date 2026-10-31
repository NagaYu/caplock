# Holdout split (withheld)

The holdout split of CapLock Bench v0 (48 cases, 22 operator families) is not
published in this repository.

- Its labels were written in the generator and committed before the first scoring run, together with the
  dev split, and the cases were then scored once with CapLock 0.1.0. The holdout numbers in
  `bench/RESULTS.md` and `bench/results.json` come from that full-corpus run (re-run unchanged on
  2026-10-31T09:10:53Z).
- `results.json` records, per holdout case, the id, family, axis, labels, CapLock's observed outcome and the
  score, but not the mutation itself. The generator in this repository (`bench/make_corpus.py`) contains the
  dev operator families only; the holdout operators were removed because they would regenerate the cases.
- Identity can be checked on any future disclosure: `results.json` → `corpusDigest`
  (`sha256:45d8a333cd01d9e3adbba2ad1e7ef77bb0c7bf927919788ff191bf876b848562`) is the sha256 over all 90 cases, dev and holdout, computed by
  `bench/run_bench.py:corpus_digest`.
- In this tree, `bench/run_bench.py` scores the dev split only and does not rewrite `results.json` /
  `RESULTS.md`; the related tests skip what needs the holdout files.
