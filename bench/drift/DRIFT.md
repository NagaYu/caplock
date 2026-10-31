# Drift corpus v0 — feasibility survey and package drift

Fetched 2026-10-31T04:43:34Z – 2026-10-31T05:06:09Z (UTC). Registry metadata only: no package contents were downloaded and no server was run. Raw responses and their sha256 are in `raw/` (`raw/MANIFEST.json`).

## 1. Coverage first (decides the scope)

- Method: git ls-remote --tags and GET raw.githubusercontent.com/<repo>/HEAD/<file> for manifest.json, tools.json, mcp.json, server.json, .well-known/mcp.json; a file counts only if it is JSON with a tools[] list of named tools.
- Top 30 npm-backed entries: 30/30 have a GitHub repository; 21/30 have one of the candidate files at HEAD, but **0/30 contain a tool list** (mostly `server.json`, which is registry metadata without tools; a manual check of the MCPB `manifest.json` files found no `tools` list, one declaring `tools_generated: true`).
- PyPI random sample: 1/10 with a tool list (macos-mcp; names and descriptions only, 0 with inputSchema).
- Coverage 0% vs kill threshold 10% → **surface drift OUT OF SCOPE for v0 (coverage below the kill threshold); package drift only**. Human-readable tool lists in READMEs and docs exist for many servers but were not treated as definitions (no schema, not versioned with the package).

## 2. Selection

- npm: top 30 distinct npm packages by last-month downloads among active latest registry entries with exactly one npm/PyPI package. Unscoped: api.npmjs.org bulk downloads. Scoped (no bulk API): the monthly count npm search reports for its first 2000 results of text=mcp; scoped packages outside that window have no count and rank last.
- PyPI: random sample of 10 distinct PyPI packages (random.Random(0), sorted by name) among the same registry entries; not a top list, because PyPI has no first-party download statistics

## 3. Registry-wide metadata

- Latest entries: 53449; remote-only (no package, CapLock: always unverifiable): 31231.
- npm/PyPI package entries carrying any content-hash field: 0/19646.
- Package entries with a hash field, by registry type: cargo 0/107, mcpb 2089/2089, npm 0/14682, nuget 0/166, oci 0/1337, pypi 0/4964.
- Version spec of npm/PyPI package entries: npm:exact 14667, npm:non-exact 15, pypi:exact 4962, pypi:non-exact 2.

## 4. Package drift — npm top 30

- Versions: 6237 in total; with sha512 integrity 6236, shasum (sha1) only 1 (in 1 packages), no hash 0.
- Releases in the last 90 days: 1151 (26/30 packages released at least once; median 17.0 per package). Median of per-package median days between releases (last year): 2.29.
- Latest version with an npm provenance attestation: 26/30.
- Unpublished versions (listed in `time`, gone from `versions`): 12 in 5 packages. A lockfile pinned to one of them can no longer be re-verified.
- Registry entry's version not on npm: 0/30; registry version older than npm `latest`: 13/30.

| package | versions | 90d releases | median days between | shasum-only | unpublished | latest provenance |
|---|---|---|---|---|---|---|
| `@playwright/mcp` | 436 | 31 | 1.0 | 0 | 0 | yes |
| `firebase-tools` | 566 | 28 | 3.91 | 1 | 0 | no |
| `@storybook/addon-mcp` | 86 | 41 | 1.31 | 0 | 0 | yes |
| `chrome-devtools-mcp` | 65 | 7 | 6.23 | 0 | 1 | yes |
| `color-space` | 64 | 4 | 1.45 | 0 | 0 | yes |
| `@upstash/context7-mcp` | 97 | 21 | 3.42 | 0 | 0 | no |
| `snyk` | 2138 | 105 | 0.7 | 0 | 7 | no |
| `telnyx` | 276 | 18 | 0.53 | 0 | 0 | yes |
| `@wonderwhy-er/desktop-commander` | 126 | 10 | 2.54 | 0 | 0 | yes |
| `agent-device` | 213 | 63 | 0.75 | 0 | 0 | yes |
| `e2e` | 58 | 50 | 0.82 | 0 | 0 | yes |
| `rea-agents` | 34 | 16 | 0.67 | 0 | 0 | yes |
| `@zereight/mcp-gitlab` | 230 | 90 | 0.91 | 0 | 2 | yes |
| `@swmansion/argent` | 424 | 317 | 0.04 | 0 | 0 | yes |
| `firecrawl-mcp` | 139 | 41 | 1.07 | 0 | 0 | yes |
| `mongodb-mcp-server` | 104 | 26 | 2.04 | 0 | 0 | yes |
| `@sentry/mcp-server` | 47 | 5 | 10.28 | 0 | 0 | no |
| `next-devtools-mcp` | 35 | 0 | 3.62 | 0 | 0 | yes |
| `figma-developer-mcp` | 51 | 0 | 3.05 | 0 | 1 | yes |
| `@sap-ux/fiori-mcp-server` | 185 | 47 | 1.26 | 0 | 0 | yes |
| `repomix` | 86 | 2 | 13.01 | 0 | 0 | yes |
| `@hostinger/mcp` | 117 | 117 | 0.07 | 0 | 1 | yes |
| `@ui5/mcp-server` | 31 | 6 | 10.08 | 0 | 0 | yes |
| `@supabase/mcp-server-supabase` | 63 | 6 | 20.01 | 0 | 0 | yes |
| `xcodebuildmcp` | 80 | 0 | 3.99 | 0 | 0 | yes |
| `nx-mcp` | 50 | 0 | 5.05 | 0 | 0 | yes |
| `@softeria/ms-365-mcp-server` | 346 | 78 | 0.27 | 0 | 0 | yes |
| `@cap-js/mcp-server` | 9 | 4 | 18.19 | 0 | 0 | yes |
| `@mobilenext/mobile-mcp` | 75 | 16 | 6.22 | 0 | 0 | yes |
| `@serdnaley/metabase-mcp` | 6 | 2 | 5.86 | 0 | 0 | yes |

## 5. Package drift — PyPI random sample

- 10/10 fetched; 200 releases; files without sha256: 0.
- Releases whose file set grew more than 24 h after the first upload (the same version number with different content over time; CapLock's integritySet reports this as integrity_mismatch): 0.
- Releases with yanked files: 0; registry version not on PyPI: 0.

## Not measured

- Tool-surface drift between versions (coverage below the kill threshold; see surfaces).
- Whether package contents changed under an unchanged version: npm forbids republishing a version, so registry metadata can only show unpublished versions and late-added PyPI files, not silent rewrites.
- Anything about runtime behavior; no package was downloaded and no server was run.

## Redistribution

`raw/` holds registry API responses with README / long-description fields removed (the original response's sha256 is kept). Tool-definition file bodies were not stored. Review the registries' terms before redistributing `raw/`; it is excluded from the publication packet.
