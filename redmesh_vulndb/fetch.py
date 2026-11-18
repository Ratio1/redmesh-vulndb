"""Fetch the v1 feeds into a cache directory and record a sha256 for every input.

Layout of the cache:
  nvd/nvdcve-2.0-<year>.json.gz, nvd/nvdcve-2.0-modified.json.gz   NVD JSON 2.0 yearly and modified feeds
  overrides/nvd-data-overrides-<commit>.zip                        anchore/nvd-data-overrides (CC0), pinned by commit
  cvelist/<asset>.zip                                              cvelistV5 release
  kev/kev.json                                                     CISA KEV
  epss/epss_scores-current.csv.gz                                  FIRST EPSS daily CSV (header has the model version)
  oval/com.ubuntu.<codename>.cve.oval.xml.bz2                      Canonical CVE OVAL per Ubuntu release (optional: distro_fix)
  debian/security-tracker.json                                     Debian Security Tracker JSON (optional: distro_fix)
  manifest.json                                                    {"inputs": {path: {sha256, bytes, url}}, "sources": {...}}
`sources.cvelist` / `sources.overrides` name the one file of their folder that the build reads ({"file", "release"|"commit"});
`fetch --refresh` deletes the superseded ones. `build --offline` reads only the manifest's files and refuses a
file whose sha256 differs from the manifest. Redirects must stay on https.
"""
import datetime
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

USER_AGENT = "redmesh-vulndb-builder/0.1"
NVD_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0/"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
CVELIST_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
OVERRIDES_API = "https://api.github.com/repos/anchore/nvd-data-overrides/commits/main"
OVERRIDES_ZIP = "https://codeload.github.com/anchore/nvd-data-overrides/zip/"
OVAL_URL = "https://security-metadata.canonical.com/oval/com.ubuntu.{}.cve.oval.xml.bz2"
DEBIAN_URL = "https://security-tracker.debian.org/tracker/data/json"
UBUNTU_RELEASES = ("focal", "jammy", "noble")  # the releases of distro_map.toml
KINDS = {"nvd": "*.json.gz", "overrides": "*.zip", "cvelist": "*.zip", "kev": "*.json", "epss": "*.csv.gz",
         "oval": "*.xml.bz2", "debian": "*.json"}


def sha256_file(path):
  h = hashlib.sha256()
  with open(path, "rb") as f:
    for chunk in iter(lambda: f.read(1 << 20), b""):
      h.update(chunk)
  return h.hexdigest()


class _HttpsOnly(urllib.request.HTTPRedirectHandler):
  def redirect_request(self, req, fp, code, msg, headers, newurl):
    if not newurl.startswith("https://"):
      raise urllib.error.URLError(f"refusing redirect to non-https URL {newurl}")
    new = super().redirect_request(req, fp, code, msg, headers, newurl)
    if new is not None and urlsplit(newurl).netloc != urlsplit(req.full_url).netloc:
      new.remove_header("Authorization")  # the token never follows a redirect to another host
    return new


def _request(url):
  """Request with the job token (GH_TOKEN or GITHUB_TOKEN, read-only) on api.github.com calls only; unauthenticated without one."""
  req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
  token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
  if token and urlsplit(url).netloc == "api.github.com":
    req.add_header("Authorization", f"Bearer {token}")
  return req


def _open(url):
  return urllib.request.build_opener(_HttpsOnly).open(_request(url), timeout=120)


def check_sha(sha):
  if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
    raise ValueError(f"not a git sha: {sha!r}")
  return sha


def check_asset(name, url):
  if not re.fullmatch(r"[\w.\-]+", name) or not url.startswith("https://github.com/"):
    raise ValueError(f"refusing release asset {name!r} at {url!r}")


def _download(url, dest):
  dest.parent.mkdir(parents=True, exist_ok=True)
  part = dest.with_name(dest.name + ".part")
  with _open(url) as r, open(part, "wb") as f:
    while chunk := r.read(1 << 20):
      f.write(chunk)
  part.replace(dest)


def selected(cache, manifest):
  """{kind: Path} of the cvelist and overrides files the manifest names."""
  out = {}
  for k, v in manifest.get("sources", {}).items():
    if k in ("cvelist", "overrides"):
      rel = Path(v["file"])
      if rel.is_absolute() or ".." in rel.parts:  # lexical: cache entries may be symlinks
        raise ValueError(f"manifest names {v['file']}, outside the cache")
      out[k] = Path(cache) / rel
  return out


def inputs(cache, sel=None):
  """Cache layout to {kind: [paths]}, each sorted; `sel` (from `selected`) pins cvelist and overrides to one file."""
  cache = Path(cache)
  found = {k: sorted(cache.glob(f"{k}/{pat}")) for k, pat in KINDS.items()}
  for kind, path in (sel or {}).items():
    if not path.exists():
      raise FileNotFoundError(f"manifest names {path}, which is missing")
    found[kind] = [path]
  for kind in ("nvd", "cvelist", "kev", "epss"):
    if not found[kind]:
      raise FileNotFoundError(f"cache {cache} has no {kind} input; run `redmesh-vulndb fetch`")
  return found


def write_manifest(cache, extra_sources=None, urls=None):
  """Hash every input in the layout and write manifest.json. Returns the manifest."""
  cache = Path(cache)
  old = {}
  if (cache / "manifest.json").exists():
    old = json.loads((cache / "manifest.json").read_text())
  sources = {**old.get("sources", {}), **(extra_sources or {})}
  for kind in ("cvelist", "overrides"):  # one file per kind: the pinned one, else the only one present
    files = sorted((cache / kind).glob("*.zip"))
    if kind in sources and (cache / sources[kind]["file"]).exists():
      continue
    if len(files) > 1:
      raise ValueError(f"more than one {kind} file in the cache and none selected: {[f.name for f in files]}")
    if files:
      sources[kind] = {"file": str(files[0].relative_to(cache))}
    else:
      sources.pop(kind, None)
  found = inputs(cache, selected(cache, {"sources": sources}))
  entries = {}
  for paths in found.values():
    for p in paths:
      rel = str(p.relative_to(cache))
      entries[rel] = {"sha256": sha256_file(p), "bytes": p.stat().st_size,
                      "url": (urls or {}).get(rel) or old.get("inputs", {}).get(rel, {}).get("url", "")}
  manifest = {"inputs": entries, "sources": sources}
  (cache / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
  return manifest


def verify(cache):
  """Return the manifest after checking every input against its recorded sha256."""
  cache = Path(cache)
  manifest = json.loads((cache / "manifest.json").read_text())
  found = inputs(cache, selected(cache, manifest))
  rels = {str(p.relative_to(cache)) for paths in found.values() for p in paths}
  if rels != set(manifest["inputs"]):
    raise ValueError(f"cache files differ from manifest: {sorted(rels ^ set(manifest['inputs']))}")
  for rel, meta in manifest["inputs"].items():
    if sha256_file(cache / rel) != meta["sha256"]:
      raise ValueError(f"sha256 mismatch for {rel}")
  return manifest


def _prune(cache, keep):
  """Remove the zips of `keep`'s folder that `keep` supersedes."""
  for p in (cache / keep).parent.glob("*.zip"):
    if p != cache / keep:
      p.unlink()


def fetch(cache, refresh=False, log=print):
  """Download what the cache lacks (everything with refresh), then write the manifest."""
  cache = Path(cache)
  urls, sources = {}, {}

  def get(rel, url):
    urls[rel] = url
    dest = cache / rel
    if refresh or not dest.exists():
      log(f"fetch {rel}")
      _download(url, dest)

  year = datetime.datetime.now(datetime.timezone.utc).year
  for y in [*range(2002, year + 1), "modified"]:
    get(f"nvd/nvdcve-2.0-{y}.json.gz", f"{NVD_BASE}nvdcve-2.0-{y}.json.gz")
  get("kev/kev.json", KEV_URL)
  get("epss/epss_scores-current.csv.gz", EPSS_URL)
  for rel_name in UBUNTU_RELEASES:
    get(f"oval/com.ubuntu.{rel_name}.cve.oval.xml.bz2", OVAL_URL.format(rel_name))
  get("debian/security-tracker.json", DEBIAN_URL)
  if refresh or not list((cache / "cvelist").glob("*.zip")):
    with _open(CVELIST_API) as r:
      rel = json.load(r)
    asset = next(a for a in rel["assets"] if a["name"].endswith(".zip") and "all_CVEs" in a["name"])
    check_asset(asset["name"], asset["browser_download_url"])
    get(f"cvelist/{asset['name']}", asset["browser_download_url"])
    sources["cvelist"] = {"file": f"cvelist/{asset['name']}", "release": rel["tag_name"]}
    _prune(cache, sources["cvelist"]["file"])
  if refresh or not list((cache / "overrides").glob("*.zip")):
    with _open(OVERRIDES_API) as r:
      sha = check_sha(json.load(r)["sha"])
    get(f"overrides/nvd-data-overrides-{sha}.zip", OVERRIDES_ZIP + sha)
    sources["overrides"] = {"file": f"overrides/nvd-data-overrides-{sha}.zip", "commit": sha}
    _prune(cache, sources["overrides"]["file"])
  return write_manifest(cache, sources, urls)
