import atexit
import shutil
import tempfile
import sqlite3
from pathlib import Path

import pytest

from redmesh_vulndb import build, fetch

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_CACHE = ROOT / "tests/fixtures/cache"


def _plain_root():
  """The data files without distro_map.toml: the fixture cache has no distro sources, and the distro_fix gate needs them."""
  plain = Path(tempfile.mkdtemp(prefix="vulndb-plain-root-"))
  for name in ("product_map.toml", "eol.toml"):
    shutil.copy(ROOT / name, plain / name)
  for d in ("overlay", "allowlist", "tests/golden"):
    shutil.copytree(ROOT / d, plain / d)
  atexit.register(shutil.rmtree, plain, ignore_errors=True)
  return plain


PLAIN_ROOT = _plain_root()


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
  def refuse(url):
    raise AssertionError(f"tests must not use the network: {url}")
  monkeypatch.setattr(fetch, "_open", refuse)


@pytest.fixture(scope="session")
def built(tmp_path_factory):
  """The fixture cache built once with the real product map and overlay: (db path, build record)."""
  out = tmp_path_factory.mktemp("build") / "vulndb.sqlite"
  record = build.build(FIXTURE_CACHE, out, root=PLAIN_ROOT, log=lambda *_: None)
  return out, record


@pytest.fixture
def db(built):
  con = sqlite3.connect(f"file:{built[0]}?mode=ro", uri=True)
  yield con
  con.close()


@pytest.fixture
def root_copy(tmp_path):
  """A writable copy of the data files, for tests that change the overlay."""
  for name in ("product_map.toml", "eol.toml", "distro_map.toml"):
    shutil.copy(ROOT / name, tmp_path / name)
  (tmp_path / "overlay").mkdir()
  shutil.copy(ROOT / "overlay/curated.json", tmp_path / "overlay/curated.json")
  shutil.copytree(ROOT / "allowlist", tmp_path / "allowlist")
  shutil.copytree(ROOT / "tests/golden", tmp_path / "tests/golden")
  return tmp_path
