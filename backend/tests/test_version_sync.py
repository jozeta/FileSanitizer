"""The version in VERSION, README, frontend and backend must agree."""
import re
from pathlib import Path

import pytest

from app.config import settings

ROOT = Path(__file__).resolve().parents[2]


def test_backend_version_matches_version_file():
    version_file = ROOT / "VERSION"
    if not version_file.exists():
        pytest.skip("repo root not available (running inside the container image)")
    version = version_file.read_text().strip()
    assert settings.APP_VERSION == version
    ts = (ROOT / "frontend/src/version.ts").read_text()
    assert re.search(r"APP_VERSION\s*=\s*'%s'" % re.escape(version), ts)
    assert f'"version": "{version}"' in (ROOT / "frontend/package.json").read_text()
    assert f"**{version}**" in (ROOT / "README.md").read_text()
