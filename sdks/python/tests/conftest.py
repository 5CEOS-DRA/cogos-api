"""Pytest fixtures shared across the SDK test suite.

The ``fixtures.json`` file is committed; it is regenerated from the live
server primitives by ``tests/generate_fixtures.js``. Re-run that script
whenever the wire format changes.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

# Make the package importable without a `pip install -e .` step. Tests run
# from sdks/python/ directly, so we put that on sys.path.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session")
def fixtures() -> dict:
    """Cross-implementation byte-exact fixtures produced by node."""
    p = Path(__file__).resolve().parent / "fixtures.json"
    return json.loads(p.read_text("utf-8"))
