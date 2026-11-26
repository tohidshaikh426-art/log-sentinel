"""Smoke tests for Phase 1 collector package foundation."""

import log_sentinel
from log_sentinel import collector, config, detection, ingestion, parser


def test_package_version_and_subpackages():
    assert log_sentinel.__version__ == "1.0.0"
    assert all(m is not None for m in (collector, config, detection, ingestion, parser))
