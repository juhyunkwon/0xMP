"""Run the 0xMP test suite the supported way.

Test modules under tests/ are pytest modules: they rely on fixtures
(tmp_path) and on tests/conftest.py putting the project root on sys.path.
Running a file directly (`python tests/test_features.py`) therefore fails
with `ModuleNotFoundError: No module named 'server'` and would not execute
any test even if the import worked.

Usage:
    python run_tests.py                      # whole suite
    python run_tests.py tests/test_features.py
    python run_tests.py tests/test_features.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest  # noqa: E402


def main() -> int:
    args = sys.argv[1:] or ["tests", "-q"]
    return pytest.main(args)


if __name__ == "__main__":
    raise SystemExit(main())
