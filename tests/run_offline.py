"""Run all offline tests without enabling any lab or legacy mutation suite."""
import os
import unittest
from pathlib import Path


def main():
    os.environ.pop("BLOODYAD_LAB_TESTS", None)
    os.environ.pop("BLOODYAD_LEGACY_TESTS", None)
    root = Path(__file__).resolve().parent.parent
    loader = unittest.TestLoader()
    suite = loader.discover(str(root / "tests"), top_level_dir=str(root))
    suite.addTests(loader.loadTestsFromName("tests.unit_test"))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    raise SystemExit(not result.wasSuccessful())


if __name__ == "__main__":
    main()
