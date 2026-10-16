"""Explicit lab runner producing a sanitized local JSON report."""
import argparse
import datetime
import json
import os
import sys
import unittest
import uuid
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("suite", choices=["safety", "auth", "all"])
    args = parser.parse_args()
    from tests.support import LabConfig
    config = LabConfig.from_environment()
    snapshot = os.getenv("BLOODYAD_LAB_SNAPSHOT")
    if args.suite != "auth":
        if not snapshot:
            parser.error("BLOODYAD_LAB_SNAPSHOT must identify the verified pre-test VM snapshot")
        uuid.UUID(snapshot)
    os.environ["BLOODYAD_LAB_TESTS"] = "1"
    names = []
    if args.suite in ("safety", "all"):
        names.append("tests.test_integration_safety")
    if args.suite in ("auth", "all"):
        names.append("tests.test_authentication")
    suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    result = unittest.TextTestRunner(verbosity=2, failfast=True).run(suite)
    report = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "suite": args.suite, "host": config.host, "ip": config.ip,
        "snapshot": snapshot, "python": sys.version.split()[0],
        "tests_run": result.testsRun, "successful": result.wasSuccessful(),
        "failures": [test.id() for test, detail in result.failures],
        "errors": [test.id() for test, detail in result.errors],
        "skips": [{"test": test.id(), "reason": reason} for test, reason in result.skipped],
    }
    destination = Path(__file__).resolve().parent / "reports"
    destination.mkdir(exist_ok=True)
    name = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + args.suite + ".json"
    (destination / name).write_text(json.dumps(report, indent=2), encoding="utf-8")
    raise SystemExit(not result.wasSuccessful())


if __name__ == "__main__":
    main()
