import hashlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from tests.e2e_installed import verify_wheel_files
from tests.support import ROOT


class CliIdentityTests(unittest.TestCase):
    def test_help_identifies_the_fork_even_from_the_source_launcher(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "bloodyAD.py"), "--help"],
            cwd=tempfile.gettempdir(), capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.startswith("usage: bloodyad-opsec "), result.stdout)


class WheelAttestationTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.wheel = Path(self.folder.name) / "example.whl"
        with zipfile.ZipFile(self.wheel, "w") as archive:
            archive.writestr("bloodyAD/main.py", b"original runtime")
            archive.writestr("bloodyad_opsec-0.1.0.dist-info/METADATA", b"version metadata")
        self.installed = {"bloodyAD/main.py": hashlib.sha256(b"original runtime").hexdigest(),
                          "bloodyad_opsec-0.1.0.dist-info/METADATA": hashlib.sha256(b"version metadata").hexdigest()}

    def test_matching_runtime_and_metadata_are_verified(self):
        self.assertEqual(verify_wheel_files(self.wheel, self.installed), 2)

    def test_modified_missing_extra_and_wrong_version_files_are_rejected(self):
        candidates = [
            {**self.installed, "bloodyAD/main.py": "wrong"},
            {"bloodyAD/main.py": self.installed["bloodyAD/main.py"]},
            {**self.installed, "bloodyAD/extra.py": "unexpected"},
            {**self.installed, "bloodyad_opsec-0.1.0.dist-info/METADATA": "wrong version"},
        ]
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                with self.assertRaises(ValueError):
                    verify_wheel_files(self.wheel, candidate)
