import os
import unittest
from unittest.mock import patch


class HarnessTests(unittest.TestCase):
    def test_cli_failure_reports_exit_code_without_echoing_arguments(self):
        from tests.support import run_cli, LabCommandError
        with self.assertRaises(LabCommandError) as error:
            run_cli(["--unknown-CANARY"])
        self.assertEqual(error.exception.returncode, 2)
        self.assertNotIn("CANARY", str(error.exception))

    def test_help_runs_with_current_interpreter_without_credentials_in_output(self):
        from tests.support import run_cli
        result = run_cli(["--help"], env={"BLOODYAD_PASSWORD": "CANARY"})
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("CANARY", result.stdout + result.stderr)

    def test_loaded_credentials_are_not_in_configuration_repr_or_argv(self):
        from tests.support import LabConfig
        with patch.dict(os.environ, {"BLOODYAD_LAB_PASSWORD": "CANARY", "BLOODYAD_LAB_USER": "operator"}):
            config = LabConfig.from_environment()
        self.assertNotIn("CANARY", repr(config))
        self.assertNotIn("CANARY", config.arguments())
        self.assertEqual(config.password, "CANARY")
