import argparse
import asyncio
import contextlib
import io
import sys
import unittest
from unittest.mock import AsyncMock, patch

from bloodyAD.main import amain
from bloodyAD import opsec
from bloodyAD.cli_modules import add, rollback


class CapabilityTests(unittest.TestCase):
    def test_rejected_cli_combinations_never_construct_a_connection(self):
        cases = [
            ["--base-dn", "", "get", "search"],
            ["--dry-run", "add", "shadowCredentials", "target"],
            ["--dry-run", "add", "badSuccessor", "target"],
            ["--base-dn", "OU=Test,DC=example,DC=com", "get", "bloodhound"],
            ["--no-tombstone", "get", "writable", "--bh"],
            ["--sleep", "1", "msldap", "whoami"],
            ["--chunk", "1", "get", "object", "target"],
        ]
        for args in cases:
            with self.subTest(args=args):
                with patch.object(sys, "argv", ["bloodyAD", "-H", "invalid.example", *args]):
                    with patch("bloodyAD.main.ConnectionHandler", side_effect=AssertionError("Connection constructed before rejection")) as handler:
                        with contextlib.redirect_stderr(io.StringIO()):
                            with self.assertRaises(SystemExit) as error:
                                asyncio.run(amain())
                self.assertEqual(error.exception.code, 2)
                handler.assert_not_called()

    def test_library_shadow_command_rejects_dry_run_before_any_ldap_call(self):
        conn = argparse.Namespace(options=opsec.OpsecOptions(dry_run=True), getLdap=AsyncMock())
        with self.assertRaises(ValueError):
            asyncio.run(add.shadowCredentials(conn, "target"))
        conn.getLdap.assert_not_awaited()

    def test_library_recovery_rejects_unsupported_options_before_reading_journal(self):
        for options in (opsec.OpsecOptions(dry_run=True),
                        opsec.OpsecOptions(base_dn="OU=Test,DC=example,DC=com")):
            conn = argparse.Namespace(options=options, getLdap=AsyncMock())
            with self.subTest(options=options):
                with patch("bloodyAD.rollback.RollbackJournal") as journal:
                    with self.assertRaises(ValueError):
                        asyncio.run(rollback.apply(conn, "unused.jsonl"))
                    journal.assert_not_called()
                conn.getLdap.assert_not_awaited()
