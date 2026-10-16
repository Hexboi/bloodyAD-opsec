import argparse
import contextlib
import io
import unittest
from unittest.mock import AsyncMock

from bloodyAD import exceptions
from bloodyAD.cli_modules import add, remove, set as setter
from bloodyAD.opsec import OpsecOptions
from tests.test_write_outcomes import fake_ldap


class DryRunTests(unittest.IsolatedAsyncioTestCase):
    async def test_basic_command_callers_stop_before_success_and_journal(self):
        ldap = fake_ldap(OpsecOptions(dry_run=True))
        conn = argparse.Namespace(options=ldap.options, getLdap=AsyncMock(return_value=ldap))
        for command, args in (
            (add.user, ("user", "CANARY", "OU=Test,DC=example,DC=com")),
            (add.computer, ("pc", "CANARY", "OU=Test,DC=example,DC=com")),
            (add.groupMember, ("group", "member")),
            (setter.object, ("user", "description", ["CANARY"])),
            (setter.password, ("user", "CANARY")),
            (remove.object, ("user",)),
            (remove.groupMember, ("group", "member")),
        ):
            with self.subTest(command=command.__name__):
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors):
                    exceptions.enableCliLogger("INFO")
                    result = await command(conn, *args)
                self.assertEqual(result.status, "simulated")
                self.assertNotIn("CANARY", errors.getvalue())
                self.assertNotIn("successfully", errors.getvalue())
                self.assertNotIn("created", errors.getvalue())
        ldap.add.assert_not_awaited()
        ldap.modify.assert_not_awaited()
        ldap.delete.assert_not_awaited()
