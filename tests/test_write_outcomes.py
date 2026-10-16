import argparse
import unittest
from unittest.mock import AsyncMock, patch

from bloodyAD.network.ldap import Ldap
from bloodyAD.opsec import OpsecOptions


def fake_ldap(options=None):
    ldap = object.__new__(Ldap)
    ldap.options = options or OpsecOptions()
    ldap.domainname = "example.com"
    ldap.dnResolver = AsyncMock(return_value="CN=Test,DC=example,DC=com")
    ldap.add = AsyncMock(return_value=(True, None))
    ldap.modify = AsyncMock(return_value=(True, None))
    ldap.delete = AsyncMock(return_value=(True, None))
    ldap._con = argparse.Namespace(modify_dn=AsyncMock(return_value=(True, None)))
    return ldap


class WriteOutcomeTests(unittest.IsolatedAsyncioTestCase):
    async def test_post_write_local_failure_keeps_completed_transport_steps(self):
        from bloodyAD.operations import PartialWriteError
        for operation in ("add", "modify", "delete"):
            ldap = fake_ldap()
            cause = OSError("local failure after confirmed write")
            with self.subTest(operation=operation):
                with patch("bloodyAD.opsec.OpsecOptions.pause", AsyncMock(side_effect=cause)):
                    with self.assertRaises(PartialWriteError) as error:
                        if operation == "add":
                            await ldap.bloodyadd("test", attributes={})
                        elif operation == "modify":
                            await ldap.bloodymodify("test", {"description": [("replace", ["after"])]})
                        else:
                            await ldap.bloodydelete("test")
                self.assertEqual(error.exception.outcome.completed_steps, (operation,))
                self.assertIs(error.exception.__cause__, cause)
                getattr(ldap, operation).assert_awaited_once()

    async def test_cancelled_post_write_step_also_reports_applied_effect(self):
        import asyncio
        from bloodyAD.operations import PartialWriteError
        ldap = fake_ldap()
        with patch("bloodyAD.opsec.OpsecOptions.pause", AsyncMock(side_effect=asyncio.CancelledError())):
            with self.assertRaises(PartialWriteError) as error:
                await ldap.bloodyadd("test", attributes={})
        self.assertEqual(error.exception.outcome.completed_steps, ("add",))

    async def test_preexisting_membership_does_not_log_an_applied_write(self):
        from bloodyAD.cli_modules import add
        from bloodyAD.operations import WriteOutcome
        ldap = fake_ldap(OpsecOptions(rollback_file="unused.jsonl"))
        conn = argparse.Namespace(options=ldap.options, getLdap=AsyncMock(return_value=ldap))
        with patch("bloodyAD.rollback.add_member", AsyncMock(return_value=WriteOutcome(
                "unchanged", "modify", "group"))):
            with patch.object(add.LOG, "info") as log:
                result = await add.groupMember(conn, "group", "member")
        self.assertEqual(result.status, "unchanged")
        log.assert_not_called()

    async def test_simulation_never_reaches_any_mutative_transport(self):
        ldap = fake_ldap(OpsecOptions(dry_run=True))
        results = [await ldap.bloodyadd("test", attributes={}),
                   await ldap.bloodymodify("test", {"description": [("replace", ["new"])]}),
                   await ldap.bloodydelete("test")]
        self.assertEqual([r.status for r in results], ["simulated"] * 3)
        for method in (ldap.add, ldap.modify, ldap.delete, ldap._con.modify_dn):
            method.assert_not_awaited()

    async def test_success_is_explicit(self):
        ldap = fake_ldap()
        result = await ldap.bloodymodify("test", {"description": [("replace", ["new"])]})
        self.assertEqual(result.status, "applied")
        ldap.modify.assert_awaited_once()

    async def test_rename_failure_after_modify_is_reported_as_partial(self):
        from bloodyAD.operations import PartialWriteError
        ldap = fake_ldap()
        cause = RuntimeError("server refused rename")
        ldap._con.modify_dn.return_value = (False, cause)
        with self.assertRaises(PartialWriteError) as error:
            await ldap.bloodymodify("test", {
                "description": [("replace", ["new"])],
                "distinguishedName": [("replace", ["CN=New,DC=example,DC=com"])],
            })
        self.assertEqual(error.exception.outcome.status, "partial")
        self.assertEqual(error.exception.outcome.completed_steps, ("modify",))
        self.assertIs(error.exception.__cause__, cause)
