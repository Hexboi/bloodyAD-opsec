"""Opt-in integration tests limited to per-run temporary objects."""
import asyncio
import os
import secrets
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from bloodyAD.cli_modules import add, remove, rollback, set as setter
from bloodyAD.network.ldap import Scope
from bloodyAD.opsec import OpsecOptions
from bloodyAD.rollback import JournalConflict, RollbackJournal, read_state
from bloodyAD.search_policy import ScopeViolationError
from tests.fixtures import LabFixture, snapshot_fixture_state
from tests.support import LabConfig


@unittest.skipUnless(os.getenv("BLOODYAD_LAB_TESTS") == "1", "Lab tests are opt-in")
class SafetyIntegrationTests(unittest.IsolatedAsyncioTestCase):
    def _callTestMethod(self, method):
        self._callAsync(self._run_bounded, method)

    async def _run_bounded(self, method):
        await asyncio.wait_for(method(), timeout=45)

    async def asyncSetUp(self):
        self.config = LabConfig.from_environment()
        self.fixture = LabFixture(self.config)
        self.addAsyncCleanup(self.fixture.close)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        await asyncio.wait_for(self.fixture.start(), timeout=25)

    async def connection(self, options):
        conn = self.config.connection(options=options)
        self.addAsyncCleanup(conn.closeLdap)
        return conn

    async def test_dry_run_preserves_fixture_state_and_creates_no_journal(self):
        before = await snapshot_fixture_state(self.fixture)
        path = Path(self.temp.name) / "never-created.jsonl"
        conn = await self.connection(OpsecOptions(dry_run=True))
        user = "badry" + self.fixture.short
        password = secrets.token_urlsafe(20) + "!Aa7"
        results = [
            await add.user(conn, user, password, self.fixture.base),
            await add.computer(conn, "badc" + self.fixture.short, password, self.fixture.base),
            await setter.object(conn, self.fixture.user, "description", ["after"]),
            await setter.password(conn, self.fixture.user, password),
            await add.groupMember(conn, self.fixture.group, self.fixture.user),
            await remove.groupMember(conn, self.fixture.group, self.fixture.user),
            await remove.object(conn, self.fixture.user),
        ]
        journal_conn = await self.connection(OpsecOptions(dry_run=True, rollback_file=str(path)))
        results.append(await add.user(journal_conn, user, password, self.fixture.base))
        self.assertTrue(all(result.status == "simulated" for result in results))
        self.assertEqual(before, await snapshot_fixture_state(self.fixture))
        self.assertFalse(path.exists())

    async def test_scope_preserves_point_queries_and_rejects_siblings(self):
        inside = "OU=Inside," + self.fixture.base
        outside = "OU=Outside," + self.fixture.base
        for dn, name in ((inside, "Inside"), (outside, "Outside")):
            await self.fixture.create(dn, {"objectClass": ["top", "organizationalUnit"], "ou": name})
        conn = await self.connection(OpsecOptions(base_dn=inside))
        ldap = await conn.getLdap()
        entries = [entry async for entry in ldap.bloodysearch(inside, attr=["distinguishedName"])]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["distinguishedName"].lower(), inside.lower())
        narrowed = [entry async for entry in ldap.bloodysearch(ldap.domainNC, search_scope=Scope.SUBTREE)]
        self.assertEqual(len(narrowed), 1)
        with self.assertRaises(ScopeViolationError):
            _ = [entry async for entry in ldap.bloodysearch(outside)]
        with self.assertRaises(ScopeViolationError):
            _ = [entry async for entry in ldap.bloodysearch(ldap.domainNC)]

    async def test_journal_recovers_user_computer_membership_and_attribute_in_lifo_order(self):
        baseline = await snapshot_fixture_state(self.fixture)
        path = Path(self.temp.name) / "recovery.jsonl"
        conn = await self.connection(OpsecOptions(rollback_file=str(path)))
        password = secrets.token_urlsafe(20) + "!Aa7"
        user_name, pc_name = "bau" + self.fixture.short, "bac" + self.fixture.short
        user_dn, pc_dn = "CN=" + user_name + "," + self.fixture.base, "CN=" + pc_name + "," + self.fixture.base
        self.fixture.expect(user_dn)
        await add.user(conn, user_name, password, self.fixture.base)
        await self.fixture.identify(user_dn)
        self.fixture.expect(pc_dn)
        await add.computer(conn, pc_name, password, self.fixture.base)
        await self.fixture.identify(pc_dn)
        await add.groupMember(conn, self.fixture.group, user_dn)
        await setter.object(conn, user_dn, "description", ["after"], bak=True)
        records = RollbackJournal(path).read_actions()
        self.assertEqual(len(records), 4)
        self.assertTrue(all(record["status"] == "applied" for record in records))
        self.assertTrue(password not in path.read_text(encoding="utf-8"), "Credential data found in journal")
        outcomes = await rollback.apply(self.fixture.conn, str(path))
        self.assertEqual(len(outcomes), 4)
        self.assertEqual(await rollback.apply(self.fixture.conn, str(path)), [])
        self.assertEqual(baseline, await snapshot_fixture_state(self.fixture))

    async def test_recovery_preserves_an_external_attribute_update(self):
        path = Path(self.temp.name) / "conflict.jsonl"
        conn = await self.connection(OpsecOptions(rollback_file=str(path)))
        await setter.object(conn, self.fixture.user, "description", ["recorded"], bak=True)
        await self.fixture.ldap.bloodymodify(self.fixture.user, {"description": [("replace", ["external"])]})
        with self.assertRaises(JournalConflict):
            await rollback.apply(self.fixture.conn, str(path))
        current = await read_state(self.fixture.ldap, self.fixture.user, "description")
        from bloodyAD.rollback import decode_values
        self.assertEqual(decode_values(current["values"]), [b"external"])

    async def test_external_restore_cannot_authorize_deletion_of_created_user(self):
        path = Path(self.temp.name) / "external-restore.jsonl"
        conn = await self.connection(OpsecOptions(rollback_file=str(path)))
        name = "baxs" + self.fixture.short
        target = "CN=" + name + "," + self.fixture.base
        self.fixture.expect(target)
        await add.user(conn, name, secrets.token_urlsafe(20) + "!Aa7", self.fixture.base)
        await self.fixture.identify(target)
        await setter.object(conn, target, "description", ["recorded"], bak=True)
        await self.fixture.ldap.bloodymodify(target, {
            "description": [("replace", [])], "title": [("replace", ["external change"])],
        })
        with self.assertRaises(JournalConflict):
            await rollback.apply(self.fixture.conn, str(path))
        self.assertIsNotNone(await read_state(self.fixture.ldap, target))
        self.assertTrue(all(a["status"] == "applied" for a in RollbackJournal(path).read_actions()))

    async def test_recovery_preserves_membership_removed_and_readded_externally(self):
        from bloodyAD.rollback import decode_values
        path = Path(self.temp.name) / "readded.jsonl"
        conn = await self.connection(OpsecOptions(rollback_file=str(path)))
        await add.groupMember(conn, self.fixture.group, self.fixture.user)
        await self.fixture.ldap.bloodymodify(self.fixture.group, {"member": [("delete", [self.fixture.user])]})
        await self.fixture.ldap.bloodymodify(self.fixture.group, {"member": [("add", [self.fixture.user])]})
        with self.assertRaises(JournalConflict):
            await rollback.apply(self.fixture.conn, str(path))
        state = await read_state(self.fixture.ldap, self.fixture.group, "member")
        members = [v.decode().lower() if isinstance(v, bytes) else v.lower() for v in decode_values(state["values"])]
        self.assertIn(self.fixture.user.lower(), members)

    async def test_preexisting_membership_is_unchanged_and_not_journaled(self):
        path = Path(self.temp.name) / "unchanged.jsonl"
        await self.fixture.ldap.bloodymodify(self.fixture.group, {"member": [("add", [self.fixture.user])]})
        conn = await self.connection(OpsecOptions(rollback_file=str(path)))
        result = await add.groupMember(conn, self.fixture.group, self.fixture.user)
        self.assertEqual(result.status, "unchanged")
        self.assertFalse(path.exists())

    async def test_unprivileged_fixture_write_fails_without_applied_journal_record(self):
        from badldap.commons.exceptions import LDAPModifyException
        path = Path(self.temp.name) / "denied.jsonl"
        username = "balp" + self.fixture.short
        password = secrets.token_urlsafe(20) + "!Aa7"
        user_dn = "CN=" + username + "," + self.fixture.base
        self.fixture.expect(user_dn)
        await add.user(self.fixture.conn, username, password, self.fixture.base)
        await self.fixture.identify(user_dn)
        config = replace(self.config, username=username, password=password)
        conn = config.connection(options=OpsecOptions(rollback_file=str(path)))
        self.addAsyncCleanup(conn.closeLdap)
        before = await read_state(self.fixture.ldap, self.fixture.group, "description")
        with self.assertRaises(LDAPModifyException) as error:
            await setter.object(conn, self.fixture.group, "description", ["not-authorized"], bak=True)
        self.assertEqual(error.exception.resultcode, 50)
        self.assertEqual(before, await read_state(self.fixture.ldap, self.fixture.group, "description"))
        actions = RollbackJournal(path).read_actions()
        self.assertEqual([action["status"] for action in actions], ["prepared"])
