import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "journal.jsonl"

    def action(self, target="CN=One,DC=example,DC=com"):
        return {"kind": "delete_created", "target_dn": target,
                "domain_dn": "DC=example,DC=com", "server": "dc.example.com"}

    def test_only_confirmed_actions_are_recovered_in_reverse_order(self):
        from bloodyAD.rollback import RollbackJournal, plan_rollback
        journal = RollbackJournal(self.path)
        first = journal.prepare(self.action())
        journal.mark_applied(first, {"guid": "00000000-0000-0000-0000-000000000001", "usn": "10"})
        pending = journal.prepare(self.action("CN=Pending,DC=example,DC=com"))
        second = journal.prepare(self.action("CN=Two,DC=example,DC=com"))
        journal.mark_applied(second, {"guid": "00000000-0000-0000-0000-000000000002", "usn": "11"})
        records = journal.read_actions()
        self.assertEqual([a["operation_id"] for a in plan_rollback(records)], [second, first])
        self.assertIn(pending, [a["operation_id"] for a in records if a["status"] == "prepared"])

    def test_legacy_or_truncated_journal_is_rejected_without_execution(self):
        from bloodyAD.rollback import RollbackJournal, JournalError
        for content in ("remove object name\n", '{"version":1'):
            self.path.write_text(content, encoding="utf-8")
            with self.assertRaises(JournalError):
                RollbackJournal(self.path).read_actions()

    def test_sensitive_and_unclassified_attribute_backups_are_rejected(self):
        from bloodyAD.rollback import RollbackJournal
        for attribute in ("unicodePwd", "supplementalCredentials", "unknownAttribute"):
            action = self.action()
            action.update(kind="restore_attribute", attribute=attribute, before=[], after=[])
            with self.assertRaises(ValueError):
                RollbackJournal(self.path).prepare(action)
        self.assertFalse(self.path.exists())

    def test_recovered_marker_is_persistent_and_keeps_own_change_sequence(self):
        from bloodyAD.rollback import RollbackJournal, plan_rollback
        journal = RollbackJournal(self.path)
        operation = journal.prepare(self.action())
        state = {"guid": "00000000-0000-0000-0000-000000000001", "usn": "10"}
        journal.mark_applied(operation, state)
        journal.mark_recovered(operation, {"guid": state["guid"], "usn": "12"})
        recovered = RollbackJournal(self.path).read_actions()
        self.assertEqual(plan_rollback(recovered), [])
        self.assertEqual(recovered[0]["recovery_evidence"]["usn"], "12")


class RecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_later_recovery_conflict_reports_prior_completed_actions(self):
        import argparse
        from bloodyAD.cli_modules import rollback
        from bloodyAD.rollback import RollbackJournal, JournalConflict
        from bloodyAD.operations import WriteOutcome, PartialWriteError
        from bloodyAD.opsec import OpsecOptions
        ldap = self.recovery_ldap()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "journal.jsonl"
            journal = RollbackJournal(path)
            actions = []
            for name in ("One", "Two"):
                action = self.recovery_action("delete_created")
                action["target_dn"] = "CN=" + name + ",DC=example,DC=com"
                op = journal.prepare(action)
                journal.mark_applied(op, {"guid": "00000000-0000-0000-0000-000000000001", "usn": "10"})
                actions.append(op)
            conn = argparse.Namespace(options=OpsecOptions(), getLdap=AsyncMock(return_value=ldap))
            conflict = JournalConflict("changed target")
            results = [WriteOutcome("applied", "delete", "CN=Two,DC=example,DC=com", ("delete",)), conflict]
            with patch("bloodyAD.rollback.apply_action", AsyncMock(side_effect=results)):
                with patch("bloodyAD.rollback.read_state", AsyncMock(return_value=None)):
                    with self.assertRaises(PartialWriteError) as error:
                        await rollback.apply(conn, str(path))
            self.assertEqual(error.exception.outcome.completed_steps, ("recovery:" + actions[1],))
            self.assertIs(error.exception.__cause__, conflict)
            self.assertEqual([a["status"] for a in journal.read_actions()], ["applied", "recovered"])

    def recovery_ldap(self):
        from tests.test_write_outcomes import fake_ldap
        ldap = fake_ldap()
        ldap.domainNC = "DC=example,DC=com"
        ldap.conf = type("Config", (), {"host": "dc.example.com"})()
        return ldap

    def recovery_action(self, kind="restore_attribute"):
        return {"kind": kind, "target_dn": "CN=One,DC=example,DC=com",
                "domain_dn": "DC=example,DC=com", "server": "dc.example.com"}

    async def test_external_restore_does_not_authorize_deletion_of_created_object(self):
        import argparse
        from bloodyAD.rollback import RollbackJournal, encode_values, JournalConflict
        from bloodyAD.cli_modules import rollback
        from bloodyAD.opsec import OpsecOptions
        ldap = self.recovery_ldap()
        guid = "00000000-0000-0000-0000-000000000001"
        before = encode_values([b"before"])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "journal.jsonl"
            journal = RollbackJournal(path)
            creation = journal.prepare(self.recovery_action("delete_created"))
            journal.mark_applied(creation, {"guid": guid, "usn": "10"})
            action = self.recovery_action()
            action.update(attribute="description", before=before)
            change = journal.prepare(action)
            journal.mark_applied(change, {"guid": guid, "usn": "11", "values": encode_values([b"after"])})
            conn = argparse.Namespace(options=OpsecOptions(), getLdap=AsyncMock(return_value=ldap))
            async def external_state(_ldap, dn, attribute=None):
                return {"guid": guid, "usn": "99", **({"values": before} if attribute else {})}
            with patch("bloodyAD.rollback.read_state", AsyncMock(side_effect=external_state)):
                with self.assertRaises(JournalConflict):
                    await rollback.apply(conn, str(path))
            ldap.delete.assert_not_awaited()
            ldap.modify.assert_not_awaited()

    async def test_readded_membership_with_newer_sequence_conflicts(self):
        from bloodyAD.rollback import apply_action, encode_values, JournalConflict
        ldap = self.recovery_ldap()
        action = self.recovery_action("remove_member")
        member_dn = "CN=Member,DC=example,DC=com"
        action.update(member_dn=member_dn, member_guid="member", evidence={"guid": "group", "usn": "10"})
        state = {"guid": "group", "usn": "12", "values": encode_values([member_dn])}
        with patch("bloodyAD.rollback.read_state", AsyncMock(side_effect=[state, {"guid": "member", "usn": "1"}])):
            with self.assertRaises(JournalConflict):
                await apply_action(ldap, action)
        ldap.modify.assert_not_awaited()

    async def test_failed_recovery_marker_cannot_bless_sequence_on_resume(self):
        import argparse
        from bloodyAD.rollback import RollbackJournal, encode_values, JournalConflict
        from bloodyAD.cli_modules import rollback
        from bloodyAD.opsec import OpsecOptions
        from bloodyAD.operations import PartialWriteError
        ldap = self.recovery_ldap()
        from tests.test_raw_modify import raw_transport
        transport_ldap, _ = raw_transport()
        ldap._con = transport_ldap._con
        guid = "00000000-0000-0000-0000-000000000001"
        before, after = encode_values([b"before"]), encode_values([b"after"])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "journal.jsonl"
            journal = RollbackJournal(path)
            creation = journal.prepare(self.recovery_action("delete_created"))
            journal.mark_applied(creation, {"guid": guid, "usn": "10"})
            action = self.recovery_action()
            action.update(attribute="description", before=before)
            change = journal.prepare(action)
            journal.mark_applied(change, {"guid": guid, "usn": "11", "values": after})
            conn = argparse.Namespace(options=OpsecOptions(), getLdap=AsyncMock(return_value=ldap))
            states = [{"guid": guid, "usn": "11", "values": after}, {"guid": guid, "usn": "12"}]
            with patch("bloodyAD.rollback.read_state", AsyncMock(side_effect=states)):
                with patch.object(RollbackJournal, "mark_recovered", side_effect=OSError("disk")):
                    with self.assertRaises(PartialWriteError):
                        await rollback.apply(conn, str(path))
            async def resumed_state(_ldap, dn, attribute=None):
                return {"guid": guid, "usn": "12", **({"values": before} if attribute else {})}
            with patch("bloodyAD.rollback.read_state", AsyncMock(side_effect=resumed_state)):
                with self.assertRaises(JournalConflict):
                    await rollback.apply(conn, str(path))
            ldap.delete.assert_not_awaited()

    async def test_missing_ldap_base_is_absent_but_access_denial_is_not(self):
        from bloodyAD.rollback import read_state
        from badldap.commons.exceptions import LDAPSearchException
        from tests.test_write_outcomes import fake_ldap
        ldap = fake_ldap()

        async def missing(*args, **kwargs):
            raise LDAPSearchException("noSuchObject", b"not present")
            yield
        ldap.bloodysearch = missing
        self.assertIsNone(await read_state(ldap, "CN=Absent,DC=example,DC=com"))

        async def denied(*args, **kwargs):
            raise LDAPSearchException("insufficientAccessRights", b"denied")
            yield
        ldap.bloodysearch = denied
        with self.assertRaises(LDAPSearchException):
            await read_state(ldap, "CN=Denied,DC=example,DC=com")

    async def test_user_creation_records_identity_but_not_password(self):
        import argparse
        from bloodyAD.cli_modules import add
        from bloodyAD.opsec import OpsecOptions
        from bloodyAD.rollback import RollbackJournal
        from tests.test_write_outcomes import fake_ldap
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "journal.jsonl"
            ldap = fake_ldap(OpsecOptions(rollback_file=str(path)))
            ldap.domainNC = "DC=example,DC=com"
            ldap.conf = argparse.Namespace(host="dc.example.com")
            conn = argparse.Namespace(options=ldap.options, getLdap=AsyncMock(return_value=ldap))
            state = {"guid": "00000000-0000-0000-0000-000000000001", "usn": "12"}
            with patch("bloodyAD.rollback.read_state", new=AsyncMock(side_effect=[None, state])):
                await add.user(conn, "fixture", "CANARY_never_journal", "OU=Test,DC=example,DC=com")
            self.assertEqual(len(RollbackJournal(path).read_actions()), 1)
            self.assertEqual(RollbackJournal(path).read_actions()[0]["status"], "applied")
            self.assertNotIn("CANARY", path.read_text(encoding="utf-8"))

    async def test_simulated_recorded_write_never_creates_a_file(self):
        from bloodyAD.rollback import recorded_write
        from bloodyAD.opsec import OpsecOptions
        from tests.test_write_outcomes import fake_ldap
        from bloodyAD.operations import WriteOutcome
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "journal.jsonl"
            ldap = fake_ldap(OpsecOptions(dry_run=True, rollback_file=str(path)))
            send = AsyncMock(return_value=WriteOutcome("simulated", "add", "test"))
            result = await recorded_write(ldap, {}, send)
            self.assertEqual(result.status, "simulated")
            self.assertFalse(path.exists())

    async def test_journal_failure_before_send_prevents_mutation(self):
        from bloodyAD.rollback import recorded_write
        from bloodyAD.opsec import OpsecOptions
        from tests.test_write_outcomes import fake_ldap
        ldap = fake_ldap(OpsecOptions(rollback_file="unused"))
        send = AsyncMock()
        with patch("bloodyAD.rollback.RollbackJournal.prepare", side_effect=OSError("disk")):
            with self.assertRaises(OSError):
                await recorded_write(ldap, {}, send)
        send.assert_not_awaited()

    async def test_journal_failure_after_send_reports_applied_effect(self):
        from bloodyAD.rollback import recorded_write
        from bloodyAD.opsec import OpsecOptions
        from bloodyAD.operations import WriteOutcome, PartialWriteError
        from tests.test_write_outcomes import fake_ldap
        ldap = fake_ldap(OpsecOptions(rollback_file="unused"))
        send = AsyncMock(return_value=WriteOutcome("applied", "add", "test", ("add",)))
        with patch("bloodyAD.rollback.RollbackJournal.prepare", return_value="op"):
            with patch("bloodyAD.rollback.read_state", new=AsyncMock(side_effect=OSError("disk"))):
                with self.assertRaises(PartialWriteError) as error:
                    await recorded_write(ldap, {"target_dn": "test"}, send)
        self.assertEqual(error.exception.outcome.completed_steps, ("add",))

    async def test_changed_object_guid_prevents_delete(self):
        from bloodyAD.rollback import apply_action, JournalConflict
        from tests.test_write_outcomes import fake_ldap
        ldap = fake_ldap()
        ldap.domainNC = "DC=example,DC=com"
        ldap.conf = type("Config", (), {"host": "dc.example.com"})()
        record = {"kind": "delete_created", "target_dn": "CN=One,DC=example,DC=com",
                  "domain_dn": ldap.domainNC, "server": "dc.example.com",
                  "evidence": {"guid": "original", "usn": "10"}}
        with patch("bloodyAD.rollback.read_state", new=AsyncMock(return_value={"guid": "different", "usn": "10"})):
            with self.assertRaises(JournalConflict):
                await apply_action(ldap, record)
        ldap.delete.assert_not_awaited()

    async def test_recovery_uses_version_from_its_own_previous_undo(self):
        from bloodyAD.rollback import apply_action
        from tests.test_write_outcomes import fake_ldap
        ldap = fake_ldap()
        ldap.domainNC = "DC=example,DC=com"
        ldap.conf = type("Config", (), {"host": "dc.example.com"})()
        record = {"kind": "delete_created", "target_dn": "CN=One,DC=example,DC=com",
                  "domain_dn": ldap.domainNC, "server": "dc.example.com",
                  "evidence": {"guid": "original", "usn": "10"}}
        with patch("bloodyAD.rollback.read_state", new=AsyncMock(return_value={"guid": "original", "usn": "12"})):
            outcome = await apply_action(ldap, record, expected_usn="12")
        self.assertEqual(outcome.status, "applied")
