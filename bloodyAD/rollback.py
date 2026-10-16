"""Versioned recovery data. Journal records are never interpreted as shell commands."""
import base64
import ctypes
import json
import os
import uuid
from pathlib import Path

from bloodyAD.exceptions import NoResultError
from badldap.commons.exceptions import LDAPSearchException
from bloodyAD.operations import PartialWriteError, WriteOutcome
from bloodyAD.search_policy import SearchPolicy, canonical_dn

BACKUP_ATTRIBUTES = frozenset({"description", "displayname", "info", "title", "department",
                               "telephonenumber", "mail", "wwwhomepage", "physicaldeliveryofficename"})


class JournalError(ValueError):
    pass


class JournalConflict(JournalError):
    pass


def validate_attribute(attribute):
    if attribute.lower() not in BACKUP_ATTRIBUTES:
        raise JournalError("Backup is restricted to explicitly classified noncredential attributes")


def encode_values(values):
    encoded = []
    for value in values:
        if isinstance(value, bytes):
            encoded.append({"type": "bytes", "value": base64.b64encode(value).decode("ascii")})
        elif type(value) in (str, int):
            encoded.append({"type": type(value).__name__, "value": value})
        else:
            raise JournalError("Unsupported attribute value type")
    return encoded


def decode_values(values):
    result = []
    if not isinstance(values, list):
        raise JournalError("Attribute values must be a list")
    for value in values:
        if not isinstance(value, dict) or set(value) != {"type", "value"}:
            raise JournalError("Malformed attribute value")
        if value["type"] == "bytes":
            result.append(base64.b64decode(value["value"], validate=True))
        elif value["type"] == "str" and type(value["value"]) is str:
            result.append(value["value"])
        elif value["type"] == "int" and type(value["value"]) is int:
            result.append(value["value"])
        else:
            raise JournalError("Unsupported attribute value type")
    return result


def _validate_action(action):
    if not isinstance(action, dict):
        raise JournalError("Malformed recovery action")
    common = {"kind", "target_dn", "domain_dn", "server"}
    fields = {"delete_created": set(), "restore_attribute": {"attribute", "before"},
              "remove_member": {"member_dn", "member_guid"}}
    if action.get("kind") not in fields or set(action) != common | fields[action["kind"]]:
        raise JournalError("Unsupported recovery action fields")
    if not all(type(action[k]) is str and action[k] for k in common):
        raise JournalError("Recovery context is incomplete")
    SearchPolicy(action["domain_dn"]).validate_target(action["target_dn"])
    if len(canonical_dn(action["target_dn"])) <= len(canonical_dn(action["domain_dn"])):
        raise JournalError("Recovery cannot target a naming-context root")
    if action["kind"] == "restore_attribute":
        validate_attribute(action["attribute"])
        decode_values(action["before"])
    elif action["kind"] == "remove_member":
        canonical_dn(action["member_dn"])
        uuid.UUID(action["member_guid"])


def _secure_file(path):
    if os.name != "nt":
        os.chmod(path, 0o600)
        return
    from winacl.functions.highlevel import get_file_sd
    from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
    owner = str(get_file_sd(str(path)).Owner)
    descriptor = SECURITY_DESCRIPTOR.from_sddl(f"D:P(A;;FA;;;{owner})(A;;FA;;;SY)")
    dacl = descriptor.Dacl.to_bytes()
    buffer = ctypes.create_string_buffer(dacl)
    function = ctypes.windll.advapi32.SetNamedSecurityInfoW
    function.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                         ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    function.restype = ctypes.c_uint32
    error = function(str(path), 1, 0x80000004, None, None, buffer, None)
    if error:
        raise OSError(error, "Could not restrict journal permissions")


class RollbackJournal:
    def __init__(self, path):
        self.path = Path(path)
        self.run_id = str(uuid.uuid4())

    def _append(self, record):
        if self.path.is_symlink() or (hasattr(self.path, "is_junction") and self.path.is_junction()):
            raise JournalError("Journal must be a regular file")
        if self.path.exists():
            self.read_actions()
        else:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        _secure_file(self.path)
        with self.path.open("a+b") as stream:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                stream.seek(0, os.SEEK_END)
                payload = {"version": 1, "run_id": self.run_id, **record}
                stream.write((json.dumps(payload, ensure_ascii=True) + "\n").encode("utf-8"))
                stream.flush()
                os.fsync(stream.fileno())
            finally:
                stream.seek(0)
                if os.name == "nt":
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(stream, fcntl.LOCK_UN)

    def prepare(self, action):
        _validate_action(action)
        operation_id = str(uuid.uuid4())
        self._append({"status": "prepared", "operation_id": operation_id, "action": action})
        return operation_id

    def mark_applied(self, operation_id, evidence):
        self._append({"status": "applied", "operation_id": operation_id, "evidence": evidence})

    def mark_recovered(self, operation_id, evidence=None):
        self._append({"status": "recovered", "operation_id": operation_id, "recovery_evidence": evidence})

    def read_actions(self):
        if not self.path.exists():
            return []
        if self.path.stat().st_size > 16 * 1024 * 1024:
            raise JournalError("Journal exceeds the supported size")
        actions = {}
        try:
            with self.path.open("r", encoding="utf-8") as stream:
                for line in stream:
                    if not line.endswith("\n"):
                        raise JournalError("Journal ends with an incomplete record")
                    record = json.loads(line)
                    if not isinstance(record, dict) or record.get("version") != 1:
                        raise JournalError("Unsupported journal version")
                    uuid.UUID(record["run_id"])
                    operation = record["operation_id"]
                    uuid.UUID(operation)
                    status = record["status"]
                    if status == "prepared":
                        if operation in actions or set(record) != {"version", "run_id", "operation_id", "status", "action"}:
                            raise JournalError("Duplicate or malformed preparation")
                        _validate_action(record["action"])
                        actions[operation] = {**record["action"], "operation_id": operation, "status": status}
                    elif status == "applied":
                        if operation not in actions or actions[operation]["status"] != "prepared":
                            raise JournalError("Applied record has no unique preparation")
                        evidence = record["evidence"]
                        if set(record) != {"version", "run_id", "operation_id", "status", "evidence"} or not isinstance(evidence, dict):
                            raise JournalError("Malformed application evidence")
                        if not set(evidence) <= {"guid", "usn", "values"} or not {"guid", "usn"} <= set(evidence):
                            raise JournalError("Application evidence is incomplete")
                        uuid.UUID(evidence["guid"])
                        if not str(evidence["usn"]).isdigit():
                            raise JournalError("Invalid change sequence")
                        if "values" in evidence:
                            decode_values(evidence["values"])
                        actions[operation].update(status=status, evidence=evidence)
                    elif status == "recovered":
                        if operation not in actions or actions[operation]["status"] != "applied":
                            raise JournalError("Recovery record has no applied operation")
                        if set(record) != {"version", "run_id", "operation_id", "status", "recovery_evidence"}:
                            raise JournalError("Malformed recovery record")
                        recovery = record["recovery_evidence"]
                        if recovery is not None:
                            if not isinstance(recovery, dict) or set(recovery) != {"guid", "usn"}:
                                raise JournalError("Malformed recovery evidence")
                            if recovery["guid"] != actions[operation]["evidence"]["guid"] or not str(recovery["usn"]).isdigit():
                                raise JournalError("Recovery evidence does not match the target")
                        actions[operation]["recovery_evidence"] = recovery
                        actions[operation]["status"] = status
                    else:
                        raise JournalError("Unsupported record status")
        except (KeyError, TypeError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            if isinstance(error, JournalError):
                raise
            raise JournalError("Invalid or legacy journal; no recovery was executed") from error
        return list(actions.values())


def plan_rollback(actions):
    return [action for action in reversed(actions) if action["status"] == "applied"]


async def read_state(ldap, dn, attribute=None):
    attributes = ["objectGUID", "uSNChanged"] + ([attribute] if attribute else [])
    stream = ldap.bloodysearch(dn, attr=attributes, raw=True)
    entry = None
    try:
        async for entry in stream:
            break
    except NoResultError:
        return None
    except LDAPSearchException as error:
        if error.resultcode == 32:
            return None
        raise
    finally:
        await stream.aclose()
    if entry is None:
        return None
    def values(name):
        value = next((v for k, v in entry.items() if k.lower() == name.lower()), [])
        return value if isinstance(value, list) else [value]
    guids, usns = values("objectGUID"), values("uSNChanged")
    if len(guids) != 1 or len(usns) != 1:
        raise JournalError("Cannot identify target and change sequence")
    raw_guid = guids[0]
    guid = str(uuid.UUID(bytes_le=raw_guid)) if isinstance(raw_guid, bytes) else str(uuid.UUID(str(raw_guid)))
    raw_usn = usns[0]
    result = {"guid": guid, "usn": raw_usn.decode() if isinstance(raw_usn, bytes) else str(raw_usn)}
    if attribute:
        result["values"] = encode_values(values(attribute))
    return result


def action_context(ldap, kind, target_dn, **fields):
    return {"kind": kind, "target_dn": target_dn, "domain_dn": ldap.domainNC,
            "server": ldap.conf.host, **fields}


async def recorded_write(ldap, action, send, attribute=None):
    if ldap.options.dry_run or not ldap.options.rollback_file:
        return await send()
    journal = RollbackJournal(ldap.options.rollback_file)
    operation = journal.prepare(action)
    outcome = await send()
    if outcome.status == "applied":
        try:
            state = await read_state(ldap, action["target_dn"], attribute)
            if state is None:
                raise JournalError("Applied target cannot be identified")
            journal.mark_applied(operation, state)
        except Exception as error:
            raise PartialWriteError(WriteOutcome("partial", outcome.operation, outcome.target, outcome.completed_steps)) from error
    return outcome


async def create_object(ldap, target_dn, attributes, controls=None):
    async def send():
        return await ldap.bloodyadd(target_dn, attributes=attributes, controls=controls)
    if ldap.options.dry_run or not ldap.options.rollback_file:
        return await send()
    if await read_state(ldap, target_dn) is not None:
        raise JournalConflict("Journaled creation requires an absent target")
    return await recorded_write(ldap, action_context(ldap, "delete_created", target_dn), send)


async def add_member(ldap, group, member):
    group_dn = await ldap.dnResolver(group)
    member_dn = await ldap.dnResolver(member)
    async def send():
        return await ldap.bloodymodify(group_dn, {"member": [("add", [member_dn])]})
    if ldap.options.dry_run or not ldap.options.rollback_file:
        return await send()
    before = await read_state(ldap, group_dn, "member")
    identity = await read_state(ldap, member_dn)
    if before is None or identity is None:
        raise JournalConflict("Journaled membership requires identifiable local objects")
    members = [v.decode() if isinstance(v, bytes) else v for v in decode_values(before["values"])]
    if any(canonical_dn(v) == canonical_dn(member_dn) for v in members):
        return WriteOutcome("unchanged", "modify", group_dn)
    action = action_context(ldap, "remove_member", group_dn, member_dn=member_dn, member_guid=identity["guid"])
    return await recorded_write(ldap, action, send, "member")


def _same_values(left, right):
    return sorted(json.dumps(item, sort_keys=True) for item in left) == sorted(json.dumps(item, sort_keys=True) for item in right)


async def apply_action(ldap, action, *, expected_usn=None):
    if canonical_dn(ldap.domainNC) != canonical_dn(action["domain_dn"]) or ldap.conf.host.lower() != action["server"].lower():
        raise JournalConflict("Recovery context does not match the current domain and server")
    kind = action["kind"]
    attribute = action.get("attribute") if kind == "restore_attribute" else "member" if kind == "remove_member" else None
    state = await read_state(ldap, action["target_dn"], attribute)
    if state is None:
        if kind == "delete_created":
            return WriteOutcome("unchanged", "delete", action["target_dn"])
        raise JournalConflict("Recovery target no longer exists")
    if state["guid"] != action["evidence"]["guid"]:
        raise JournalConflict("Recovery target was replaced")
    if state["usn"] != (expected_usn or action["evidence"]["usn"]):
        raise JournalConflict("Recovery target changed after the recorded operation")
    if kind == "delete_created":
        return await ldap.bloodydelete(action["target_dn"])
    if kind == "restore_attribute":
        if _same_values(state["values"], action["before"]):
            return WriteOutcome("unchanged", "modify", action["target_dn"])
        if not _same_values(state["values"], action["evidence"].get("values", [])):
            raise JournalConflict("Attribute changed after the recorded operation")
        return await ldap.bloodymodify(action["target_dn"], {attribute: [("replace", decode_values(action["before"]))]}, encode=False)
    if kind == "remove_member":
        members = [v.decode() if isinstance(v, bytes) else v for v in decode_values(state["values"])]
        if not any(canonical_dn(m) == canonical_dn(action["member_dn"]) for m in members):
            return WriteOutcome("unchanged", "modify", action["target_dn"])
        member = await read_state(ldap, action["member_dn"])
        if member is None or member["guid"] != action["member_guid"]:
            raise JournalConflict("Recorded group member was replaced")
        return await ldap.bloodymodify(action["target_dn"], {"member": [("delete", [action["member_dn"]])]})
    raise JournalError("Unsupported recovery action")
