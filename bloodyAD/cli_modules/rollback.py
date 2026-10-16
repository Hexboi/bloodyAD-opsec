import asyncio

from bloodyAD import rollback as _rollback


async def inspect(conn, path: str):
    """
    Inspect a structured recovery journal without changing AD

    :param path: path to a version 1 JSONL recovery journal
    """
    return _rollback.RollbackJournal(path).read_actions()


async def apply(conn, path: str):
    """
    Apply confirmed recovery actions in reverse order with conflict checks

    :param path: path to a version 1 JSONL recovery journal
    """
    journal = _rollback.RollbackJournal(path)
    actions = journal.read_actions()
    if any(a["status"] == "prepared" for a in actions):
        raise _rollback.JournalError("Unconfirmed operations require read-only reconciliation before recovery")
    ldap = await conn.getLdap()
    outcomes = []
    versions = {}
    for previous in actions:
        evidence = previous.get("recovery_evidence")
        if evidence:
            guid = evidence["guid"]
            versions[guid] = str(max(int(versions.get(guid, "0")), int(evidence["usn"])))
    completed = []
    for action in _rollback.plan_rollback(actions):
        try:
            outcome = await _rollback.apply_action(ldap, action, expected_usn=versions.get(action["evidence"]["guid"]))
            if outcome.status == "applied":
                completed.append("recovery:" + action["operation_id"])
            if outcome.status in ("applied", "unchanged"):
                if outcome.status == "applied":
                    state = await _rollback.read_state(ldap, action["target_dn"])
                elif action["kind"] == "delete_created":
                    state = None
                else:
                    state = {"guid": action["evidence"]["guid"],
                             "usn": versions.get(action["evidence"]["guid"], action["evidence"]["usn"])}
                journal.mark_recovered(action["operation_id"], state)
                if state:
                    versions[state["guid"]] = state["usn"]
            outcomes.append({"operation_id": action["operation_id"], "status": outcome.status})
        except (Exception, asyncio.CancelledError) as error:
            from bloodyAD.operations import PartialWriteError, WriteOutcome
            steps = tuple(completed)
            if isinstance(error, PartialWriteError):
                steps += error.outcome.completed_steps
            if steps:
                raise PartialWriteError(WriteOutcome("partial", "recovery", action["target_dn"], steps)) from error
            raise
    return outcomes


from bloodyAD import capabilities as _capabilities
_capabilities.guard_module(globals(), "rollback")
