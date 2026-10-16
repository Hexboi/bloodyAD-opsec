"""Explicit installed-wheel CLI end-to-end checks; never imported by discovery."""
import argparse
import asyncio
import base64
import datetime
import hashlib
import json
import os
import re
import secrets
import subprocess
import tempfile
import time
import unittest
import uuid
import zipfile
from dataclasses import replace
from pathlib import Path

from badldap.commons.exceptions import LDAPSearchException
from tests.fixtures import LabFixture
from tests.support import LabConfig, ROOT

BASIC_WRITES = {("add", n) for n in ("user", "computer", "groupMember")}
BASIC_WRITES |= {("set", "object"), ("set", "password"), ("remove", "object"), ("remove", "groupMember")}
EVENTS = []
FIXTURE_BASES = []
PACKAGE = {}
INVENTORY = []

async def oracle(ldap, base, strict=False):
    """Query the dependency transport directly, not the fork's read/format wrappers."""
    attributes = ["objectGUID", "description", "member", "sAMAccountName", "title"]
    if strict:
        attributes += ["uSNChanged", "pwdLastSet"]
    stream = ldap.pagedsearch("(objectClass=*)", attributes, tree=base, search_scope=2, raw=True)
    result = {}
    try:
        async for entry, error in stream:
            if error:
                if isinstance(error, LDAPSearchException) and error.resultcode == 32:
                    return {}
                raise error
            result[entry["objectName"].lower()] = {
                name.lower(): sorted(value if isinstance(value, list) else [value], key=repr)
                for name, value in entry["attributes"].items()
            }
    finally:
        await stream.aclose()
    return result

class InstalledCliTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.config = LabConfig.from_environment()
        self.fixture = LabFixture(self.config)
        self.addAsyncCleanup(self.fixture.close)
        await asyncio.wait_for(self.fixture.start(), 25)
        FIXTURE_BASES.append(self.fixture.base)
        self.folder = tempfile.TemporaryDirectory(prefix="bloodyad-e2e-")
        self.addCleanup(self.folder.cleanup)
        self.work = Path(self.folder.name)
        self.secrets = [self.config.password]
        self.console = Path(os.environ["BLOODYAD_E2E_CONSOLE"]).resolve()
        self.assertTrue(self.console.is_file(), "Installed console executable missing")

    def _callTestMethod(self, method):
        self._callAsync(self._bounded, method)

    async def _bounded(self, method):
        await asyncio.wait_for(method(), 600)

    def password(self):
        value = secrets.token_urlsafe(24) + "!Aa7"
        self.secrets.append(value)
        return value

    async def call(self, args, *, expected=0, config=None, global_args=(), stage=None):
        config = config or self.config
        environment = os.environ.copy()
        environment["BLOODYAD_PASSWORD"] = config.password
        environment.pop("PYTHONPATH", None)
        environment.pop("PYTHONHOME", None)
        command = [str(self.console), *config.arguments(), *global_args, *args]
        started = time.monotonic()
        try:
            result = await asyncio.to_thread(
                subprocess.run, command, cwd=self.work, env=environment,
                shell=False, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=25,
            )
        except subprocess.TimeoutExpired:
            EVENTS.append({"test": self._testMethodName, "stage": stage or " ".join(args[:2]),
                           "returncode": 124, "seconds": round(time.monotonic() - started, 3)})
            raise AssertionError("Installed CLI timed out; command and output omitted") from None
        EVENTS.append({"test": self._testMethodName, "stage": stage or " ".join(args[:2]),
                       "returncode": result.returncode, "seconds": round(time.monotonic() - started, 3),
                       "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
                       "stderr_sha256": hashlib.sha256(result.stderr.encode()).hexdigest()})
        for secret in self.secrets + [config.password]:
            self.assertFalse(secret and secret in result.stdout + result.stderr,
                             "Credential canary leaked in CLI output")
        if expected is None:
            self.assertNotEqual(result.returncode, 0, "Expected an explicit failure")
        else:
            self.assertEqual(result.returncode, expected,
                             "Unexpected CLI exit code; output omitted, see stage in sanitized report")
        return result

    def parsed(self, result):
        try:
            return json.loads(result.stdout)
        except (ValueError, TypeError):
            raise AssertionError("CLI did not return valid JSON; output omitted") from None

    async def read(self, target, attributes="distinguishedName,description,member,sAMAccountName", **kwargs):
        return self.parsed(await self.call(["get", "object", target, "--attr", attributes],
                                          global_args=["--json"], **kwargs))

    async def create_user(self, name, password, journal=None):
        target = "CN=" + name + "," + self.fixture.base
        self.assertFalse(await oracle(self.fixture.ldap, target), "Creation target already exists")
        self.fixture.expect(target)
        options = ["--json"]
        if journal:
            options += ["--rollback-file", str(journal)]
        try:
            result = await self.call(["add", "user", name, password, "--ou", self.fixture.base],
                                     global_args=options)
        finally:
            if await oracle(self.fixture.ldap, target):
                await self.fixture.identify(target)
        self.assertEqual(self.parsed(result)["status"], "applied")
        return target

    async def inspect(self, path):
        return self.parsed(await self.call(["rollback", "inspect", str(path)], global_args=["--json"]))

    async def recover(self, path, **kwargs):
        return await self.call(["rollback", "apply", str(path)], global_args=["--json"], **kwargs)

    async def test_01_installed_identity_and_every_command_help(self):
        self.assertIn("site-packages", PACKAGE["file"].lower())
        self.assertNotIn("Scripts/bloodyAD-opsec/bloodyAD", PACKAGE["file"].replace("\\", "/"))
        self.assertGreater(len(INVENTORY), 100)
        async def check(item):
            await self.call([item["category"], item["name"], "--help"], stage="help:" + item["category"] + "." + item["name"])
        for offset in range(0, len(INVENTORY), 4):
            batch = INVENTORY[offset:offset + 4]
            await asyncio.gather(*(check(item) for item in batch))
            if (offset + len(batch)) % 20 == 0 or offset + len(batch) == len(INVENTORY):
                print("CLI help verified:", offset + len(batch), flush=True)

    async def test_02_unsupported_options_and_invalid_inputs_are_rejected(self):
        before = await oracle(self.fixture.ldap, self.fixture.base, strict=True)
        refused = [item for item in INVENTORY if (item["category"], item["name"]) not in BASIC_WRITES]
        async def check(item):
            result = await self.call([item["category"], item["name"], *item["required"]],
                                     global_args=["--dry-run"], expected=2,
                                     stage="deny-dry-run:" + item["category"] + "." + item["name"])
            self.assertIn("does not support --dry-run", result.stderr)
        for offset in range(0, len(refused), 4):
            batch = refused[offset:offset + 4]
            await asyncio.gather(*(check(item) for item in batch))
            if (offset + len(batch)) % 20 == 0 or offset + len(batch) == len(refused):
                print("CLI option refusals verified:", offset + len(batch), flush=True)
        cases = [
            ["--chunk", "1"], ["--sleep", "-1"], ["--sleep", "nan"],
            ["--sleep", "inf"], ["--jitter", "1.1"], ["--base-dn", ""],
        ]
        for options in cases:
            await self.call(["get", "object", self.fixture.user], global_args=options, expected=2)
        for args, options in [
            (["get", "bloodhound"], ["--base-dn", self.fixture.base]),
            (["get", "writable", "--bh"], ["--no-tombstone"]),
            (["msldap", "whoami"], ["--sleep", "1"]),
            (["set", "object", self.fixture.user, "unicodePwd", "--bak"], ["--rollback-file", str(self.work / "secret.jsonl")]),
            (["set", "object", self.fixture.user, "description", "--bak"], []),
            (["remove", "object", self.fixture.user], ["--base-dn", self.fixture.base]),
        ]:
            await self.call(args, global_args=options, expected=2)
        self.assertEqual(before, await oracle(self.fixture.ldap, self.fixture.base, strict=True))

    async def test_03_read_authentication_transports_and_diagnostics(self):
        for options in ([], ["-k", "kdc=" + self.config.ip], ["-s"], ["--gc"]):
            result = await self.call(["get", "object", self.fixture.user, "--attr", "distinguishedName"],
                                     global_args=["--json", *options])
            self.assertEqual(self.parsed(result)[0]["distinguishedName"].lower(), self.fixture.user.lower())
        for level in ("QUIET", "INFO", "DEBUG", "TRACE"):
            result = await self.call(["get", "object", self.fixture.user, "--attr", "distinguishedName"],
                                     global_args=["--json", "-v", level])
            self.assertEqual(len(self.parsed(result)), 1)

    async def test_04_every_supported_dry_run_has_no_ad_effect_or_journal(self):
        before = await oracle(self.fixture.ldap, self.fixture.base, strict=True)
        password = self.password()
        path = self.work / "dry.jsonl"
        commands = [
            ["add", "user", "baeud" + self.fixture.short, password, "--ou", self.fixture.base],
            ["add", "computer", "baecd" + self.fixture.short, password, "--ou", self.fixture.base],
            ["set", "object", self.fixture.user, "description", "-v", "must-not-apply"],
            ["set", "password", self.fixture.user, password],
            ["add", "groupMember", self.fixture.group, self.fixture.user],
            ["remove", "groupMember", self.fixture.group, self.fixture.user],
            ["remove", "object", self.fixture.user],
        ]
        for command in commands:
            result = await self.call(command, global_args=["--json", "--dry-run"])
            self.assertEqual(self.parsed(result)["status"], "simulated")
        result = await self.call(commands[0], global_args=["--json", "--dry-run", "--rollback-file", str(path)])
        self.assertEqual(self.parsed(result)["status"], "simulated")
        self.assertFalse(path.exists())
        self.assertEqual(before, await oracle(self.fixture.ldap, self.fixture.base, strict=True))

    async def test_05_full_journal_cycle_and_idempotent_replay(self):
        baseline = await oracle(self.fixture.ldap, self.fixture.base)
        password = self.password()
        path = self.work / "journal with spaces.jsonl"
        user = await self.create_user("baeju" + self.fixture.short, password, path)
        name = "baejc" + self.fixture.short
        pc = "CN=" + name + "," + self.fixture.base
        self.fixture.expect(pc)
        try:
            result = await self.call(["add", "computer", name, password, "--ou", self.fixture.base],
                                     global_args=["--json", "--rollback-file", str(path)])
        finally:
            if await oracle(self.fixture.ldap, pc):
                await self.fixture.identify(pc)
        self.assertEqual(self.parsed(result)["status"], "applied")
        await self.call(["add", "groupMember", self.fixture.group, user],
                        global_args=["--json", "--rollback-file", str(path)])
        await self.call(["set", "object", user, "description", "-v", "recorded", "--bak"],
                        global_args=["--json", "--rollback-file", str(path)])
        actions = await self.inspect(path)
        self.assertEqual(len(actions), 4)
        self.assertTrue(all(action["status"] == "applied" for action in actions))
        self.assertFalse(password in path.read_text(encoding="utf-8"), "Credential leaked in journal")
        self.assertEqual(len(self.parsed(await self.recover(path))), 4)
        await self.recover(path)
        self.assertTrue(all(action["status"] == "recovered" for action in await self.inspect(path)))
        self.assertEqual(baseline, await oracle(self.fixture.ldap, self.fixture.base))

    async def test_06_real_password_membership_and_removal(self):
        name = "baerw" + self.fixture.short
        original, changed = self.password(), self.password()
        user = await self.create_user(name, original)
        await self.call(["add", "groupMember", self.fixture.group, user], global_args=["--json"])
        memberships = self.parsed(await self.call(["get", "membership", user, "--no-recurse"], global_args=["--json"]))
        self.assertTrue(any(row.get("sAMAccountName") for row in memberships))
        await self.call(["remove", "groupMember", self.fixture.group, user], global_args=["--json"])
        state = await oracle(self.fixture.ldap, self.fixture.group)
        self.assertNotIn(user.encode(), state[self.fixture.group.lower()].get("member", []))
        await self.call(["set", "password", user, changed], global_args=["--json"])
        config = replace(self.config, username=name, password=changed)
        await self.read(user, config=config)
        from Cryptodome.Hash import MD4
        digest = MD4.new(changed.encode("utf-16-le")).hexdigest()
        self.secrets.append(digest)
        await self.read(user, config=replace(config, password=":" + digest))
        await self.call(["remove", "object", user], global_args=["--json"])
        self.assertFalse(await oracle(self.fixture.ldap, user))

    async def test_07_scope_point_subtree_siblings_and_escaped_names(self):
        inside, outside = "OU=Inside," + self.fixture.base, "OU=Outside," + self.fixture.base
        for target, name in ((inside, "Inside"), (outside, "Outside")):
            await self.fixture.create(target, {"objectClass": ["top", "organizationalUnit"], "ou": name})
        escaped = r"CN=Doe\, Alice," + inside
        await self.fixture.create(escaped, {"objectClass": ["top", "person", "organizationalPerson", "user"],
                                            "sAMAccountName": "baees" + self.fixture.short, "userAccountControl": 514})
        scoped = ["--json", "--base-dn", inside]
        rows = self.parsed(await self.call(["get", "object", escaped, "--attr", "distinguishedName"], global_args=scoped))
        self.assertEqual(rows[0]["distinguishedName"].lower(), escaped.lower())
        rows = self.parsed(await self.call(["get", "search", "--base", self.fixture.ldap.domainNC,
                                            "--attr", "distinguishedName"], global_args=scoped))
        self.assertEqual(len(rows), 2)
        rows = self.parsed(await self.call(["get", "children", "--target", inside, "--direct"], global_args=scoped))
        self.assertEqual(len(rows), 1)
        for target in (outside, self.fixture.ldap.domainNC):
            await self.call(["get", "object", target], global_args=scoped, expected=1)
        await self.call(["get", "children", "--target", self.fixture.ldap.domainNC, "--direct"], global_args=scoped, expected=1)
        await self.call(["get", "object", "baees" + self.fixture.short, "--attr", "distinguishedName"], global_args=scoped)

    async def test_08_attribute_quotes_unicode_and_raw_base64_backup(self):
        path = self.work / "attribute backup.jsonl"
        baseline = await oracle(self.fixture.ldap, self.fixture.base)
        words = ["O'Brien \u03b1", "line with spaces"]
        encoded = [base64.b64encode(value.encode()).decode() for value in words]
        args = ["set", "object", self.fixture.base, "description", "--raw", "--b64", "--bak"]
        for value in encoded:
            args += ["-v", value]
        await self.call(args, global_args=["--json", "--rollback-file", str(path)])
        state = await oracle(self.fixture.ldap, self.fixture.base)
        self.assertEqual(state[self.fixture.base.lower()]["description"], sorted([value.encode() for value in words], key=repr))
        await self.recover(path)
        self.assertEqual(baseline, await oracle(self.fixture.ldap, self.fixture.base))

    async def test_09_external_changes_block_recovery(self):
        path = self.work / "conflict.jsonl"
        name = "baexc" + self.fixture.short
        user = await self.create_user(name, self.password(), path)
        await self.call(["set", "object", user, "description", "-v", "recorded", "--bak"],
                        global_args=["--json", "--rollback-file", str(path)])
        _, error = await self.fixture.ldap.modify(user, {"description": [("replace", [])],
                                                        "title": [("replace", ["external"])]})
        if error:
            raise error
        await self.recover(path, expected=1)
        self.assertTrue(await oracle(self.fixture.ldap, user))
        members = self.work / "member conflict.jsonl"
        await self.call(["add", "groupMember", self.fixture.group, user],
                        global_args=["--json", "--rollback-file", str(members)])
        for change in ("delete", "add"):
            _, error = await self.fixture.ldap.modify(self.fixture.group, {"member": [(change, [user])]})
            if error:
                raise error
        await self.recover(members, expected=1)
        state = await oracle(self.fixture.ldap, self.fixture.group)
        self.assertIn(user.encode(), state[self.fixture.group.lower()]["member"])

    async def test_10_denied_write_and_pending_journal(self):
        name, password = "baelp" + self.fixture.short, self.password()
        await self.create_user(name, password)
        config = replace(self.config, username=name, password=password)
        path = self.work / "denied.jsonl"
        before = await oracle(self.fixture.ldap, self.fixture.group, strict=True)
        await self.call(["set", "object", self.fixture.group, "description", "-v", "denied", "--bak"],
                        global_args=["--json", "--rollback-file", str(path)], config=config, expected=1)
        self.assertEqual(before, await oracle(self.fixture.ldap, self.fixture.group, strict=True))
        actions = await self.inspect(path)
        self.assertEqual([action["status"] for action in actions], ["prepared"])
        await self.recover(path, expected=1)
        # One failed authentication attempt against only our temporary account.
        invalid = replace(config, password=self.password())
        await self.call(["get", "object", self.fixture.user], config=invalid, expected=1)

    async def test_11_partial_recovery_reports_completed_actions(self):
        path = self.work / "partial.jsonl"
        for target in (self.fixture.user, self.fixture.group):
            await self.call(["set", "object", target, "description", "-v", "recorded", "--bak"],
                            global_args=["--json", "--rollback-file", str(path)])
        _, error = await self.fixture.ldap.modify(self.fixture.user, {"description": [("replace", ["external"])]})
        if error:
            raise error
        result = await self.recover(path, expected=1)
        self.assertIn("Partially applied recovery", result.stderr)
        self.assertIn("recovery:", result.stderr)
        actions = await self.inspect(path)
        self.assertEqual([action["status"] for action in actions], ["applied", "recovered"])
        state = await oracle(self.fixture.ldap, self.fixture.user)
        self.assertEqual(state[self.fixture.user.lower()]["description"], [b"external"])

    async def test_12_replaced_object_guid_blocks_deletion(self):
        name, password = "baerp" + self.fixture.short, self.password()
        path = self.work / "replacement.jsonl"
        user = await self.create_user(name, password, path)
        original = await oracle(self.fixture.ldap, user)
        await self.call(["remove", "object", user], global_args=["--json"])
        await self.create_user(name, self.password())
        replacement = await oracle(self.fixture.ldap, user)
        self.assertNotEqual(original[user.lower()]["objectguid"], replacement[user.lower()]["objectguid"])
        await self.recover(path, expected=1)
        self.assertEqual(replacement, await oracle(self.fixture.ldap, user))

    async def test_13_certificate_authentication(self):
        certificate = os.getenv("BLOODYAD_LAB_CERTIFICATE")
        if not certificate:
            self.skipTest("No issued lab certificate provided; no automatic enrollment")
        await self.call(["get", "object", self.fixture.user, "--attr", "distinguishedName"],
                        global_args=["--json", "-c", certificate])

    async def test_14_preexisting_multivalue_description_is_fully_recovered(self):
        from badldap.protocol.messages import Change, PartialAttribute, ModifyRequest, protocolOp
        original = [b"original one", "O'Brien \u03b1".encode()]
        change = Change({"operation": "replace", "modification": PartialAttribute({
            "type": b"description", "attributes": original,
        })})
        message = {"protocolOp": protocolOp({"modifyRequest": ModifyRequest({
            "object": self.fixture.base.encode(), "changes": [change],
        })})}
        connection = self.fixture.ldap._con
        message_id = await connection.send_message(message)
        responses = await connection.recv_message(message_id)
        self.assertEqual(responses[0].native["protocolOp"]["resultCode"], "success")
        baseline = await oracle(self.fixture.ldap, self.fixture.base)
        self.assertCountEqual(baseline[self.fixture.base.lower()]["description"], original)
        path = self.work / "preexisting multivalue.jsonl"
        await self.call(["set", "object", self.fixture.base, "description", "-v", "recorded", "--bak"],
                        global_args=["--json", "--rollback-file", str(path)])
        await self.recover(path)
        self.assertEqual(baseline, await oracle(self.fixture.ldap, self.fixture.base))

def verify_wheel_files(wheel, installed_files):
    with zipfile.ZipFile(wheel) as archive:
        expected = {name: hashlib.sha256(archive.read(name)).hexdigest() for name in archive.namelist()
                    if (name.startswith("bloodyAD/") and name.endswith(".py"))
                    or (".dist-info/" in name and name.rsplit("/", 1)[-1] in {"METADATA", "WHEEL", "entry_points.txt"})}
    if not expected or expected != installed_files:
        raise ValueError("Installed runtime/metadata files do not match the supplied wheel")
    return len(expected)


def installed_metadata(python):
    program = """
import importlib,importlib.metadata,inspect,json,pkgutil,sys,bloodyAD,hashlib
from pathlib import Path
from bloodyAD import cli_modules
commands=[]
for item in pkgutil.iter_modules(cli_modules.__path__):
    module=importlib.import_module('bloodyAD.cli_modules.'+item.name)
    for name,function in inspect.getmembers(module,inspect.isfunction):
        required=[]
        for parameter in inspect.signature(function).parameters.values():
            if parameter.name=='conn' or parameter.default is not inspect.Parameter.empty:
                continue
            required.append('0' if parameter.annotation in (int,float) else '__E2E_REFUSED__')
        commands.append({'category':item.name,'name':name,'required':required})
distribution=importlib.metadata.distribution('bloodyad-opsec')
root=Path(bloodyAD.__file__).parent
files={str(path.relative_to(root.parent)).replace('\\\\','/'):hashlib.sha256(path.read_bytes()).hexdigest()
       for path in root.rglob('*.py')}
for entry in distribution.files:
    name=str(entry).replace('\\\\','/')
    if '.dist-info/' in name and name.rsplit('/',1)[-1] in {'METADATA','WHEEL','entry_points.txt'}:
        files[name]=hashlib.sha256(Path(distribution.locate_file(entry)).read_bytes()).hexdigest()
print(json.dumps({'python':sys.version.split()[0],'file':bloodyAD.__file__,
                  'version':distribution.version,'commands':commands,
                  'installed_files':files,
                  'dependencies':dict((d.metadata['Name'],d.version) for d in importlib.metadata.distributions())}))
"""
    result = subprocess.run([str(python), "-I", "-c", program], capture_output=True, text=True,
                            cwd=tempfile.gettempdir(), timeout=20, check=True)
    return json.loads(result.stdout)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--console", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--case", action="append", choices=unittest.defaultTestLoader.getTestCaseNames(InstalledCliTests))
    parser.add_argument("--source-revision", help="Verified source SHA supplied by a cross-OS launcher when Git paths differ")
    args = parser.parse_args()
    snapshot = os.getenv("BLOODYAD_LAB_SNAPSHOT")
    if not snapshot:
        parser.error("BLOODYAD_LAB_SNAPSHOT is required")
    uuid.UUID(snapshot)
    config = LabConfig.from_environment()
    console = args.console.resolve()
    python = console.parent / ("python.exe" if os.name == "nt" else "python")
    global PACKAGE, INVENTORY
    PACKAGE = installed_metadata(python)
    PACKAGE["verified_wheel_files"] = verify_wheel_files(args.wheel, PACKAGE["installed_files"])
    INVENTORY = PACKAGE.pop("commands")
    revision = args.source_revision
    if revision is None:
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if not re.fullmatch("[0-9a-f]{40}", revision):
        parser.error("Source revision must be a full verified Git SHA")
    os.environ["BLOODYAD_E2E_CONSOLE"] = str(console)
    suite = (unittest.TestSuite(InstalledCliTests(name) for name in args.case) if args.case
             else unittest.defaultTestLoader.loadTestsFromTestCase(InstalledCliTests))
    # Continue independent cases to obtain a complete validation result; every fixture has cleanup.
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_revision": revision, "revision_origin": "launcher" if args.source_revision else "git",
        "wheel_sha256": hashlib.sha256(args.wheel.read_bytes()).hexdigest(),
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "selection": args.case or "all",
        "installed_package": PACKAGE, "command_inventory": INVENTORY,
        "snapshot": snapshot, "host": config.host, "ip": config.ip,
        "tests_run": result.testsRun, "successful": result.wasSuccessful(),
        "failures": [test.id() for test, detail in result.failures],
        "errors": [test.id() for test, detail in result.errors],
        "skips": [{"test": test.id(), "reason": reason} for test, reason in result.skipped],
        "fixture_bases": FIXTURE_BASES, "commands": EVENTS,
    }
    destination = ROOT / "tests" / "reports"
    destination.mkdir(exist_ok=True)
    name = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S") + "-e2e-py" + PACKAGE["python"] + ".json"
    (destination / name).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("Sanitized E2E report:", destination / name)
    raise SystemExit(not result.wasSuccessful())

if __name__ == "__main__":
    main()
