"""Opt-in, read-only comparisons against the configured VirtualBox DC."""
import asyncio
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from bloodyAD.cli_modules import get
from bloodyAD.enumeration import QUERIES, format_policy_value
from bloodyAD.network.ldap import Scope
from bloodyAD.opsec import OpsecOptions
from bloodyAD.search_policy import ScopeViolationError
from tests.support import LabConfig, lab_cli, probe_lab


def normalized(entries):
    result = {}
    for entry in entries:
        attrs = {key.casefold(): sorted(str(v) for v in (value if isinstance(value, list) else [value]))
                 for key, value in entry.items()}
        dn = attrs.pop("distinguishedname")[0].casefold()
        if dn in result:
            raise AssertionError("Duplicate DN in enumeration")
        result[dn] = attrs
    return result


@unittest.skipUnless(os.getenv("BLOODYAD_LAB_TESTS") == "1", "Lab tests are opt-in")
class EnumerationLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = LabConfig.from_environment()
        cls.capabilities = asyncio.run(probe_lab(cls.config))

    def reference(self, name, ldap_filter=None):
        shell = shutil.which("powershell") or shutil.which("pwsh")
        if os.name != "nt" or not shell:
            self.skipTest("Independent signed LDAP reference requires Windows PowerShell")
        scope, query_filter, attributes = QUERIES[name]
        environment = os.environ.copy()
        environment.update(BLOODYAD_LAB_IP=self.config.ip, BLOODYAD_LAB_DOMAIN=self.config.domain,
                           BLOODYAD_LAB_USER=self.config.username, BLOODYAD_LAB_PASSWORD=self.config.password)
        completed = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-File", str(Path(__file__).with_name("ldap_enumeration_reference.ps1")),
             "-Base", self.capabilities.domain_dn, "-Filter", ldap_filter or query_filter,
             "-Attributes", ",".join(attributes), "-Scope", "Base" if scope == Scope.BASE else "Subtree"],
            env=environment, capture_output=True, text=True, timeout=90,
        )
        self.assertEqual(completed.returncode, 0, "Independent LDAP query failed; output omitted")
        return json.loads(completed.stdout)

    def command(self, name, *, raw=True, **kwargs):
        async def collect():
            conn = self.config.connection()
            try:
                return [entry async for entry in getattr(get, name)(conn, raw=raw, **kwargs)]
            finally:
                await conn.closeLdap()
        return asyncio.run(collect())

    def test_raw_commands_match_independent_signed_ldap(self):
        for name in QUERIES:
            with self.subTest(command=name):
                self.assertTrue(normalized(self.command(name)) == normalized(self.reference(name)),
                                "Command differs from independent LDAP; directory data omitted")

    def test_spn_class_matches_independent_signed_ldap(self):
        self.assertTrue(normalized(self.command("spn", spn_class="HOST")) ==
                        normalized(self.reference("spn", "(servicePrincipalName=HOST/*)")),
                        "SPN class differs from independent LDAP; directory data omitted")

    def test_readable_policy_matches_raw_reference(self):
        raw = self.reference("password_policy")
        expected = [{key: [format_policy_value(key, v) for v in values] for key, values in entry.items()}
                    for entry in raw]
        self.assertTrue(normalized(self.command("password_policy", raw=False)) == normalized(expected),
                        "Policy annotations differ; directory data omitted")

    def test_cli_all_commands_json_raw_and_policy_text(self):
        for name in QUERIES:
            with self.subTest(command=name):
                cli_name = name.replace("_", "-")
                output = lab_cli(self.config, ["--json", "get", cli_name, "--raw"], timeout=60)
                self.assertTrue(normalized(json.loads(output.stdout)) == normalized(self.reference(name)),
                                "CLI differs from independent LDAP; directory data omitted")
        output = lab_cli(self.config, ["get", "password-policy"], timeout=60)
        self.assertIn("minPwdLength", output.stdout)
        self.assertIn("pwdProperties", output.stdout)
        self.assertFalse(self.config.password in output.stderr, "Credential appeared in diagnostics")

    def test_empty_spn_class_is_valid_empty_json(self):
        output = lab_cli(self.config, ["--json", "get", "spn", "--spn-class", "BloodyADNoSuchServiceClass20261104"], timeout=60)
        self.assertEqual(json.loads(output.stdout), [])

    def test_installed_console_outside_source_tree(self):
        console = Path(sys.executable).with_name("bloodyad-opsec.exe" if os.name == "nt" else "bloodyad-opsec")
        if not console.is_file():
            self.skipTest("Installed console is not available beside the test interpreter")
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment["BLOODYAD_PASSWORD"] = self.config.password
        temporary_root = Path(__file__).parent / "tmp"
        temporary_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=temporary_root) as directory:
            for name in QUERIES:
                with self.subTest(command=name):
                    completed = subprocess.run(
                        [str(console), *self.config.arguments(), "--json", "get", name.replace("_", "-"), "--raw"],
                        env=environment, cwd=directory, capture_output=True, text=True, timeout=60,
                    )
                    self.assertEqual(completed.returncode, 0, "Installed console failed; output omitted")
                    self.assertTrue(normalized(json.loads(completed.stdout)) == normalized(self.reference(name)),
                                    "Installed console differs from independent LDAP; directory data omitted")
                    # Account names or descriptions can legitimately equal the password in a lab.
                    self.assertFalse(self.config.password in completed.stderr, "Credential appeared in diagnostics")

    def test_domain_policy_rejects_ou_scope(self):
        async def check():
            conn = self.config.connection(options=OpsecOptions(base_dn="OU=Domain Controllers," + self.capabilities.domain_dn))
            try:
                with self.assertRaises(ScopeViolationError):
                    await anext(get.password_policy(conn))
            finally:
                await conn.closeLdap()
        asyncio.run(check())

    def test_enumeration_respects_ou_scope(self):
        async def check():
            base = "OU=Domain Controllers," + self.capabilities.domain_dn
            conn = self.config.connection(options=OpsecOptions(base_dn=base))
            try:
                entries = [entry async for entry in get.spn(conn, raw=True)]
                self.assertTrue(entries, "Expected DC SPNs in the Domain Controllers OU")
                self.assertTrue(all(entry["distinguishedName"].casefold().endswith("," + base.casefold()) for entry in entries))
            finally:
                await conn.closeLdap()
        asyncio.run(check())
