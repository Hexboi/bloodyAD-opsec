"""Offline contracts for the native read-only enumeration commands."""
import argparse
import asyncio
import contextlib
import io
import json
import os
import sys
import unittest
from unittest.mock import AsyncMock, patch

from bloodyAD.cli_modules import get
from bloodyAD.network.ldap import Scope
from bloodyAD.opsec import OpsecOptions
from bloodyAD.exceptions import NoResultError
from bloodyAD.main import amain


class FakeLdap:
    domainNC = "DC=example,DC=test"

    def __init__(self, entries=None, error=None):
        self.entries = entries if entries is not None else [{"distinguishedName": self.domainNC}]
        self.calls = []
        self.error = error

    async def bloodysearch(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.error:
            raise self.error
        for entry in self.entries:
            yield dict(entry)


def connection(ldap=None, options=None):
    return argparse.Namespace(getLdap=AsyncMock(return_value=ldap or FakeLdap()),
                              closeLdap=AsyncMock(), options=options or OpsecOptions())


class EnumerationTests(unittest.IsolatedAsyncioTestCase):
    async def test_queries_have_exact_filters_scope_and_attributes(self):
        contracts = [
            ("password_policy", Scope.BASE, "(objectClass=domainDNS)",
             "distinguishedName,minPwdLength,pwdHistoryLength,minPwdAge,maxPwdAge,pwdProperties,lockoutThreshold,lockoutDuration,lockOutObservationWindow,forceLogoff"),
            ("domain_level", Scope.BASE, "(objectClass=*)", "msDS-Behavior-Version"),
            ("maq", Scope.BASE, "(objectClass=*)", "ms-DS-MachineAccountQuota"),
            ("users_description", Scope.SUBTREE, "(sAMAccountType=805306368)", "distinguishedName,sAMAccountName,description"),
            ("asrep", Scope.SUBTREE, "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))", "sAMAccountName,userAccountControl"),
            ("spn", Scope.SUBTREE, "(servicePrincipalName=*)", "sAMAccountName,servicePrincipalName,objectClass,userAccountControl,adminCount"),
            ("kerberoastable", Scope.SUBTREE, "(&(samAccountType=805306368)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "sAMAccountName,servicePrincipalName,objectClass,userAccountControl,adminCount,msDS-SupportedEncryptionTypes"),
        ]
        for name, scope, ldap_filter, attributes in contracts:
            with self.subTest(name=name):
                ldap = FakeLdap()
                result = [e async for e in getattr(get, name)(connection(ldap))]
                self.assertEqual(len(result), 1)
                args, kwargs = ldap.calls[0]
                self.assertEqual(args, (ldap.domainNC, ldap_filter))
                self.assertEqual(kwargs["search_scope"], scope)
                self.assertEqual(kwargs["attr"], attributes.split(","))
                self.assertEqual(kwargs["raw"], name == "password_policy")
                self.assertEqual(kwargs["control_flag"], 0)

    async def test_enumeration_explicit_base_and_raw(self):
        for name in ("users_description", "asrep", "spn", "kerberoastable"):
            ldap = FakeLdap()
            base = "OU=Assessment," + ldap.domainNC
            await anext(getattr(get, name)(connection(ldap), base=base, raw=True))
            self.assertEqual(ldap.calls[0][0][0], base)
            self.assertTrue(ldap.calls[0][1]["raw"])

    async def test_spn_service_class_and_invalid_input_before_connection(self):
        ldap = FakeLdap()
        await anext(get.spn(connection(ldap), spn_class="MSSQLSvc"))
        self.assertEqual(ldap.calls[0][0][1], "(servicePrincipalName=MSSQLSvc/*)")
        for value in ("*", "HTTP/host", "x)(objectClass=*)", "x\\00", "a\x00", " "):
            conn = connection()
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                await anext(get.spn(conn, spn_class=value))
            conn.getLdap.assert_not_awaited()

    async def test_empty_result_is_empty_but_permission_error_propagates(self):
        for name in ("password_policy", "domain_level", "maq", "users_description", "asrep", "spn", "kerberoastable"):
            ldap = FakeLdap(error=NoResultError("base", "filter"))
            self.assertEqual([e async for e in getattr(get, name)(connection(ldap))], [])
        with self.assertRaises(PermissionError):
            await anext(get.spn(connection(FakeLdap(error=PermissionError("denied")))))

    async def test_policy_raw_case_projection_and_missing_attributes(self):
        ldap = FakeLdap([{"distinguishedName": FakeLdap.domainNC, "MINPWDLENGTH": [b"12"],
                          "maxpwdage": [b"0"], "unexpected": [b"drop"]}])
        readable = [e async for e in get.password_policy(connection(ldap))]
        raw = [e async for e in get.password_policy(connection(ldap), raw=True)]
        self.assertEqual(readable[0]["maxPwdAge"], ["0 (never expires)"])
        self.assertEqual(raw[0]["maxPwdAge"], ["0"])
        self.assertEqual(readable[0]["minPwdLength"], ["12"])
        self.assertNotIn("unexpected", readable[0])
        self.assertNotIn("lockoutThreshold", readable[0])

    async def test_users_without_description_are_preserved(self):
        ldap = FakeLdap([{"distinguishedName": "CN=Alice," + FakeLdap.domainNC,
                          "sAMAccountName": [b"alice"]}])
        result = [e async for e in get.users_description(connection(ldap))]
        self.assertEqual(len(result), 1)
        self.assertNotIn("description", result[0])

    async def test_scope_capabilities_and_unsupported_options(self):
        from bloodyAD.capabilities import capabilities_for
        for name in ("password_policy", "domain_level", "maq", "users_description", "asrep", "spn", "kerberoastable"):
            caps = capabilities_for("get", name, {})
            self.assertTrue(caps.search_scope)
            self.assertTrue(caps.delay)
            self.assertTrue(caps.filtered_controls)
            for options in (OpsecOptions(dry_run=True), OpsecOptions(rollback_file="unused.jsonl")):
                conn = connection(options=options)
                with self.assertRaises(ValueError):
                    await anext(getattr(get, name)(conn))
                conn.getLdap.assert_not_awaited()

    async def test_real_wrapper_rejects_root_scope_and_narrows_enumeration(self):
        from bloodyAD.search_policy import ScopeViolationError
        from tests.test_write_outcomes import fake_ldap
        allowed = "OU=Assessment,DC=example,DC=test"
        ldap = fake_ldap(OpsecOptions(base_dn=allowed))
        ldap.domainNC = "DC=example,DC=test"
        ldap.get_policy = AsyncMock(return_value={"MaxPageSize": 1000})
        calls = []

        async def pages(*args, **kwargs):
            calls.append(kwargs)
            yield {"objectName": "CN=Alice," + allowed, "attributes": {}}, None

        ldap.pagedsearch = pages
        for name in ("password_policy", "domain_level", "maq"):
            with self.subTest(name=name), self.assertRaises(ScopeViolationError):
                await anext(getattr(get, name)(connection(ldap)))
        self.assertEqual(calls, [])
        for name in ("users_description", "asrep", "spn", "kerberoastable"):
            result = [e async for e in getattr(get, name)(connection(ldap))]
            self.assertEqual(len(result), 1)
            self.assertEqual(calls[-1]["tree"], allowed)

    async def test_closing_command_closes_ldap_stream(self):
        closed = []
        ldap = FakeLdap()

        async def stream(*args, **kwargs):
            try:
                yield {"distinguishedName": ldap.domainNC}
                yield {"distinguishedName": ldap.domainNC}
            finally:
                closed.append(True)

        ldap.bloodysearch = stream
        result = get.spn(connection(ldap))
        await anext(result)
        await result.aclose()
        self.assertEqual(closed, [True])


class PolicyFormatterTests(unittest.TestCase):
    def test_policy_values(self):
        from bloodyAD.enumeration import format_policy_value
        cases = [
            ("pwdProperties", b"17", "17 (DOMAIN_PASSWORD_COMPLEX | DOMAIN_PASSWORD_STORE_CLEARTEXT)"),
            ("pwdProperties", "65", "65 (DOMAIN_PASSWORD_COMPLEX | unknown bits: 0x40)"),
            ("pwdProperties", 0, "0 (no flags set)"),
            ("maxPwdAge", 0, "0 (never expires)"),
            ("maxPwdAge", -(2**63), "-9223372036854775808 (never expires)"),
            ("minPwdAge", 0, "0 (no minimum age)"),
            ("lockoutThreshold", 0, "0 (lockout disabled)"),
            ("lockoutDuration", 0, "0 (administrator unlock required when lockout is enabled)"),
            ("lockoutDuration", -(2**63), "-9223372036854775808 (administrator unlock required when lockout is enabled)"),
            ("forceLogoff", -(2**63), "-9223372036854775808 (forced logoff disabled)"),
            ("forceLogoff", 0, "0 (immediate logoff when logon hours expire)"),
            ("lockOutObservationWindow", -15000001, "-15000001 (1.5000001 seconds)"),
            ("maxPwdAge", -864000000000, "-864000000000 (86400 seconds)"),
            ("maxPwdAge", "bad", "bad"),
            ("maxPwdAge", 12, "12"),
            ("maxPwdAge", True, "True"),
            ("minPwdLength", 12, "12"),
        ]
        for name, value, expected in cases:
            with self.subTest(name=name, value=value):
                self.assertEqual(format_policy_value(name, value), expected)


class EnumerationCliTests(unittest.TestCase):
    def test_lab_enumeration_runner_selects_only_read_only_suite_without_snapshot(self):
        from tests import run_lab
        from tests.support import LabConfig
        result = unittest.TestResult()
        with patch.object(sys, "argv", ["run_lab", "enumeration"]), patch.dict(os.environ, {}, clear=True):
            with patch("tests.support.LabConfig.from_environment", return_value=LabConfig(password="CANARY")):
                with patch.object(run_lab.unittest.defaultTestLoader, "loadTestsFromNames", return_value=unittest.TestSuite()) as loader:
                    with patch.object(run_lab.unittest, "TextTestRunner") as runner, patch.object(run_lab, "Path"):
                        runner.return_value.run.return_value = result
                        with self.assertRaises(SystemExit) as status:
                            run_lab.main()
                        self.assertEqual(status.exception.code, 0)
                        loader.assert_called_once_with(["tests.test_enumeration_lab"])

    def test_cli_names_aliases_json_and_close(self):
        for name in ("password-policy", "PASSWORD-POLICY", "password_policy", "users-description", "users_description", "domain-level", "domain_level", "maq", "asrep", "spn", "kerberoastable"):
            conn = connection()
            output = io.StringIO()
            with self.subTest(name=name), patch.object(sys, "argv", ["bloodyad-opsec", "-H", "invalid.test", "--json", "get", name]):
                with patch("bloodyAD.main.ConnectionHandler", return_value=conn), contextlib.redirect_stdout(output):
                    asyncio.run(amain())
                self.assertEqual(len(json.loads(output.getvalue())), 1)
                conn.closeLdap.assert_awaited_once()

    def test_empty_json_is_valid_array(self):
        conn = connection(FakeLdap(error=NoResultError("base", "filter")))
        with patch.object(sys, "argv", ["bloodyad-opsec", "-H", "invalid.test", "--json", "get", "spn"]):
            output = io.StringIO()
            with patch("bloodyAD.main.ConnectionHandler", return_value=conn), contextlib.redirect_stdout(output):
                asyncio.run(amain())
        self.assertEqual(json.loads(output.getvalue()), [])

    def test_help_lists_canonical_names(self):
        with patch.object(sys, "argv", ["bloodyad-opsec", "-H", "invalid.test", "get", "--help"]):
            output = io.StringIO()
            with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as result:
                asyncio.run(amain())
        self.assertEqual(result.exception.code, 0)
        self.assertIn("get commands:", output.getvalue())
        self.assertEqual(output.getvalue().count("[preset]"), 7)
        for name in ("password-policy", "users-description", "domain-level", "maq", "asrep", "spn", "kerberoastable"):
            self.assertIn(name, output.getvalue())
