"""Offline AD CS analysis contracts; no directory or CA access."""
import argparse
import asyncio
import contextlib
import io
import json
import struct
import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from bloodyAD.cli_modules import get
from bloodyAD.exceptions import NoResultError
from bloodyAD.formatters.accesscontrol import createACE, createEmptySD
from bloodyAD.main import amain
from bloodyAD.network.ldap import Scope
from bloodyAD.opsec import OpsecOptions


CONFIG = "CN=Configuration,DC=example,DC=test"
PKI = "CN=Public Key Services,CN=Services," + CONFIG
USER = "S-1-5-21-1-2-3-513"
ADMIN = "S-1-5-21-1-2-3-512"
ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
AUTOENROLL = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
AGENT = "1.3.6.1.4.1.311.20.2.1"
ANY_PURPOSE = "2.5.29.37.0"
POLICY = "1.2.3.4"
GROUP = "CN=CertificateUsers,CN=Users,DC=example,DC=test"


def descriptor(*aces, owner="S-1-5-32-544"):
    sd = createEmptySD()
    sd["OwnerSid"].fromCanonical(owner)
    sd["Dacl"].aces = list(aces)
    return sd.getData()


def ace(mask=0x100, guid=ENROLL, sid=USER, flags=0, denied=False):
    item = createACE(sid, object_type=guid, access_mask=mask)
    item["AceFlags"] = flags
    if denied:
        item["AceType"] = 6 if guid else 1
    return item


def template(**changes):
    entry = {
        "distinguishedName": "CN=Test,CN=Certificate Templates," + PKI,
        "name": [b"Test"], "displayName": [b"Test template"],
        "msPKI-Certificate-Name-Flag": [b"1"],
        "msPKI-Enrollment-Flag": [b"0"],
        "msPKI-RA-Signature": [b"0"],
        "msPKI-Template-Schema-Version": [b"2"],
        "pKIExtendedKeyUsage": [CLIENT_AUTH.encode()],
        "nTSecurityDescriptor": [descriptor(ace())],
    }
    entry.update(changes)
    return entry


def ca(**changes):
    entry = {"distinguishedName": "CN=CA,CN=Enrollment Services," + PKI,
             "name": [b"CA"], "dNSHostName": [b"ca.example.test"],
             "certificateTemplates": [b"TEST"],
             "nTSecurityDescriptor": [descriptor()]}
    entry.update(changes)
    return entry


def dc_entry(sid, uac=8192):
    raw_sid = createEmptySD()["OwnerSid"]
    raw_sid.fromCanonical(sid)
    return {"distinguishedName": "CN=RenamedDC,OU=Servers,DC=example,DC=test",
            "objectSid": [raw_sid.getData()], "userAccountControl": [str(uac).encode()]}


class FakeLdap:
    configNC = CONFIG
    domainNC = "DC=example,DC=test"

    def __init__(self, templates=(), cas=(), policies=(), ntauth=(), computers=(), error=None):
        self.data = {"pKIEnrollmentService": cas, "pKICertificateTemplate": templates,
                     "msPKI-Enterprise-Oid": policies, "certificationAuthority": ntauth,
                     "computer": computers}
        self.error = error
        self.calls = []
        self.closed = []

    async def bloodysearch(self, base, ldap_filter, **kwargs):
        self.calls.append((base, ldap_filter, kwargs))
        try:
            if self.error:
                raise self.error
            rows = next(rows for key, rows in self.data.items() if key in ldap_filter)
            if not rows:
                raise NoResultError(base, ldap_filter)
            for row in rows:
                yield dict(row)
        finally:
            self.closed.append(ldap_filter)


def connection(ldap=None, options=None):
    return argparse.Namespace(getLdap=AsyncMock(return_value=ldap or FakeLdap()),
                              closeLdap=AsyncMock(), options=options or OpsecOptions())


class AnalysisTests(unittest.IsolatedAsyncioTestCase):
    async def analyze(self, entry=None, cas=None, **kwargs):
        from bloodyAD.adcs import analyze
        ldap = FakeLdap(templates=[entry or template()], cas=[ca()] if cas is None else cas, **kwargs)
        rows = [row async for row in analyze(connection(ldap))]
        return next(row for row in rows if row["kind"] == "template")

    def ids(self, row):
        return {finding["id"] for finding in row["findings"]}

    async def test_esc1_publication_case_signed_flags_and_evidence(self):
        row = await self.analyze(template(**{"msPKI-Certificate-Name-Flag": [b"-2147483647"]}))
        self.assertEqual(self.ids(row), {"ESC1"})
        self.assertEqual(row["published_on"], ["CA"])
        self.assertEqual(row["settings"]["name_flags"], 0x80000001)
        self.assertEqual(row["findings"][0]["principals"], [USER])
        self.assertEqual(row["findings"][0]["status"], "potential")
        self.assertTrue(row["findings"][0]["unverified"])
        self.assertEqual(row["acl"][0]["sid"], "S-1-5-32-544")

    async def test_template_rules(self):
        cases = [({"pKIExtendedKeyUsage": [ANY_PURPOSE]}, {"ESC1", "ESC2", "ESC17"}),
                 ({"pKIExtendedKeyUsage": [AGENT]}, {"ESC3"}),
                 ({"msPKI-Enrollment-Flag": [0x80000]}, {"ESC1", "ESC9"}),
                 ({"msPKI-Template-Schema-Version": [1], "pKIExtendedKeyUsage": [SERVER_AUTH]}, {"ESC15", "ESC17"}),
                 ({"msPKI-Certificate-Name-Flag": [0x400000]}, set())]
        for changes, expected in cases:
            with self.subTest(changes=changes):
                self.assertEqual(self.ids(await self.analyze(template(**changes))), expected)

    async def test_approval_and_signatures_block_automatic_issuance_rules(self):
        for changes in ({"msPKI-Enrollment-Flag": [2]}, {"msPKI-RA-Signature": [1]}):
            for eku in (CLIENT_AUTH, ANY_PURPOSE, AGENT):
                row = await self.analyze(template(**{**changes, "pKIExtendedKeyUsage": [eku]}))
                self.assertFalse(self.ids(row) & {"ESC1", "ESC2", "ESC3"})

    async def test_modification_and_autoenroll_are_not_enrollment(self):
        for grant, expected in ((ace(0x40000000, None), {"ESC4"}),
                                (ace(0x100, AUTOENROLL), set()),
                                (ace(0x20, "ea1dddc4-60ff-416e-8cc0-17cee534bce7"), {"ESC4"}),
                                (ace(0x20, "bf967950-0de6-11d0-a285-00aa003049e2"), set())):
            row = await self.analyze(template(nTSecurityDescriptor=[descriptor(grant)]))
            self.assertEqual(self.ids(row), expected)

    async def test_multiple_mask_bits_and_mapped_full_control(self):
        for mask in (0x40000 | 0x80000 | 0x100, 0xF01FF, 0x10000000):
            row = await self.analyze(template(nTSecurityDescriptor=[descriptor(ace(mask, None))]))
            self.assertEqual(self.ids(row), {"ESC1", "ESC4"})
            rights = {item["right"] for item in row["acl"] if item["sid"] == USER}
            self.assertTrue({"WriteDacl", "WriteOwner", "Enroll"} <= rights)

    async def test_object_guid_restricts_enrollment_and_generic_write(self):
        unrelated = "bf967950-0de6-11d0-a285-00aa003049e2"
        row = await self.analyze(template(nTSecurityDescriptor=[descriptor(ace(0xF01FF, unrelated))]))
        self.assertEqual(self.ids(row), {"ESC4"})
        row = await self.analyze(template(nTSecurityDescriptor=[descriptor(ace(0x40000000, unrelated))]))
        self.assertEqual(self.ids(row), set())

    async def test_null_and_empty_dacl_are_distinct(self):
        null = struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 0, 0)
        row = await self.analyze(template(nTSecurityDescriptor=[null]))
        self.assertEqual(self.ids(row), {"ESC1", "ESC4"})
        self.assertTrue(any("NULL DACL" in note for note in row["limitations"]))
        row = await self.analyze(template(nTSecurityDescriptor=[descriptor()]))
        self.assertEqual(self.ids(row), set())

    async def test_zero_schema_version_is_unknown(self):
        row = await self.analyze(template(**{"msPKI-Template-Schema-Version": [0]}))
        self.assertIsNone(row["settings"]["schema_version"])
        self.assertEqual(row["assessment"], "incomplete")

    async def test_unpublished_template_keeps_latent_acl_finding(self):
        row = await self.analyze(template(nTSecurityDescriptor=[descriptor(ace(0x10000000, None))]), cas=[])
        self.assertEqual(row["published_on"], [])
        self.assertEqual(self.ids(row), {"ESC4"})
        self.assertIn("unpublished", row["publication"])

    async def test_esc13_joins_issuance_policy_not_template_identity(self):
        policy = {"distinguishedName": "CN=Policy,CN=OID," + PKI,
                  "msPKI-Cert-Template-OID": [POLICY], "msDS-OIDToGroupLink": [GROUP]}
        row = await self.analyze(template(**{"msPKI-Certificate-Name-Flag": [0],
                                            "msPKI-Certificate-Policy": [POLICY]}), policies=[policy])
        self.assertEqual(self.ids(row), {"ESC13"})
        self.assertEqual(row["linked_groups"], [GROUP])
        row = await self.analyze(template(**{"msPKI-Cert-Template-OID": [POLICY]}), policies=[policy])
        self.assertNotIn("ESC13", self.ids(row))

    async def test_esc13_preserves_all_issuance_policy_group_links(self):
        other_policy = "1.2.3.5"
        other_group = "CN=OtherCertificateUsers,CN=Users,DC=example,DC=test"
        policies = [
            {"distinguishedName": "CN=First,CN=OID," + PKI,
             "msPKI-Cert-Template-OID": [POLICY], "msDS-OIDToGroupLink": [GROUP]},
            {"distinguishedName": "CN=Second,CN=OID," + PKI,
             "msPKI-Cert-Template-OID": [other_policy], "msDS-OIDToGroupLink": [other_group]},
        ]
        row = await self.analyze(template(**{"msPKI-Certificate-Name-Flag": [0],
                                            "msPKI-Certificate-Policy": [b"1.2.3.0", POLICY.encode(), other_policy.encode()]}),
                                 policies=policies)
        self.assertEqual(self.ids(row), {"ESC13"})
        self.assertEqual(row["linked_groups"], sorted([GROUP, other_group]))
        self.assertEqual(row["issuance_policies"], ["1.2.3.0", POLICY, other_policy])
        self.assertEqual(row["findings"][0]["principals"], [USER])

    async def test_esc13_requires_known_issuance_gates_and_enrollment(self):
        policy = {"distinguishedName": "CN=Policy,CN=OID," + PKI,
                  "msPKI-Cert-Template-OID": [POLICY], "msDS-OIDToGroupLink": [GROUP]}
        for changes in ({"msPKI-Enrollment-Flag": [2]}, {"msPKI-RA-Signature": [1]},
                        {"msPKI-Enrollment-Flag": []}, {"msPKI-RA-Signature": [b"invalid"]},
                        {"nTSecurityDescriptor": [descriptor()]}, {"pKIExtendedKeyUsage": [SERVER_AUTH]}):
            with self.subTest(changes=changes):
                row = await self.analyze(template(**{"msPKI-Certificate-Name-Flag": [0],
                                                    "msPKI-Certificate-Policy": [POLICY], **changes}), policies=[policy])
                self.assertNotIn("ESC13", self.ids(row))
        row = await self.analyze(template(**{"msPKI-Certificate-Policy": [POLICY]}), policies=[policy], cas=[])
        self.assertNotIn("ESC13", self.ids(row))

    async def test_esc17_server_authentication_any_purpose_and_absent_ekus(self):
        for ekus, expected in (([SERVER_AUTH], {"ESC17"}),
                               ([SERVER_AUTH, CLIENT_AUTH], {"ESC1", "ESC17"}),
                               ([ANY_PURPOSE], {"ESC1", "ESC2", "ESC17"}),
                               ([], {"ESC1", "ESC2", "ESC17"})):
            with self.subTest(ekus=ekus):
                row = await self.analyze(template(pKIExtendedKeyUsage=ekus))
                self.assertEqual(self.ids(row), expected)
                finding = next(item for item in row["findings"] if item["id"] == "ESC17")
                self.assertEqual(finding["principals"], [USER])
                self.assertEqual(finding["status"], "potential")
                self.assertTrue(finding["unverified"])

    async def test_esc17_requires_subject_enrollment_publication_and_issuance_gates(self):
        for changes in ({"msPKI-Certificate-Name-Flag": [0]}, {"msPKI-Certificate-Name-Flag": [65536]},
                        {"msPKI-Certificate-Name-Flag": []}, {"msPKI-Enrollment-Flag": [2]},
                        {"msPKI-RA-Signature": [1]}, {"msPKI-RA-Signature": []},
                        {"nTSecurityDescriptor": [descriptor(ace(sid=ADMIN))]},
                        {"nTSecurityDescriptor": [descriptor(ace(guid=AUTOENROLL))]},
                        {"nTSecurityDescriptor": [descriptor(ace(0x40000000, None))]},
                        {"pKIExtendedKeyUsage": [CLIENT_AUTH]}, {"pKIExtendedKeyUsage": [b"invalid"]}):
            with self.subTest(changes=changes):
                row = await self.analyze(template(**{"pKIExtendedKeyUsage": [SERVER_AUTH], **changes}))
                self.assertNotIn("ESC17", self.ids(row))
        row = await self.analyze(template(pKIExtendedKeyUsage=[SERVER_AUTH]), cas=[])
        self.assertNotIn("ESC17", self.ids(row))

    async def test_esc17_uses_effective_application_policies(self):
        row = await self.analyze(template(**{"pKIExtendedKeyUsage": [CLIENT_AUTH],
                                            "msPKI-Certificate-Application-Policy": [SERVER_AUTH]}))
        self.assertEqual(self.ids(row), {"ESC17"})
        row = await self.analyze(template(**{"pKIExtendedKeyUsage": [SERVER_AUTH],
                                            "msPKI-Certificate-Application-Policy": [CLIENT_AUTH]}))
        self.assertEqual(self.ids(row), {"ESC1"})

    async def test_application_policy_precedes_eku_and_ra_policies_are_separate(self):
        row = await self.analyze(template(**{"msPKI-Certificate-Application-Policy": [SERVER_AUTH],
                                            "msPKI-RA-Application-Policies": [CLIENT_AUTH]}))
        self.assertNotIn("ESC1", self.ids(row))
        self.assertEqual(row["settings"]["effective_ekus"], [SERVER_AUTH])
        row = await self.analyze(template(**{"msPKI-Certificate-Application-Policy": [CLIENT_AUTH],
                                            "pKIExtendedKeyUsage": [SERVER_AUTH]}))
        self.assertIn("ESC1", self.ids(row))

    async def test_missing_and_invalid_attributes_remain_unknown(self):
        for value in ([], [b"invalid"], [b"0", b"1"], [-1]):
            row = await self.analyze(template(**{"msPKI-RA-Signature": value}))
            self.assertIsNone(row["settings"]["authorized_signatures"])
            self.assertEqual(row["assessment"], "incomplete")
            self.assertTrue(row["limitations"])
        row = await self.analyze(template(pKIExtendedKeyUsage=[]))
        self.assertIn("ESC2", self.ids(row))
        self.assertTrue(any("absen" in note.lower() for note in row["limitations"]))
        row = await self.analyze(template(pKIExtendedKeyUsage=[b"not-an-oid"]))
        self.assertNotIn("ESC2", self.ids(row))
        self.assertEqual(row["assessment"], "incomplete")

    async def test_v1_absent_signature_attribute_uses_schema_default_with_remark(self):
        entry = template(**{"msPKI-Template-Schema-Version": [1]})
        del entry["msPKI-RA-Signature"]
        row = await self.analyze(entry)
        self.assertIn("ESC15", self.ids(row))
        self.assertTrue(any("schema-v1" in note for note in row["limitations"]))

    async def test_missing_invalid_deny_conditional_and_inherit_only_acls(self):
        from bloodyAD.adcs import acl_evidence
        for raw in (None, b"invalid", descriptor()[:20]):
            grants, limits = acl_evidence(raw)
            self.assertTrue(limits)
        row = await self.analyze(template(nTSecurityDescriptor=[descriptor(ace(flags=8))]))
        self.assertEqual(self.ids(row), set())
        row = await self.analyze(template(nTSecurityDescriptor=[descriptor(ace(denied=True), ace())]))
        self.assertEqual(row["assessment"], "incomplete")
        self.assertTrue(any("deny" in note.lower() for note in row["limitations"]))
        conditional = ace(guid=None)
        conditional["AceType"] = 9
        row = await self.analyze(template(nTSecurityDescriptor=[descriptor(conditional)]))
        self.assertEqual(self.ids(row), set())
        self.assertTrue(any("unsupported" in note.lower() for note in row["limitations"]))

    async def test_privileged_filter_does_not_match_arbitrary_sid_suffix(self):
        for sid, expected in ((ADMIN, set()), ("S-1-5-32-544", set()),
                              ("S-1-5-80-1-2-3-512", {"ESC1"})):
            row = await self.analyze(template(nTSecurityDescriptor=[descriptor(ace(sid=sid))]))
            self.assertEqual(self.ids(row), expected)

    async def test_ca_directory_acl_is_not_esc7(self):
        from bloodyAD.adcs import analyze
        rows = [row async for row in analyze(connection(FakeLdap(cas=[ca(nTSecurityDescriptor=[
            descriptor(ace(0x40000, None))])])))]
        row = next(row for row in rows if row["kind"] == "ca")
        self.assertEqual(self.ids(row), {"CA_OBJECT_ACL"})
        self.assertEqual(row["findings"][0]["principals"], [USER])

    async def test_ldap_dc_role_suppresses_ca_alert_but_preserves_acl_and_esc1(self):
        from bloodyAD.adcs import analyze
        machine_sid = "S-1-5-21-1-2-3-1001"
        for uac in (0x82000, 0x5001000):
            ldap = FakeLdap(templates=[template()], cas=[ca(nTSecurityDescriptor=[
                descriptor(ace(0xF00FF, None, sid=machine_sid))])],
                computers=[dc_entry(machine_sid, uac)])
            rows = [row async for row in analyze(connection(ldap))]
            ca_row = next(row for row in rows if row["kind"] == "ca")
            self.assertEqual(ca_row["findings"], [])
            self.assertEqual(ca_row["excluded_dc_sids"], [machine_sid])
            self.assertTrue(any(grant["sid"] == machine_sid and grant["right"] == "WriteDacl" for grant in ca_row["acl"]))
            self.assertEqual(self.ids(next(row for row in rows if row["kind"] == "template")), {"ESC1"})
            base, ldap_filter, options = next(call for call in ldap.calls if "(objectClass=computer)" in call[1])
            self.assertEqual(base, ldap.domainNC)
            self.assertEqual(ldap_filter, "(&(objectClass=computer)(|(userAccountControl:1.2.840.113556.1.4.803:=8192)"
                             "(userAccountControl:1.2.840.113556.1.4.803:=67108864)))")
            self.assertEqual(options["attr"], ["objectSid", "userAccountControl"])
            self.assertTrue(options["raw"])
            self.assertEqual(options["control_flag"], 0)
            self.assertEqual(len(ldap.closed), 5)

    async def test_dc_filter_preserves_other_ca_trustees(self):
        from bloodyAD.adcs import analyze
        machine_sid = "S-1-5-21-1-2-3-1001"
        ldap = FakeLdap(cas=[ca(nTSecurityDescriptor=[descriptor(
            ace(0x40000, None, sid=machine_sid), ace(0x40000, None))])],
            computers=[dc_entry(machine_sid)])
        rows = [row async for row in analyze(connection(ldap))]
        row = next(row for row in rows if row["kind"] == "ca")
        self.assertEqual(self.ids(row), {"CA_OBJECT_ACL"})
        self.assertEqual(row["findings"][0]["principals"], [USER])

    async def test_unverified_dc_roles_never_suppress_ca_alerts(self):
        from bloodyAD.adcs import analyze
        machine_sid = "S-1-5-21-1-2-3-1001"
        ordinary = dc_entry(machine_sid, 4096)
        ordinary["distinguishedName"] = "CN=DC01,OU=Domain Controllers," + FakeLdap.domainNC
        ordinary["primaryGroupID"] = [b"516"]
        malformed = dc_entry(machine_sid)
        malformed["objectSid"] = [b"invalid"]
        missing_role = dc_entry(machine_sid)
        missing_role.pop("userAccountControl")
        for computers in ([], [ordinary], [malformed], [missing_role]):
            ldap = FakeLdap(cas=[ca(nTSecurityDescriptor=[descriptor(
                ace(0x40000, None, sid=machine_sid))])], computers=computers)
            rows = [row async for row in analyze(connection(ldap))]
            row = next(row for row in rows if row["kind"] == "ca")
            self.assertEqual(self.ids(row), {"CA_OBJECT_ACL"})
            self.assertEqual(row["excluded_dc_sids"], [])
            if computers == [malformed] or computers == [missing_role]:
                coverage = next(row for row in rows if row["kind"] == "coverage")
                self.assertTrue(any("domain-controller" in note.lower() for note in coverage["limitations"]))

    async def test_dc_role_lookup_permission_error_is_not_a_clean_result(self):
        from bloodyAD.adcs import analyze
        ldap = FakeLdap(cas=[ca()])
        original = ldap.bloodysearch
        closed = []

        async def searches(base, ldap_filter, **options):
            if "(objectClass=computer)" in ldap_filter:
                try:
                    raise PermissionError("DC inventory denied")
                    yield
                finally:
                    closed.append(True)
            else:
                async for row in original(base, ldap_filter, **options):
                    yield row

        ldap.bloodysearch = searches
        with self.assertRaises(PermissionError):
            await anext(analyze(connection(ldap)))
        self.assertEqual(closed, [True])

    async def test_scoped_ca_certificate_template_write_is_reported(self):
        from bloodyAD.adcs import analyze
        grant = ace(0x20, "2a39c5b1-8960-11d1-aebc-0000f80367c1")
        rows = [row async for row in analyze(connection(FakeLdap(cas=[ca(
            nTSecurityDescriptor=[descriptor(grant)])])))]
        self.assertEqual(self.ids(next(row for row in rows if row["kind"] == "ca")), {"CA_OBJECT_ACL"})

    async def test_collection_scope_controls_raw_values_cleanup_and_empty_coverage(self):
        from bloodyAD.adcs import analyze
        ldap = FakeLdap()
        rows = [row async for row in analyze(connection(ldap))]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "coverage")
        self.assertIn("ESC7", rows[0]["unverified_checks"])
        self.assertIn("ESC13", rows[0]["checks"])
        self.assertIn("ESC17", rows[0]["checks"])
        self.assertNotIn("ESC17", rows[0]["unverified_checks"])
        self.assertEqual(len(ldap.calls), 4)
        self.assertEqual(len(ldap.closed), 4)
        for base, ldap_filter, options in ldap.calls:
            self.assertEqual(base, CONFIG)
            self.assertEqual(options["search_scope"], Scope.SUBTREE)
            self.assertTrue(options["raw"])
            self.assertNotIn("*", options["attr"])
            self.assertEqual(options["control_flag"], 5 if "nTSecurityDescriptor" in options["attr"] else 0)
        ldap = FakeLdap(error=PermissionError("denied"))
        with self.assertRaises(PermissionError):
            await anext(analyze(connection(ldap)))
        self.assertEqual(len(ldap.closed), 1)

    async def test_partial_search_failure_and_cancellation_close_streams(self):
        from bloodyAD.adcs import analyze
        for failure in (OSError("connection lost"), asyncio.CancelledError()):
            ldap = FakeLdap()
            closed = []

            async def failing_stream(*args, **kwargs):
                try:
                    yield ca()
                    raise failure
                finally:
                    closed.append(True)

            ldap.bloodysearch = failing_stream
            with self.assertRaises(type(failure)):
                await anext(analyze(connection(ldap)))
            self.assertEqual(closed, [True])

    async def test_attribute_names_are_case_insensitive(self):
        row = await self.analyze({key.upper(): value for key, value in template().items()})
        self.assertEqual(self.ids(row), {"ESC1"})

    async def test_certificates_ntauth_and_invalid_blob_visibility(self):
        from bloodyAD.adcs import analyze
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(1)
                .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
                .not_valid_after(datetime(2021, 1, 1, tzinfo=timezone.utc))
                .sign(key, hashes.SHA256()))
        blob = cert.public_bytes(serialization.Encoding.DER)
        ntauth = {"distinguishedName": "CN=NTAuthCertificates," + PKI, "cACertificate": [blob]}
        ldap = FakeLdap(cas=[ca(cACertificate=[blob, b"invalid"])], ntauth=[ntauth])
        rows = [row async for row in analyze(connection(ldap))]
        row = next(row for row in rows if row["kind"] == "ca")
        self.assertEqual(row["certificates"][0]["sha256"], cert.fingerprint(hashes.SHA256()).hex().upper())
        self.assertTrue(row["certificates"][0]["ntauth_match"])
        self.assertEqual(row["certificates"][0]["validity"], "expired")
        self.assertTrue(any("certificate" in note.lower() for note in row["limitations"]))

    async def test_real_ldap_wrapper_keeps_controls_delay_and_never_writes(self):
        from tests.test_write_outcomes import fake_ldap
        ldap = fake_ldap(OpsecOptions(sleep=0.01))
        ldap.configNC = CONFIG
        ldap.get_policy = AsyncMock(return_value={"MaxPageSize": 1000})
        calls, closed = [], []

        async def pages(ldap_filter, attributes, **kwargs):
            calls.append((attributes, kwargs))
            try:
                rows = [template()] if "pKICertificateTemplate" in ldap_filter else []
                if "NTAuthCertificates" in ldap_filter:
                    rows = [{"distinguishedName": "CN=NTAuthCertificates," + PKI}]
                for row in rows:
                    raw_attributes = {key: value for key, value in row.items() if key != "distinguishedName"}
                    if "distinguishedName" in attributes:
                        raw_attributes["distinguishedName"] = [row["distinguishedName"].encode()]
                    yield {"objectName": row["distinguishedName"],
                           "attributes": raw_attributes}, None
            finally:
                closed.append(True)

        ldap.pagedsearch = pages
        with patch("bloodyAD.opsec.asyncio.sleep", new_callable=AsyncMock) as sleep:
            rows = [row async for row in get.adcs(connection(ldap, options=ldap.options))]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1]["distinguishedName"], template()["distinguishedName"])
        self.assertEqual(len(closed), 4)
        self.assertTrue(sleep.await_count)
        for attributes, options in calls:
            self.assertEqual(options["tree"], CONFIG)
            controls = options["controls"]
            if "nTSecurityDescriptor" in attributes:
                self.assertEqual(controls, [("1.2.840.113556.1.4.801", True, b"\x30\x03\x02\x01\x05")])
            else:
                self.assertEqual(controls, [])
        for method in (ldap.add, ldap.modify, ldap.delete, ldap._con.modify_dn):
            method.assert_not_awaited()


class CliTests(unittest.TestCase):
    def test_help_describes_adcs_coverage_dc_exclusions_and_limits(self):
        cases = [(["--help"], ["AD CS"]),
                 (["get", "--help"], ["adcs", "AD CS"]),
                 (["get", "adcs", "--help"],
                  ["ESC1", "ESC13", "ESC15", "ESC17", "CA_OBJECT_ACL", "excluded_dc_sids",
                   "SERVER_TRUST_ACCOUNT", "PARTIAL_SECRETS_ACCOUNT", "--json",
                   "--base-dn", "--dry-run", "--rollback-file", "--raw", "HTTP/RPC"])]
        for args, expected in cases:
            with self.subTest(args=args), patch.object(sys, "argv", ["bloodyad-opsec", *args]):
                output = io.StringIO()
                with patch("bloodyAD.main.ConnectionHandler") as handler:
                    with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as result:
                        asyncio.run(amain())
                self.assertEqual(result.exception.code, 0)
                handler.assert_not_called()
                for phrase in expected:
                    self.assertIn(phrase, output.getvalue())

    def test_connection_closes_on_ldap_error(self):
        conn = connection(FakeLdap(error=PermissionError("denied")))
        with patch.object(sys, "argv", ["bloodyad-opsec", "-H", "invalid.test", "get", "adcs"]):
            with patch("bloodyAD.main.ConnectionHandler", return_value=conn):
                with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(PermissionError):
                    asyncio.run(amain())
        conn.closeLdap.assert_awaited_once()

    def test_cli_text_json_help_and_connection_cleanup(self):
        for json_mode in (False, True):
            conn = connection(FakeLdap(templates=[template()], cas=[ca()]))
            output = io.StringIO()
            argv = ["bloodyad-opsec", "-H", "invalid.test"] + (["--json"] if json_mode else []) + ["get", "adcs"]
            with patch.object(sys, "argv", argv), patch("bloodyAD.main.ConnectionHandler", return_value=conn):
                with contextlib.redirect_stdout(output):
                    asyncio.run(amain())
            self.assertIn("ESC1", output.getvalue())
            if json_mode:
                rows = json.loads(output.getvalue())
                row = next(row for row in rows if row["kind"] == "template")
                self.assertEqual(row["findings"][0]["principals"], [USER])
            conn.closeLdap.assert_awaited_once()
        with patch.object(sys, "argv", ["bloodyad-opsec", "-H", "invalid.test", "get", "adcs", "--help"]):
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as result:
                asyncio.run(amain())
        self.assertEqual(result.exception.code, 0)

    def test_unsupported_cli_options_rejected_before_connection(self):
        for args in (["--base-dn", CONFIG], ["--dry-run"], ["--rollback-file", "unused.jsonl"]):
            with patch.object(sys, "argv", ["bloodyad-opsec", "-H", "invalid.test", *args, "get", "adcs"]):
                with patch("bloodyAD.main.ConnectionHandler") as handler:
                    with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
                        asyncio.run(amain())
                self.assertEqual(result.exception.code, 2)
                handler.assert_not_called()


class CapabilityTests(unittest.IsolatedAsyncioTestCase):
    async def test_library_guards_and_supported_read_controls(self):
        from bloodyAD.capabilities import capabilities_for
        caps = capabilities_for("get", "adcs", {})
        self.assertTrue(caps.delay)
        self.assertTrue(caps.filtered_controls)
        self.assertFalse(caps.search_scope)
        for options in (OpsecOptions(base_dn=CONFIG), OpsecOptions(dry_run=True),
                        OpsecOptions(rollback_file="unused.jsonl")):
            conn = connection(options=options)
            with self.assertRaises(ValueError):
                await anext(get.adcs(conn))
            conn.getLdap.assert_not_awaited()
        conn = connection(options=OpsecOptions(sleep=0.01, strip_controls=frozenset({"x"})))
        self.assertEqual(len([row async for row in get.adcs(conn)]), 1)
