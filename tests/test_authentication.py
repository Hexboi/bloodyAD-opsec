"""Read-only authentication checks; lab execution must be explicitly enabled."""
import asyncio
import os
import unittest

from tests.support import LabConfig, lab_cli, probe_lab


@unittest.skipUnless(os.getenv("BLOODYAD_LAB_TESTS") == "1", "Lab tests are opt-in")
class AuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = LabConfig.from_environment()
        cls.capabilities = asyncio.run(probe_lab(cls.config))

    def test_password_authentication(self):
        result = lab_cli(self.config, ["get", "object", self.capabilities.domain_dn, "--attr", "distinguishedName"])
        self.assertIn(self.capabilities.domain_dn.lower(), result.stdout.lower())

    def test_kerberos_password_authentication(self):
        result = lab_cli(self.config, ["-k", "kdc=" + self.config.ip, "get", "object",
                                      self.capabilities.domain_dn, "--attr", "distinguishedName"])
        self.assertIn(self.capabilities.domain_dn.lower(), result.stdout.lower())

    def test_certificate_authentication(self):
        if not self.capabilities.adcs:
            self.skipTest("No AD CS enrollment service is published in the lab")
        certificate = os.getenv("BLOODYAD_LAB_CERTIFICATE")
        if not certificate:
            self.skipTest("BLOODYAD_LAB_CERTIFICATE is not provided; no certificate was requested automatically")
        result = lab_cli(self.config, ["-c", certificate, "get", "object",
                                      self.capabilities.domain_dn, "--attr", "distinguishedName"])
        self.assertIn(self.capabilities.domain_dn.lower(), result.stdout.lower())
