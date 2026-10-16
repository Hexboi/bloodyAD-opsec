import argparse
import asyncio
import contextlib
import io
import logging
import unittest
from unittest.mock import AsyncMock, patch

from bloodyAD import exceptions
from bloodyAD.main import main


class DiagnosticsTests(unittest.TestCase):
    def tearDown(self):
        for handler in list(exceptions.LOG.handlers):
            if getattr(handler, "_bloody_cli", False):
                exceptions.LOG.removeHandler(handler)

    def test_logging_is_idempotent_and_separate_from_stdout(self):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            exceptions.enableCliLogger("INFO")
            exceptions.enableCliLogger("INFO")
            exceptions.LOG.info("one diagnostic")
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue().count("one diagnostic"), 1)

    def test_quiet_keeps_errors_visible(self):
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            exceptions.enableCliLogger("QUIET")
            exceptions.LOG.info("hidden")
            exceptions.LOG.error("visible")
        self.assertNotIn("hidden", errors.getvalue())
        self.assertIn("visible", errors.getvalue())

    def test_cli_does_not_print_dependency_exception_secrets(self):
        secret = "CANARY_password%3Ahash"
        conn = argparse.Namespace(closeLdap=AsyncMock())
        errors = io.StringIO()
        with patch("bloodyAD.main.amain", new=AsyncMock(side_effect=RuntimeError(secret))):
            with contextlib.redirect_stderr(errors):
                with self.assertRaises(SystemExit) as error:
                    main()
        self.assertEqual(error.exception.code, 1)
        self.assertNotIn(secret, errors.getvalue())
        self.assertIn("RuntimeError", errors.getvalue())

    def test_trace_does_not_enable_dependency_debug_logs(self):
        before = logging.getLogger().level
        try:
            exceptions.enableCliLogger("TRACE")
            self.assertEqual(logging.getLogger().level, before)
        finally:
            logging.getLogger().setLevel(before)

    def test_trust_read_helpers_never_log_raw_dependency_errors_or_parameters(self):
        from tests.test_write_outcomes import fake_ldap
        secret = "CANARY_SECRET"
        async def exercise():
            ldap = fake_ldap()
            conf = argparse.Namespace(host="dc.example.com", scheme="ldap", kerberos=False, certificate="")
            error = RuntimeError("ldap+ntlm://user:" + secret + "@dc")
            conn = argparse.Namespace(conf=conf, getLdap=AsyncMock(side_effect=error))
            await ldap.searchInPartition(conn, {"base": "domainNC", "ldap_filter": secret}, "")
            conn.getLdap = AsyncMock(side_effect=[argparse.Namespace(is_gc=False), error])
            await ldap.searchInForest(conn, {"base": "domainNC", "ldap_filter": secret}, "")
            future = asyncio.get_running_loop().create_future()
            future.set_exception(error)
            conn.ldap = future
            await ldap.interTrustOp({"test": {"conn_list": [conn]}}, {"filter": secret})
        for level in ("INFO", "DEBUG", "TRACE"):
            output = io.StringIO()
            with self.subTest(level=level), contextlib.redirect_stderr(output):
                exceptions.enableCliLogger(level)
                asyncio.run(exercise())
                self.assertNotIn(secret, output.getvalue())
                self.assertNotIn("ldap+ntlm://", output.getvalue())
                self.assertIn("RuntimeError", output.getvalue())
