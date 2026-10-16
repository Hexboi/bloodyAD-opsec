import argparse
import unittest
from unittest.mock import AsyncMock


class FixtureOwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def test_cleanup_refuses_an_object_with_changed_identity(self):
        from tests.fixtures import LabFixture
        from unittest.mock import patch
        ldap = argparse.Namespace(delete=AsyncMock())
        fixture = LabFixture(None)
        fixture.ldap = ldap
        fixture.base = "OU=BA-Test,DC=example,DC=com"
        fixture.owned = [{"dn": "CN=One," + fixture.base, "guid": "original"}]
        with patch("tests.fixtures.read_state", new=AsyncMock(return_value={"guid": "replacement"})):
            with self.assertRaises(RuntimeError):
                await fixture.cleanup()
        ldap.delete.assert_not_awaited()
