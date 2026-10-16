import asyncio
import unittest
from unittest.mock import AsyncMock

from bloodyAD.network.config import Config, ConnectionHandler
from bloodyAD.opsec import OpsecOptions
from tests.test_write_outcomes import fake_ldap


class LifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_resolver_contexts_do_not_share_directory_results(self):
        from bloodyAD.utils import global_lazy_adschema

        async def resolve(label):
            global_lazy_adschema.conn = object()
            global_lazy_adschema.dn_dict["CN=TEST"] = label
            await asyncio.sleep(0)
            return global_lazy_adschema.dn_dict["CN=TEST"]

        self.assertEqual(await asyncio.gather(resolve("first"), resolve("second")), ["first", "second"])

    async def test_early_search_close_closes_dependency_generator(self):
        ldap = fake_ldap()
        ldap.get_policy = AsyncMock(return_value={"MaxPageSize": 1000})
        closed = []

        async def search(*args, **kwargs):
            try:
                yield {"objectName": "CN=Test,DC=example,DC=com", "attributes": {}}, None
                yield {"objectName": "CN=Next,DC=example,DC=com", "attributes": {}}, None
            finally:
                closed.append(True)

        ldap.pagedsearch = search
        stream = ldap.bloodysearch("DC=example,DC=com")
        await anext(stream)
        await stream.aclose()
        self.assertEqual(closed, [True])

    def test_connection_copies_keep_options_without_sharing_live_sessions(self):
        config = Config(host="dc.example.com", dcip="127.0.0.1", domain="example.com")
        options = OpsecOptions(dry_run=True)
        first = ConnectionHandler(config=config, options=options)
        second = first.copy(host="other.example.com")
        first._ldap = object()
        self.assertIsNone(second._ldap)
        self.assertEqual(second.options, options)
