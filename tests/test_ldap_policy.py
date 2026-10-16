import unittest
from tests.test_write_outcomes import fake_ldap


class LDAPPolicyTests(unittest.IsolatedAsyncioTestCase):
    async def test_policy_reads_nested_attributes_and_caches_per_session(self):
        ldap = fake_ldap()
        ldap.configNC = "CN=Configuration,DC=example,DC=com"
        ldap._serverinfo = {"dsServiceName": "CN=NTDS Settings,CN=DC,CN=Servers,CN=Site,CN=Sites," + ldap.configNC}
        requests = []

        async def search(*args, **kwargs):
            requests.append((args, kwargs))
            yield {"objectName": "CN=Default Query Policy,CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services," + ldap.configNC,
                   "attributes": {"lDAPAdminLimits": [b"MaxPageSize=500"]}}, None

        ldap.pagedsearch = search
        first = await ldap.get_policy()
        self.assertEqual(first["MaxPageSize"], 500)
        first["MaxPageSize"] = 1
        self.assertEqual((await ldap.get_policy())["MaxPageSize"], 500)
        self.assertEqual(len(requests), 1)

    async def test_missing_site_and_bad_policy_use_explicit_default(self):
        ldap = fake_ldap()
        ldap.configNC = "CN=Configuration,DC=example,DC=com"
        ldap._serverinfo = {"dsServiceName": "CN=No Site," + ldap.configNC}

        async def search(*args, **kwargs):
            yield {"objectName": "CN=Other", "attributes": {"lDAPAdminLimits": [b"MaxPageSize=bad"]}}, None

        ldap.pagedsearch = search
        self.assertEqual((await ldap.get_policy())["MaxPageSize"], 1000)

    async def test_transport_errors_are_not_converted_to_defaults(self):
        ldap = fake_ldap()
        ldap.configNC = "CN=Configuration,DC=example,DC=com"
        ldap._serverinfo = {"dsServiceName": "CN=No Site," + ldap.configNC}

        async def search(*args, **kwargs):
            yield None, RuntimeError("unavailable")

        ldap.pagedsearch = search
        with self.assertRaises(RuntimeError):
            await ldap.get_policy()

    async def test_default_container_metadata_has_a_fixed_base_and_attributes(self):
        ldap = fake_ldap()
        ldap.domainNC = "DC=example,DC=com"
        requests = []

        async def search(*args, **kwargs):
            requests.append((args, kwargs))
            yield {"objectName": ldap.domainNC, "attributes": {}}, None

        ldap.pagedsearch = search
        await ldap.read_metadata("default_containers")
        self.assertEqual(requests[0][0], ("(objectClass=*)", ["wellKnownObjects"]))
        self.assertEqual(requests[0][1]["tree"], "DC=example,DC=com")
        self.assertEqual(requests[0][1]["search_scope"], 0)
        with self.assertRaises(ValueError):
            await ldap.read_metadata("arbitrary")
