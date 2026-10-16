import unittest
from unittest.mock import AsyncMock

from bloodyAD.network.ldap import Scope
from bloodyAD.opsec import OpsecOptions
from tests.test_write_outcomes import fake_ldap


class SearchPolicyTests(unittest.TestCase):
    def test_scope_preserves_child_and_only_narrows_subtree_ancestors(self):
        from bloodyAD.search_policy import SearchPolicy, ScopeViolationError
        allowed = "OU=Test,DC=example,DC=com"
        child = "CN=Alice," + allowed
        policy = SearchPolicy(allowed)
        self.assertEqual(policy.resolve_base(child, Scope.BASE), child)
        self.assertEqual(policy.resolve_base("DC=example,DC=com", Scope.SUBTREE), allowed)
        for base, scope in (("DC=example,DC=com", Scope.BASE),
                            ("DC=example,DC=com", Scope.LEVEL),
                            ("OU=Other,DC=example,DC=com", Scope.SUBTREE),
                            ("", Scope.SUBTREE),
                            ("OU=Test,DC=other,DC=com", Scope.SUBTREE)):
            with self.subTest(base=base, scope=scope):
                with self.assertRaises(ScopeViolationError):
                    policy.resolve_base(base, scope)

    def test_escaped_rdn_is_not_a_textual_suffix_boundary(self):
        from bloodyAD.search_policy import SearchPolicy, ScopeViolationError
        policy = SearchPolicy("OU=Test,DC=example,DC=com")
        with self.assertRaises(ScopeViolationError):
            policy.validate_target(r"CN=Fake\,OU=Test,DC=example,DC=com")
        policy.validate_target(r"CN=Doe\, Alice,OU=Test,DC=example,DC=com")
        policy.validate_target(r"CN=Doe\2C Alice,OU=Test,DC=example,DC=com")
        with self.assertRaises(ScopeViolationError):
            policy.validate_target("not a DN")

    def test_multivalued_rdn_order_does_not_change_identity(self):
        from bloodyAD.search_policy import SearchPolicy
        policy = SearchPolicy("OU=Test+CN=Fixture,DC=example,DC=com")
        policy.validate_target("CN=Alice,CN=Fixture+OU=TEST,DC=EXAMPLE,DC=COM")


class ScopedTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_writes_reject_search_scope_even_when_called_directly(self):
        ldap = fake_ldap(OpsecOptions(base_dn="OU=Test,DC=example,DC=com"))
        for operation in (lambda: ldap.bloodydelete("target"),
                          lambda: ldap.bloodyadd("target", attributes={}),
                          lambda: ldap.bloodymodify("target", {"description": [("replace", ["x"])]})):
            with self.assertRaises(ValueError):
                await operation()
        ldap.add.assert_not_awaited()
        ldap.delete.assert_not_awaited()
        ldap.modify.assert_not_awaited()
