"""Raw LDAP writes preserve byte values without consulting attribute codecs."""
import types
import unittest

from badldap.client import MSLDAPClient
from badldap.connection import MSLDAPClientConnection
from badldap.protocol.messages import LDAPMessage, ModifyResponse, protocolOp

from bloodyAD.opsec import OpsecOptions
from tests.test_write_outcomes import fake_ldap

def raw_transport(*, result="success", options=None):
    ldap = fake_ldap(options)
    packets = []
    response = LDAPMessage({"messageID": 1, "protocolOp": protocolOp({"modifyResponse": ModifyResponse({
        "resultCode": result, "matchedDN": b"", "diagnosticMessage": b"test response",
    })})})

    async def send_message(message):
        packet = LDAPMessage({"messageID": 1, **message}).dump()
        packets.append(LDAPMessage.load(packet).native)
        return 1

    async def recv_message(message_id):
        return [response]

    transport = types.SimpleNamespace(send_message=send_message, recv_message=recv_message)
    transport.modify = types.MethodType(MSLDAPClientConnection.modify, transport)
    ldap._con = transport
    ldap.modify = types.MethodType(MSLDAPClient.modify, ldap)
    return ldap, packets

class RawModifyTests(unittest.IsolatedAsyncioTestCase):
    async def test_raw_multivalues_are_serialized_without_single_value_codec(self):
        ldap, packets = raw_transport()
        try:
            outcome = await ldap.bloodymodify("target", {"description": [("replace", [b"first", b"\x00\xff"])]}, encode=False)
        except TypeError:
            self.fail("Raw multi-values were rejected by a schema-guessing codec")
        self.assertEqual(outcome.status, "applied")
        modification = packets[0]["protocolOp"]["changes"][0]["modification"]
        self.assertEqual(modification["type"], b"description")
        self.assertCountEqual(modification["attributes"], [b"first", b"\x00\xff"])

    async def test_raw_empty_values_and_controls_are_preserved(self):
        ldap, packets = raw_transport()
        await ldap.bloodymodify("target", {"description": [("replace", [])]},
                                controls=[("1.2.3.4", True, b"opaque")], encode=False)
        self.assertEqual(packets[0]["protocolOp"]["changes"][0]["modification"]["attributes"], [])
        self.assertEqual(packets[0]["controls"][0],
                         {"controlType": b"1.2.3.4", "criticality": True, "controlValue": b"opaque"})

    async def test_raw_rejected_server_write_never_reports_applied(self):
        from badldap.commons.exceptions import LDAPModifyException
        ldap, packets = raw_transport(result="insufficientAccessRights")
        with self.assertRaises(LDAPModifyException):
            await ldap.bloodymodify("target", {"description": [("replace", [b"first", b"second"])]}, encode=False)
        self.assertEqual(len(packets), 1)

    async def test_raw_dry_run_never_sends_a_packet(self):
        ldap, packets = raw_transport(options=OpsecOptions(dry_run=True))
        outcome = await ldap.bloodymodify("target", {"description": [("replace", [b"first", b"second"])]}, encode=False)
        self.assertEqual(outcome.status, "simulated")
        self.assertEqual(packets, [])

    async def test_raw_nonbytes_are_rejected_before_send(self):
        ldap, packets = raw_transport()
        with self.assertRaises((TypeError, ValueError)):
            await ldap.bloodymodify("target", {"description": [("replace", ["not raw bytes"])]}, encode=False)
        self.assertEqual(packets, [])

    async def test_encoded_path_still_uses_its_existing_codec(self):
        ldap, packets = raw_transport()
        outcome = await ldap.bloodymodify("target", {"description": [("replace", ["normal text"])]})
        self.assertEqual(outcome.status, "applied")
        self.assertEqual(packets[0]["protocolOp"]["changes"][0]["modification"]["attributes"], [b"normal text"])

    async def test_no_response_never_reports_success(self):
        ldap, packets = raw_transport()
        async def empty_response(message_id):
            return []
        ldap._con.recv_message = empty_response
        with self.assertRaises(RuntimeError):
            await ldap.bloodymodify("target", {"description": [("replace", [b"value"])]}, encode=False)
        self.assertEqual(len(packets), 1)

    async def test_invalid_later_attribute_prevents_the_whole_send(self):
        ldap, packets = raw_transport()
        with self.assertRaises(TypeError):
            await ldap.bloodymodify("target", {"description": [("replace", [b"valid"])],
                                                "title": [("replace", ["not bytes"])]}, encode=False)
        self.assertEqual(packets, [])
