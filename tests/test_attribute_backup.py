import unittest
import argparse
import asyncio
from unittest.mock import AsyncMock


class BackupCodecTests(unittest.TestCase):
    def test_sensitive_backup_is_rejected_before_connection(self):
        from bloodyAD.opsec import OpsecOptions
        from bloodyAD.cli_modules import set as setter
        conn = argparse.Namespace(options=OpsecOptions(rollback_file="unused.jsonl"), getLdap=AsyncMock())
        with self.assertRaises(ValueError):
            asyncio.run(setter.object(conn, "user", "unicodePwd", ["CANARY"], bak=True))
        conn.getLdap.assert_not_awaited()

    def test_mixed_binary_text_and_quoting_roundtrip_without_shell(self):
        from bloodyAD.rollback import encode_values, decode_values
        values = [b"text", b"\x00\xff", "O'Brien", "日本語", 42]
        encoded = encode_values(values)
        self.assertEqual(encoded[0], {"type": "bytes", "value": "dGV4dA=="})
        self.assertEqual(encoded[1], {"type": "bytes", "value": "AP8="})
        self.assertEqual(decode_values(encoded), values)

    def test_invalid_binary_payload_is_rejected(self):
        from bloodyAD.rollback import decode_values
        with self.assertRaises(ValueError):
            decode_values([{"type": "bytes", "value": "not base64!"}])
