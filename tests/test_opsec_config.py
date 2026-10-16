import argparse
import unittest
from unittest.mock import AsyncMock, patch

from bloodyAD import opsec


class OptionsTests(unittest.IsolatedAsyncioTestCase):
    def test_explicit_empty_boundary_is_rejected(self):
        with self.assertRaises(ValueError):
            opsec.OpsecOptions(base_dn="")

    def test_invalid_numbers_are_rejected_instead_of_silently_clamped(self):
        for field, value in (("sleep", -1), ("sleep", float("nan")),
                             ("sleep", float("inf")), ("jitter", -0.1),
                             ("jitter", 1.1), ("chunk", 1), ("chunk", -1)):
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    opsec.OpsecOptions.from_namespace(argparse.Namespace(**{field: value}))

    def test_options_do_not_share_mutable_state(self):
        first = opsec.OpsecOptions.from_namespace(argparse.Namespace(no_tombstone=True))
        second = opsec.OpsecOptions()
        self.assertIn(opsec.LDAP_SERVER_SHOW_DELETED_OID, first.strip_controls)
        self.assertEqual(second.strip_controls, frozenset())

    async def test_disabled_delay_does_not_wait(self):
        with patch.object(opsec.asyncio, "sleep", new_callable=AsyncMock) as sleep:
            await opsec.OpsecOptions().pause()
        sleep.assert_not_awaited()

    async def test_existing_delay_stays_inside_requested_bounds(self):
        options = opsec.OpsecOptions(sleep=2, jitter=0.3)
        with patch.object(opsec.random, "uniform", return_value=1.4) as rng:
            with patch.object(opsec.asyncio, "sleep", new_callable=AsyncMock) as sleep:
                await options.pause()
        rng.assert_called_once_with(1.4, 2.6)
        sleep.assert_awaited_once_with(1.4)
