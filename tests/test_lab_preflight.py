import unittest
from unittest.mock import AsyncMock, patch


class LabPreflightTests(unittest.IsolatedAsyncioTestCase):
    async def test_authentication_failure_is_a_failure_not_an_adcs_skip(self):
        from tests.support import LabConfig, probe_lab
        config = LabConfig(password="CANARY")
        with patch("tests.support.ConnectionHandler") as handler:
            handler.return_value.getLdap = AsyncMock(side_effect=PermissionError("denied"))
            handler.return_value.closeLdap = AsyncMock()
            with self.assertRaises(PermissionError):
                await probe_lab(config)
        handler.return_value.closeLdap.assert_awaited_once()
