import unittest
from bloodyAD.network.config import Config


class ConfigurationTests(unittest.TestCase):
    def test_single_windows_certificate_path_is_not_split_at_drive_letter(self):
        config = Config(host="dc", dcip="127.0.0.1", certificate=r"C:\certs\identity.pfx")
        self.assertEqual(config.crt, r"C:\certs\identity.pfx")
        self.assertEqual(config.key, "")

    def test_windows_key_certificate_pair_preserves_both_drive_letters(self):
        config = Config(host="dc", dcip="127.0.0.1",
                        certificate=r"C:\certs\key.pem:C:\certs\identity.pem")
        self.assertEqual(config.key, r"C:\certs\key.pem")
        self.assertEqual(config.crt, r"C:\certs\identity.pem")

    def test_password_containing_multiple_colons_remains_a_password(self):
        config = Config(host="dc", dcip="127.0.0.1", password="one:two:three")
        self.assertEqual(config.password, "one:two:three")
        self.assertEqual(config.nthash, "")
