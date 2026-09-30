import os
import tempfile
import unittest
from unittest import mock

from securevault import storage, strength
from securevault.cli import main
from securevault.vault import (AmbiguousEntryError, EntryExistsError,
                               EntryNotFoundError, ValidationError, Vault)

FAST = 1000

class StorageTests(unittest.TestCase):
    def test_round_trip(self):
        blob = storage.encrypt_bytes(b"secret data" * 10, "pw", FAST)
        self.assertEqual(storage.decrypt_bytes(blob, "pw"), b"secret data" * 10)

    def test_wrong_password_rejected(self):
        blob = storage.encrypt_bytes(b"data", "right", FAST)
        with self.assertRaises(storage.WrongPasswordError):
            storage.decrypt_bytes(blob, "wrong")

    def test_tampering_detected(self):
        blob = bytearray(storage.encrypt_bytes(b"data", "pw", FAST))
        blob[storage.HEADER_LEN] ^= 1
        with self.assertRaises(storage.WrongPasswordError):
            storage.decrypt_bytes(bytes(blob), "pw")

    def test_not_a_vault(self):
        with self.assertRaises(storage.CorruptFileError):
            storage.decrypt_bytes(b"hello world" * 10, "pw")

    def test_salt_makes_output_unique(self):
        a = storage.encrypt_bytes(b"same", "pw", FAST)
        b = storage.encrypt_bytes(b"same", "pw", FAST)
        self.assertNotEqual(a, b)

    def test_plaintext_not_on_disk(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "v.svlt")
            storage.save_vault(path, {"entries": [{"password": "Hunter2Secret"}]}, "pw")
            with open(path, "rb") as handle:
                self.assertNotIn(b"Hunter2Secret", handle.read())

class StrengthTests(unittest.TestCase):
    def test_generator_respects_options(self):
        pw = strength.generate_password(20, use_symbols=False)
        self.assertEqual(len(pw), 20)
        self.assertTrue(pw.isalnum())
        self.assertTrue(any(c.isdigit() for c in pw))

    def test_generator_rejects_bad_options(self):
        with self.assertRaises(strength.PasswordGenerationError):
            strength.generate_password(4)
        with self.assertRaises(strength.PasswordGenerationError):
            strength.generate_password(12, False, False, False, False)

    def test_ratings(self):
        self.assertEqual(strength.check_strength("password123").rating, "Weak")
        self.assertEqual(strength.check_strength("P@ssw0rd").rating, "Weak")
        self.assertEqual(strength.check_strength("abc").rating, "Weak")
        self.assertEqual(strength.check_strength("Tr0ub4dor&3").rating, "Medium")
        self.assertEqual(strength.check_strength("Xk9#mP2$vL7qRw").rating, "Strong")

    def test_suggestions_given(self):
        self.assertTrue(strength.check_strength("abcdefgh").suggestions)

class VaultTests(unittest.TestCase):
    def setUp(self):
        self.v = Vault()
        self.v.add("GitHub", "alice", "pw-1")

    def test_add_get_case_insensitive(self):
        self.assertEqual(self.v.get("github").username, "alice")

    def test_duplicate_rejected(self):
        with self.assertRaises(EntryExistsError):
            self.v.add("github", "ALICE", "x")

    def test_validation(self):
        with self.assertRaises(ValidationError):
            self.v.add("", "u", "p")
        with self.assertRaises(ValidationError):
            self.v.add("site", "u", "")

    def test_update_and_delete(self):
        self.v.update("github", password="new")
        self.assertEqual(self.v.get("github").password, "new")
        self.v.delete("github")
        with self.assertRaises(EntryNotFoundError):
            self.v.get("github")

    def test_ambiguous(self):
        self.v.add("github", "bob", "pw-2")
        with self.assertRaises(AmbiguousEntryError):
            self.v.get("github")
        self.assertEqual(self.v.get("github", "bob").password, "pw-2")

    def test_audit(self):
        self.v.add("mail", "alice", "Same#Pass_998877xy")
        self.v.add("bank", "alice", "Same#Pass_998877xy")
        self.v.add("blog", "alice", "password")
        report = self.v.audit()
        self.assertEqual(len(report["reused"]), 1)
        weak_sites = {e.site for e, _ in report["weak"]}
        self.assertIn("blog", weak_sites)

    def test_serialisation(self):
        again = Vault.from_dict(self.v.to_dict())
        self.assertEqual(again.get("github").password, "pw-1")

class CLITests(unittest.TestCase):
    def run_cli(self, argv, passwords=()):
        with mock.patch("getpass.getpass", side_effect=list(passwords)):
            return main(argv)

    def test_full_workflow(self):
        master = "Correct-Horse-Battery-9"
        with tempfile.TemporaryDirectory() as d:
            vp = ["--vault", os.path.join(d, "v.svlt")]
            self.assertEqual(self.run_cli(["init"] + vp, [master, master]), 0)
            self.assertEqual(self.run_cli(["add", "site", "me", "Xk9#mP2$vL7qRw"] + vp, [master]), 0)
            self.assertEqual(self.run_cli(["get", "site"] + vp, [master]), 0)
            self.assertEqual(self.run_cli(["list"] + vp, [master]), 0)
            self.assertEqual(self.run_cli(["get", "site"] + vp, ["wrong"]), 1)
            self.assertEqual(self.run_cli(["delete", "site", "-y"] + vp, [master]), 0)
            self.assertEqual(self.run_cli(["get", "site"] + vp, [master]), 1)

    def test_weak_master_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            vp = ["--vault", os.path.join(d, "v.svlt")]
            self.assertEqual(self.run_cli(["init"] + vp, ["password123", "password123"]), 1)

if __name__ == "__main__":
    unittest.main()
