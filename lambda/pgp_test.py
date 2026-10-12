"""pgp.py against GnuPG: gpg imports the key, finds the same fingerprint and
WKD file name, and verifies the signatures. Without gpg or the cryptography
package these tests are skipped."""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pgp

GPG = shutil.which("gpg")
try:
    import cryptography  # noqa: F401  the Lambda layer has it
    CRYPTOGRAPHY = True
except ImportError:
    CRYPTOGRAPHY = False
ADDRESS = "sunny-raven-80@hide.example.com"


def make_key(address=ADDRESS, created=1760000000):
    return pgp.SigningKey(hashlib.sha256(address.encode()).digest(), created, address)


@unittest.skipUnless(GPG and CRYPTOGRAPHY, "needs gpg and the cryptography package")
class GnupgTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="pgp-test-")
        self.addCleanup(shutil.rmtree, self.home, True)
        self.key = make_key()
        self.gpg("--import", data=self.key.public_key())

    def gpg(self, *args, data=None):
        result = subprocess.run([GPG, "--homedir", self.home, "--batch", "--status-fd", "1", *args], input=data, capture_output=True)
        return result.returncode, result.stdout.decode(errors="replace")

    def test_gpg_takes_the_key_as_it_is(self):
        status, out = self.gpg("--with-colons", "--fingerprint", "--with-wkd-hash", ADDRESS)
        self.assertEqual(status, 0, out)
        lines = [line.split(":") for line in out.splitlines()]
        self.assertEqual(next(line[9] for line in lines if line[0] == "fpr"), self.key.fingerprint.hex().upper())
        public = next(line for line in lines if line[0] == "pub")
        self.assertEqual((public[3], public[6], public[11]), ("22", "", "scSC"), "EdDSA, no expiry, certify and sign")
        self.assertEqual(next(line[9] for line in lines if line[0] == "uid"), ADDRESS, "the self-signature is valid")
        _, listing = self.gpg("--with-wkd-hash", "--list-keys", ADDRESS)
        self.assertIn(f"{pgp.wkd_hash('sunny-raven-80')}@hide.example.com", listing)

    def test_gpg_verifies_the_signatures(self):
        for number in range(60):
            data = f"message {number}\r\n".encode() + os.urandom(number * 37)
            signature = self.key.sign(data)
            with tempfile.NamedTemporaryFile(dir=self.home, delete=False) as handle:
                handle.write(data)
            status, out = self.gpg("--verify", "-", handle.name, data=signature.encode())
            self.assertEqual(status, 0, out)
            self.assertIn(f"VALIDSIG {self.key.fingerprint.hex().upper()}", out)

    def test_a_changed_message_fails(self):
        data = b"Hello\r\n"
        signature = self.key.sign(data)
        with tempfile.NamedTemporaryFile(dir=self.home, delete=False) as handle:
            handle.write(b"Hello!\r\n")
        status, out = self.gpg("--verify", "-", handle.name, data=signature.encode())
        self.assertNotEqual(status, 0)
        self.assertIn("BADSIG", out)


@unittest.skipUnless(CRYPTOGRAPHY, "needs the cryptography package")
class KeyTest(unittest.TestCase):
    def test_the_same_seed_and_time_make_the_same_key(self):
        self.assertEqual(make_key().public_key(), make_key().public_key())
        self.assertNotEqual(make_key().fingerprint, make_key(created=1760000001).fingerprint)

    def test_the_armored_key_has_its_frame(self):
        armored = make_key().armored_public_key()
        self.assertTrue(armored.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n\r\n"))
        self.assertTrue(armored.rstrip().endswith("-----END PGP PUBLIC KEY BLOCK-----"))


class WkdTest(unittest.TestCase):
    def test_the_example_of_the_draft(self):
        # draft-koch-openpgp-webkey-service, section 3.1: Joe.Doe@Example.ORG
        self.assertEqual(pgp.wkd_hash("Joe.Doe"), "iy9q119eutrkn8s1mk4r39qejnbu3n5q")

    def test_crc24_starts_at_its_initial_value(self):
        self.assertEqual(pgp.crc24(b""), 0xB704CE)


if __name__ == "__main__":
    unittest.main()
