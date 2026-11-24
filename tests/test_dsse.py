"""Test cases for "metadata.py"."""

import copy
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from securesystemslib.dsse import Envelope
from securesystemslib.exceptions import VerificationError
from securesystemslib.signer import CryptoSigner, Signature

PEMS_DIR = Path(__file__).parent / "data" / "pems"


class TestEnvelope(unittest.TestCase):
    """Test metadata interface provided by DSSE envelope."""

    @classmethod
    def setUpClass(cls):
        cls.signers: list[CryptoSigner] = []
        for keytype in ["rsa", "ecdsa", "ed25519"]:
            path = PEMS_DIR / f"{keytype}_private.pem"

            with open(path, "rb") as f:
                data = f.read()

            private_key = load_pem_private_key(data, None)
            signer = CryptoSigner(private_key)

            cls.signers.append(signer)

        cls.signature_dict = {
            "keyid": "11fa391a0ed7a447",
            "sig": "MEYCIQCTQuRWZSj87PanpQ==",
        }
        cls.envelope_dict = {
            "payload": "aGVsbG8gd29ybGQ=",
            "payloadType": "http://example.com/HelloWorld",
            "signatures": [cls.signature_dict],
        }
        cls.pae = b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"

    def test_envelope_from_dict_with_duplicate_signatures(self):
        """Test envelope from_dict generates error with duplicate signature keyids"""
        envelope_dict = copy.deepcopy(self.envelope_dict)

        # add duplicate keyid.
        envelope_dict["signatures"].append(copy.deepcopy(self.signature_dict))

        # assert that calling from_dict will raise an error.
        expected_error_message = (
            f"Multiple signatures found for keyid {self.signature_dict['keyid']}"
        )
        with self.assertRaises(ValueError) as context:
            Envelope.from_dict(envelope_dict)

        self.assertEqual(str(context.exception), expected_error_message)

    def test_envelope_from_to_dict(self):
        """Test envelope to_dict and from_dict methods."""

        envelope_dict = copy.deepcopy(self.envelope_dict)

        # create envelope object from its dict.
        envelope_obj = Envelope.from_dict(envelope_dict)
        for signature in envelope_obj.signatures.values():
            self.assertIsInstance(signature, Signature)

        # Assert envelope dict created by to_dict will be equal.
        self.assertDictEqual(self.envelope_dict, envelope_obj.to_dict())

    def test_envelope_eq_(self):
        """Test envelope equality."""

        envelope_obj = Envelope.from_dict(copy.deepcopy(self.envelope_dict))

        # Assert that object and None will not be equal.
        self.assertNotEqual(None, envelope_obj)

        # Assert a copy of envelope_obj will be equal to envelope_obj.
        envelope_obj_2 = copy.deepcopy(envelope_obj)
        self.assertEqual(envelope_obj, envelope_obj_2)

        # Assert that changing the "payload" will make the objects not equal.
        envelope_obj_2.payload = b"wrong_payload"
        self.assertNotEqual(envelope_obj, envelope_obj_2)
        envelope_obj_2.payload = envelope_obj.payload

        # Assert that changing the "payload_type" will make the objects not equal.
        envelope_obj_2.payload_type = "wrong_payload_type"
        self.assertNotEqual(envelope_obj, envelope_obj_2)
        envelope_obj_2.payload = envelope_obj.payload

        # Assert that changing the "signatures" will make the objects not equal.
        sig_obg = Signature("", self.signature_dict["sig"])
        envelope_obj_2.signatures = [sig_obg]
        self.assertNotEqual(envelope_obj, envelope_obj_2)

    def test_envelope_hash(self):
        """Envelopes should be hashable despite the signatures dict."""
        envelope_obj = Envelope.from_dict(copy.deepcopy(self.envelope_dict))
        envelope_obj_2 = copy.deepcopy(envelope_obj)

        # Equal envelopes hash equally and collapse in a set.
        self.assertEqual(hash(envelope_obj), hash(envelope_obj_2))
        self.assertEqual(len({envelope_obj, envelope_obj_2}), 1)

    def test_preauthencoding(self):
        """Test envelope Pre-Auth-Encoding."""

        envelope_obj = Envelope.from_dict(copy.deepcopy(self.envelope_dict))

        # Checking for Pre-Auth-Encoding generated is correct.
        self.assertEqual(self.pae, envelope_obj.pae())

    def test_preauthencoding_non_ascii_payload_type(self):
        """Test that Pre-Auth-Encoding counts payload type length in bytes."""

        envelope_obj = Envelope(b"hello world", "application/vnd.caf\u00e9+json", {})

        # 25 characters, 26 bytes in UTF-8.
        self.assertEqual(
            b"DSSEv1 26 application/vnd.caf\xc3\xa9+json 11 hello world",
            envelope_obj.pae(),
        )

    def test_sign_and_verify(self):
        """Test for creating and verifying DSSE signatures."""

        # Create an Envelope with no signatures.
        envelope_dict = copy.deepcopy(self.envelope_dict)
        envelope_dict["signatures"] = []
        envelope_obj = Envelope.from_dict(envelope_dict)

        key_list = []
        for signer in self.signers:
            envelope_obj.sign(signer)

            # Create a List of "Key" from key_dict.
            key_list.append(signer.public_key)

        # Check for signatures of Envelope.
        self.assertEqual(len(self.signers), len(envelope_obj.signatures))
        for signature in envelope_obj.signatures.values():
            self.assertIsInstance(signature, Signature)

        # Test for invalid threshold value for keys_list.
        # threshold is 0.
        with self.assertRaises(ValueError):
            envelope_obj.verify(key_list, 0)

        # threshold is greater than no of keys.
        with self.assertRaises(ValueError):
            envelope_obj.verify(key_list, 4)

        # Test with valid keylist and threshold.
        verified_keys = envelope_obj.verify(key_list, len(key_list))
        self.assertEqual(len(verified_keys), len(key_list))

        # Test for unknown keys and threshold of 1.
        new_key_list = []
        for key in key_list:
            new_key = copy.deepcopy(key)
            # if it has a different keyid, it is a different key in sslib
            new_key.keyid = reversed(key.keyid)
            new_key_list.append(new_key)

        with self.assertRaises(VerificationError):
            envelope_obj.verify(new_key_list, 1)

        all_keys = key_list + new_key_list
        envelope_obj.verify(all_keys, 3)

        # Test with duplicate keys.
        duplicate_keys = key_list + key_list
        with self.assertRaises(VerificationError):
            envelope_obj.verify(duplicate_keys, 4)  # 3 unique keys, threshold 4.

    def test_verify_rejects_spoofed_keyid(self):
        """A key with a spoofed keyid but foreign public material is rejected."""
        envelope_dict = copy.deepcopy(self.envelope_dict)
        envelope_dict["signatures"] = []
        envelope_obj = Envelope.from_dict(envelope_dict)

        trusted = self.signers[0]
        attacker = CryptoSigner.generate_ed25519()
        envelope_obj.sign(trusted)

        # attacker key copies the trusted keyid but keeps its own public key
        spoofed_key = copy.deepcopy(attacker.public_key)
        spoofed_key.keyid = trusted.public_key.keyid

        with self.assertRaises(VerificationError):
            envelope_obj.verify([spoofed_key], 1)

        # the trusted key still verifies and is cached
        accepted = envelope_obj.verify([trusted.public_key], 1)
        self.assertEqual(accepted, {trusted.public_key.keyid: trusted.public_key})

    def test_verify_failure_does_not_overwrite_trusted_cache(self):
        """A failed verification never removes or overwrites a cached key."""
        envelope_dict = copy.deepcopy(self.envelope_dict)
        envelope_dict["signatures"] = []
        envelope_obj = Envelope.from_dict(envelope_dict)

        trusted = self.signers[0]
        attacker = CryptoSigner.generate_ed25519()
        envelope_obj.sign(trusted)

        spoofed_key = copy.deepcopy(attacker.public_key)
        spoofed_key.keyid = trusted.public_key.keyid

        # the spoofed key fails but must not replace the trusted key
        accepted = envelope_obj.verify(
            [trusted.public_key, spoofed_key], 1
        )
        self.assertEqual(
            accepted, {trusted.public_key.keyid: trusted.public_key}
        )

    def test_verify_rejects_distinct_keys_with_same_keyid(self):
        """Two distinct keys claiming one keyid can't collapse in the cache."""
        envelope_dict = copy.deepcopy(self.envelope_dict)
        envelope_dict["signatures"] = []
        envelope_obj = Envelope.from_dict(envelope_dict)

        # two independent keys, forced to share an identity-bound keyid label
        first = CryptoSigner.generate_ed25519()
        second = CryptoSigner.generate_ed25519()
        envelope_obj.sign(first)

        # make second's signature and key look like first's keyid
        second_sig = second.sign(envelope_obj.pae())
        second_sig.keyid = first.public_key.keyid
        envelope_obj.signatures[first.public_key.keyid] = second_sig

        second_key = copy.deepcopy(second.public_key)
        second_key.keyid = first.public_key.keyid

        with self.assertRaises(VerificationError):
            envelope_obj.verify([first.public_key, second_key], 1)


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
