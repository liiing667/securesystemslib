"""Test cases for "metadata.py"."""

import copy
import threading
import time
import unittest
from pathlib import Path
from threading import Barrier

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

    def test_sign_failure_does_not_leave_partial_signature(self):
        """If signing fails, the envelope must keep its previous state.

        A retry with the same trusted signer then succeeds.
        """
        signer = self.signers[0]
        envelope = Envelope(b"hello world", "http://example.com/HelloWorld", {})

        class FlakySigner(CryptoSigner):
            def __init__(self, real_signer):
                super().__init__(real_signer._private_key, real_signer.public_key)
                self.attempts = 0

            def _sign(self, payload):
                self.attempts += 1
                if self.attempts == 1:
                    raise RuntimeError("signer failed mid-way")
                return super()._sign(payload)

        flaky = FlakySigner(signer)

        # The failing attempt must not commit a half signature.
        with self.assertRaises(RuntimeError):
            envelope.sign(flaky)
        self.assertEqual(envelope.signatures, {})

        # Retrying with the same trusted key commits exactly one signature.
        signature = envelope.sign(flaky)
        self.assertEqual(flaky.attempts, 2)
        self.assertEqual(
            envelope.signatures, {signer.public_key.keyid: signature}
        )
        envelope.verify([signer.public_key], 1)

    def test_sign_failure_preserves_existing_signatures(self):
        """Pre-existing envelope signatures survive a later failing sign."""
        good_signer = self.signers[0]
        failing_signer = self.signers[1]

        envelope = Envelope(b"hello world", "http://example.com/HelloWorld", {})
        first_sig = envelope.sign(good_signer)
        state_before = copy.deepcopy(envelope.signatures)

        class FailingSigner(CryptoSigner):
            def _sign(self, payload):
                raise RuntimeError("signer failed mid-way")

        with self.assertRaises(RuntimeError):
            envelope.sign(
                FailingSigner(
                    failing_signer._private_key, failing_signer.public_key
                )
            )

        # The old signature and key state are untouched.
        self.assertEqual(envelope.signatures, state_before)
        self.assertEqual(
            envelope.signatures[good_signer.public_key.keyid], first_sig
        )

    def test_concurrent_signing_each_signature_committed_once(self):
        """Concurrent sign() calls with distinct keys all commit atomically."""
        envelope = Envelope(b"hello world", "http://example.com/HelloWorld", {})

        class SlowSigner(CryptoSigner):
            def _sign(self, payload):
                time.sleep(0.01)
                return super()._sign(payload)

        signers = [
            SlowSigner(s._private_key, s.public_key) for s in self.signers
        ]
        barrier = Barrier(len(signers))
        errors = []

        def worker(signer):
            barrier.wait()
            try:
                envelope.sign(signer)
            except Exception as e:  # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(s,)) for s in signers]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        # exactly one complete signature per trusted key, no partial entries
        self.assertEqual(len(envelope.signatures), len(signers))
        self.assertEqual(
            set(envelope.signatures),
            {s.public_key.keyid for s in signers},
        )
        envelope.verify([s.public_key for s in signers], len(signers))

    def test_envelope_is_deepcopyable_with_lock(self):
        """The internal lock must not break copying the envelope."""
        envelope = Envelope(b"hello world", "http://example.com/HelloWorld", {})
        envelope.sign(self.signers[0])

        clone = copy.deepcopy(envelope)
        self.assertEqual(clone.signatures, envelope.signatures)
        clone.sign(self.signers[1])
        self.assertEqual(len(clone.signatures), 2)


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
