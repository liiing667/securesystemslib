"""Test cases for "metadata.py"."""

import copy
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from securesystemslib.dsse import Envelope
from securesystemslib.exceptions import (
    UnverifiedSignatureError,
    VerificationError,
)
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

    def test_verify_rejects_non_dict_signatures(self):
        """verify() must not trust an envelope whose signatures are not a
        keyid -> Signature dict (e.g. a raw list, bypassing from_dict)."""
        envelope_obj = Envelope.from_dict(copy.deepcopy(self.envelope_dict))
        signature = next(iter(envelope_obj.signatures.values()))
        dummy_key = self.signers[0].public_key

        evil_envelope = Envelope(
            envelope_obj.payload,
            envelope_obj.payload_type,
            [signature, signature],
        )
        with self.assertRaisesRegex(ValueError, "keyid to Signature"):
            evil_envelope.verify([dummy_key], 1)

    def test_verify_rejects_inconsistent_signature_keyid(self):
        """A Signature whose own keyid does not match its mapping key must
        never be accepted."""
        envelope_obj = Envelope.from_dict(copy.deepcopy(self.envelope_dict))
        signature = next(iter(envelope_obj.signatures.values()))

        evil_envelope = Envelope(
            envelope_obj.payload,
            envelope_obj.payload_type,
            {"some-other-keyid": signature},
        )
        dummy_key = self.signers[0].public_key
        with self.assertRaisesRegex(ValueError, "does not match"):
            evil_envelope.verify([dummy_key], 1)

    def test_verify_unknown_signer_cannot_reach_threshold(self):
        """Signatures by unknown signers can never count towards the
        threshold, even when they outnumber the trusted signatures."""
        envelope_dict = copy.deepcopy(self.envelope_dict)
        envelope_dict["signatures"] = []
        envelope_obj = Envelope.from_dict(envelope_dict)

        # One legitimate signature, plus two signatures with unknown keyids.
        envelope_obj.sign(self.signers[0])
        unknown_sigs = {}
        for i in range(2):
            sig = self.signers[1].sign(envelope_obj.pae())
            sig.keyid = f"unknown-signer-{i}"
            unknown_sigs[sig.keyid] = sig
        envelope_obj.signatures.update(unknown_sigs)

        # Two trusted keys are provided, but only the first one has a
        # matching signature in the envelope: the unknown signers must not
        # fill the gap.
        trusted_keys = [signer.public_key for signer in self.signers[:2]]

        # Threshold 2 with only one trusted key must fail.
        with self.assertRaises(VerificationError):
            envelope_obj.verify(trusted_keys, 2)

        # Threshold 1 with the trusted key must pass: unknown signers are
        # simply ignored rather than counted.
        accepted = envelope_obj.verify(trusted_keys, 1)
        self.assertEqual(list(accepted), [trusted_keys[0].keyid])

    def test_verify_duplicate_keyid_counts_only_once(self):
        """A single trusted keyid can only count once, regardless of how
        often it appears in the caller-provided key list."""
        envelope_dict = copy.deepcopy(self.envelope_dict)
        envelope_dict["signatures"] = []
        envelope_obj = Envelope.from_dict(envelope_dict)
        envelope_obj.sign(self.signers[0])

        key = self.signers[0].public_key
        another_key = self.signers[1].public_key
        with self.assertRaises(VerificationError):
            envelope_obj.verify([key, key, key, another_key], 2)

        accepted = envelope_obj.verify([key, key, key], 1)
        self.assertEqual(list(accepted), [key.keyid])

    def test_verify_requires_pae_and_signature_to_close(self):
        """A valid signature only verifies against the envelope's own PAE:
        tampering with payload or payload type breaks the closure."""
        envelope_dict = copy.deepcopy(self.envelope_dict)
        envelope_dict["signatures"] = []
        envelope_obj = Envelope.from_dict(envelope_dict)
        envelope_obj.sign(self.signers[0])
        key = self.signers[0].public_key

        tampered_payload = Envelope(
            b"tampered payload",
            envelope_obj.payload_type,
            copy.deepcopy(envelope_obj.signatures),
        )
        with self.assertRaises(VerificationError):
            tampered_payload.verify([key], 1)

        tampered_type = Envelope(
            envelope_obj.payload,
            "http://example.com/TamperedType",
            copy.deepcopy(envelope_obj.signatures),
        )
        with self.assertRaises(VerificationError):
            tampered_type.verify([key], 1)

    def test_verify_failure_does_not_into_later_run(self):
        """A failed verification leaves no state behind: the next run starts
        fresh and an independently valid envelope still verifies."""
        envelope_dict = copy.deepcopy(self.envelope_dict)
        envelope_dict["signatures"] = []
        envelope_obj = Envelope.from_dict(envelope_dict)
        envelope_obj.sign(self.signers[0])
        key = self.signers[0].public_key
        another_key = self.signers[1].public_key

        # First run fails: threshold cannot be met with one signature.
        with self.assertRaises(VerificationError):
            envelope_obj.verify([key, another_key], 2)

        # Second run with an achievable threshold succeeds independently.
        accepted = envelope_obj.verify([key], 1)
        self.assertEqual(list(accepted), [key.keyid])

        # A failed run against tampered data must not poison a subsequent
        # verification of the intact envelope.
        tampered = Envelope(
            b"tampered payload",
            envelope_obj.payload_type,
            copy.deepcopy(envelope_obj.signatures),
        )
        with self.assertRaises(VerificationError):
            tampered.verify([key], 1)
        accepted = envelope_obj.verify([key], 1)
        self.assertEqual(list(accepted), [key.keyid])

    def test_verify_valid_multi_signature_still_passes(self):
        """Legitimate multi-signer envelopes at various thresholds verify."""
        envelope_dict = copy.deepcopy(self.envelope_dict)
        envelope_dict["signatures"] = []
        envelope_obj = Envelope.from_dict(envelope_dict)

        key_list = []
        for signer in self.signers:
            envelope_obj.sign(signer)
            key_list.append(signer.public_key)

        for threshold in range(1, len(key_list) + 1):
            accepted = envelope_obj.verify(key_list, threshold)
            self.assertEqual(len(accepted), threshold)

    def test_verify_key_that_raises_non_verification_error(self):
        """A broken key implementation cannot make a signature count: only a
        clean verification of PAE + signature value is accepted."""

        envelope_dict = copy.deepcopy(self.envelope_dict)
        envelope_dict["signatures"] = []
        envelope_obj = Envelope.from_dict(envelope_dict)
        signature = envelope_obj.sign(self.signers[0])

        class ExplodingKey:
            keyid = signature.keyid

            def verify_signature(self, sig, data):
                raise UnverifiedSignatureError("never valid")

        with self.assertRaises(VerificationError):
            envelope_obj.verify([ExplodingKey()], 1)

    def test_verify_contract_violating_key_does_not_crash_verification(self):
        """If a Key implementation raises an exception outside the
        UnverifiedSignatureError contract, public verification must treat it
        as a failed signature rather than accepting it or leaking state."""
        envelope_dict = copy.deepcopy(self.envelope_dict)
        envelope_dict["signatures"] = []
        envelope_obj = Envelope.from_dict(envelope_dict)
        signature = envelope_obj.sign(self.signers[0])
        good_key = self.signers[0].public_key

        class BadContractKey:
            keyid = signature.keyid

            def verify_signature(self, sig, data):
                raise RuntimeError("broken key implementation")

        # A non-contract exception counts as a failed signature, so the
        # threshold cannot be reached with the broken implementation alone.
        with self.assertRaises(VerificationError):
            envelope_obj.verify([BadContractKey()], 1)

        # A subsequent, independent run with the genuine key is unaffected:
        # the previous failure leaves no state behind.
        accepted = envelope_obj.verify([good_key], 1)
        self.assertEqual(list(accepted), [good_key.keyid])


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
