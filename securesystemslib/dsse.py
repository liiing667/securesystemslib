"""Dead Simple Signing Envelope"""

from __future__ import annotations

import logging
from typing import Any

from securesystemslib import exceptions
from securesystemslib._internal.utils import b64dec, b64enc, make_hashable
from securesystemslib.signer import Key, Signature, Signer

logger = logging.getLogger(__name__)


class Envelope:
    """DSSE Envelope to provide interface for signing arbitrary data.

    Attributes:
        payload: Arbitrary byte sequence of serialized body.
        payload_type: string that identifies how to interpret payload.
        signatures: dict of Signature key id and Signatures.

    """

    def __init__(
        self,
        payload: bytes,
        payload_type: str,
        signatures: dict[str, Signature],
    ):
        self.payload = payload
        self.payload_type = payload_type
        self.signatures = signatures

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Envelope):
            return False

        return (
            self.payload == other.payload
            and self.payload_type == other.payload_type
            and self.signatures == other.signatures
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.payload,
                self.payload_type,
                make_hashable(self.signatures),
            )
        )

    @classmethod
    def from_dict(cls, data: dict) -> Envelope:
        """Creates a DSSE Envelope from its JSON/dict representation.

        Arguments:
            data: A dict containing a valid payload, payloadType and signatures

        Raises:
            KeyError: If any of the "payload", "payloadType" and "signatures"
                fields are missing from the "data".

            FormatError: If signature in "signatures" is incorrect.

        Returns:
            A "Envelope" instance.
        """

        payload = b64dec(data["payload"])
        payload_type = data["payloadType"]

        signatures = {}
        for signature in data["signatures"]:
            signature["sig"] = b64dec(signature["sig"]).hex()
            sig = Signature.from_dict(signature)
            if sig.keyid in signatures:
                raise ValueError(f"Multiple signatures found for keyid {sig.keyid}")
            signatures[sig.keyid] = sig
        return cls(payload, payload_type, signatures)

    def to_dict(self) -> dict:
        """Returns the JSON-serializable dictionary representation of self."""

        signatures = []
        for signature in self.signatures.values():
            sig_dict = signature.to_dict()
            sig_dict["sig"] = b64enc(bytes.fromhex(sig_dict["sig"]))
            signatures.append(sig_dict)

        return {
            "payload": b64enc(self.payload),
            "payloadType": self.payload_type,
            "signatures": signatures,
        }

    def pae(self) -> bytes:
        """Pre-Auth-Encoding byte sequence of self."""

        payload_type = self.payload_type.encode("utf-8")
        return b"DSSEv1 %d %b %d %b" % (
            len(payload_type),
            payload_type,
            len(self.payload),
            self.payload,
        )

    def sign(self, signer: Signer) -> Signature:
        """Sign the payload and create the signature.

        Arguments:
            signer: A "Signer" class instance.

        Returns:
            A "Signature" instance.
        """

        signature = signer.sign(self.pae())
        self.signatures[signature.keyid] = signature

        return signature

    def verify(self, keys: list[Key], threshold: int) -> dict[str, Key]:
        """Verify the payload with the provided Keys.

        Arguments:
            keys: A list of public keys to verify the signatures.
            threshold: Number of signatures needed to pass the verification.

        Raises:
            ValueError: If "threshold" is not valid, or if the envelope
                signatures are not represented as a dict of keyid to
                Signature.
            VerificationError: If the enclosed signatures do not pass the
                verification.

        Note:
            Mandating keyid in signatures and matching them with keyid of Key
            in order to consider them for verification, is not DSSE spec
            compliant (Issue #416).

        Returns:
            A dict of the threshold of unique public keys that verified a
            signature.
        """

        # checks for threshold value.
        if threshold <= 0:
            raise ValueError("Threshold must be greater than 0")

        if len(keys) < threshold:
            raise ValueError("Number of keys can't be less than threshold")

        # The envelope structure is part of the public API: refuse to verify
        # anything that is not a mapping of keyid -> Signature. Without this
        # check a malformed envelope (e.g. a list of signatures, or multiple
        # signatures sharing a keyid) could be fed to verify() directly and
        # bypass the duplicate-keyid protection in from_dict().
        if not isinstance(self.signatures, dict) or not all(
            isinstance(keyid, str) and isinstance(sig, Signature)
            for keyid, sig in self.signatures.items()
        ):
            raise ValueError(
                "Signatures must be a dict of keyid to Signature instances"
            )

        # Deduplicate trusted keys by keyid: one keyid can only ever count
        # once towards the threshold, even if the caller passes it repeatedly.
        trusted_keys: dict[str, Key] = {}
        for key in keys:
            trusted_keys.setdefault(key.keyid, key)

        # Every verification run starts from a fresh state: results of a
        # previous (possibly failed) verify() call are never inherited.
        accepted_keys: dict[str, Key] = {}

        # Recompute the PAE for this exact envelope on every run. A signature
        # is only accepted if the signature value cryptographically closes over
        # this PAE under a trusted key; the keyid match alone is never enough.
        pae = self.pae()

        for sig_keyid, signature in self.signatures.items():
            # The mapping key and the Signature's own keyid must be consistent.
            if sig_keyid != signature.keyid:
                raise ValueError(
                    f"Signature keyid '{signature.keyid}' does not match "
                    f"the envelope mapping key '{sig_keyid}'"
                )

            # Signatures by unknown signers are ignored: they can never
            # contribute to the threshold because no trusted key exists to
            # close the PAE/signature pair.
            key = trusted_keys.get(signature.keyid)
            if key is None:
                continue

            # Accept only when PAE and signature value verify together.
            try:
                key.verify_signature(signature, pae)
            except Exception:
                # UnverifiedSignatureError is the documented failure signal;
                # a custom Key that raises something else must never make a
                # non-closed signature count either. The failure is confined
                # to this (key, signature) pair and cannot leak into later
                # iterations or later verify() runs.
                continue

            # Count each unique trusted keyid at most once.
            accepted_keys[key.keyid] = key

            if len(accepted_keys) >= threshold:
                break

        if len(accepted_keys) < threshold:
            raise exceptions.VerificationError(
                "Accepted signatures do not match threshold,"
                f" Found: {len(accepted_keys)}, Expected {threshold}"
            )

        return accepted_keys
