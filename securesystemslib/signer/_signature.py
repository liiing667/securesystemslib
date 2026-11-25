"""Signature container class"""

from __future__ import annotations

import logging
import re
from typing import Any

from securesystemslib._internal.utils import make_hashable

logger = logging.getLogger(__name__)

_HEX_RE = re.compile(r"[0-9a-f]*\Z")
_SENSITIVE_FIELD_PARTS = ("private", "passphrase", "password", "secret")


class Signature:
    """A container class containing information about a signature.

    Contains a signature and the keyid uniquely identifying the key used
    to generate the signature.

    Provides utility methods to easily create an object from a dictionary
    and return the dictionary representation of the object.

    Args:
        keyid: HEX string used as a unique identifier of the key.
        sig: HEX string representing the signature.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by securesystemslib.

    Attributes:
        keyid: HEX string used as a unique identifier of the key.
        signature: HEX string representing the signature.
        unrecognized_fields: Dictionary of all attributes that are not managed
            by securesystemslib.

    """

    def __init__(
        self,
        keyid: str,
        sig: str,
        unrecognized_fields: dict[str, Any] | None = None,
    ):
        self.keyid = keyid
        self.signature = sig

        if unrecognized_fields is None:
            unrecognized_fields = {}

        # Keep the caller's mapping independent from this instance.
        self.unrecognized_fields = dict(unrecognized_fields)

    @property
    def signature_bytes(self) -> bytes:
        """The canonical signature bytes represented by :attr:`signature`."""
        return bytes.fromhex(self.signature)

    @property
    def algorithm(self) -> Any:
        """Algorithm binding supplied as an extension field, if present.

        Signature dictionaries traditionally carry only ``keyid`` and ``sig``.
        Callers that need an explicit algorithm binding may supply either
        ``algorithm`` or the DSSE-style ``alg`` extension; it remains stored in
        :attr:`unrecognized_fields` and is included in serialization.
        """
        fields = self.unrecognized_fields
        if "algorithm" in fields:
            return fields["algorithm"]
        return fields.get("alg")

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Signature):
            return False

        return (
            self.keyid == other.keyid
            and self.signature == other.signature
            and self.unrecognized_fields == other.unrecognized_fields
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.keyid,
                self.signature,
                make_hashable(self.unrecognized_fields),
            )
        )

    @classmethod
    def from_dict(cls, signature_dict: dict) -> Signature:
        """Creates a Signature object from its JSON/dict representation.

        Arguments:
            signature_dict:
                A dict containing a valid keyid and a signature.
                Note that the fields in it should be named "keyid" and "sig"
                respectively.

        Raises:
            KeyError: If any of the "keyid" and "sig" fields are missing from
                the signature_dict.
            ValueError: If "sig" is not canonical lowercase hexadecimal, or if
                an extension field appears to contain private key material.

        Returns:
            A "Signature" instance.
        """

        # Read before constructing anything.  In particular, never pop fields
        # from the caller's dict: a missing/invalid second field must not leave
        # a partially destroyed input dictionary behind.
        keyid = signature_dict["keyid"]
        sig = signature_dict["sig"]

        if not isinstance(keyid, str):
            raise ValueError("Signature keyid must be a string")

        if not isinstance(sig, str) or _HEX_RE.fullmatch(sig) is None:
            raise ValueError(
                "Signature sig must be canonical lowercase hexadecimal bytes"
            )

        # bytes.hex() is the canonical encoding: lowercase, even-length and
        # free of whitespace and prefixes.  Keep the round-trip check explicit
        # because bytes.fromhex() itself is more permissive.
        try:
            signature_bytes = bytes.fromhex(sig)
        except ValueError as exc:
            raise ValueError("Signature sig is not valid hexadecimal") from exc
        canonical_sig = signature_bytes.hex()
        if sig != canonical_sig:
            raise ValueError("Signature sig must use canonical lowercase hex")

        unrecognized_fields = {
            key: value
            for key, value in signature_dict.items()
            if key not in ("keyid", "sig")
        }

        for key in unrecognized_fields:
            if not isinstance(key, str):
                continue
            normalized_key = key.lower()
            if any(part in normalized_key for part in _SENSITIVE_FIELD_PARTS):
                raise ValueError(
                    f"Signature field {key!r} appears to contain private "
                    "material and is not accepted"
                )

        # All validation and copying is complete before the instance is
        # created, so a failure cannot publish a half-initialized Signature.
        return cls(keyid, canonical_sig, unrecognized_fields)

    def to_dict(self) -> dict:
        """Returns the JSON-serializable dictionary representation of self."""

        return {
            "keyid": self.keyid,
            "sig": self.signature,
            **self.unrecognized_fields,
        }
