"""
<Module Name>
  functions.py

<Author>
  Santiago Torres-Arias <santiago@nyu.edu>

<Started>
  Nov 15, 2017

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  publicly-usable functions for exporting public-keys, signing data and
  verifying signatures.
"""

import logging
import os
import subprocess
import time
from pathlib import PureWindowsPath

from securesystemslib import exceptions
from securesystemslib._gpg.common import (
    get_pubkey_bundle,
    parse_signature_packet,
)
from securesystemslib._gpg.constants import (
    FULLY_SUPPORTED_MIN_VERSION,
    GPG_TIMEOUT,
    NO_GPG_MSG,
    SHA256,
    gpg_command,
    gpg_export_pubkey_command,
    gpg_sign_command,
    have_gpg,
)
from securesystemslib._gpg.exceptions import KeyExpirationError
from securesystemslib._gpg.handlers import SIGNATURE_HANDLERS
from securesystemslib._gpg.rsa import CRYPTO

log = logging.getLogger(__name__)

NO_CRYPTO_MSG = "GPG support requires the cryptography library"


def _keyid_matches(candidate_keyid, signature_keyid):
    """Return True for an exact keyid or a compatible keyid suffix."""
    if not candidate_keyid or not signature_keyid:
        return False

    candidate_keyid = str(candidate_keyid).lower()
    signature_keyid = str(signature_keyid).lower()
    return candidate_keyid == signature_keyid or candidate_keyid.endswith(
        signature_keyid
    )


def _trusted_bundle_subkey(subkey_info, sig_keyid):
    """Apply bundle provenance policy to a matched subkey."""
    if subkey_info.get("binding_verified") is not True:
        log.info(
            "Refusing subkey '%s' without a verified primary binding.",
            sig_keyid,
        )
        return None

    if subkey_info.get("signing_capable") is False:
        log.info(
            "Refusing signature by subkey '%s' whose key flags do not allow "
            "signing.",
            sig_keyid,
        )
        return None

    if subkey_info.get("cross_binding_verified") is not True:
        log.info(
            "Refusing signing subkey '%s' without a verified embedded primary "
            "key binding.",
            sig_keyid,
        )
        return None

    return subkey_info


def _select_verification_key(pubkey_info, sig_keyid):
    """Resolve a signature issuer to one trusted primary or bundle subkey."""
    primary_matches = _keyid_matches(pubkey_info.get("keyid"), sig_keyid)
    matching_subkeys = []

    for subkey_keyid, subkey_info in pubkey_info.get("subkeys", {}).items():
        if not isinstance(subkey_info, dict):
            continue

        # The dictionary index and parsed key identity must agree. This keeps a
        # stale map entry from publishing one key while its material claims
        # another keyid.
        if _keyid_matches(subkey_keyid, sig_keyid) and _keyid_matches(
            subkey_info.get("keyid"), sig_keyid
        ):
            matching_subkeys.append(subkey_info)

    if primary_matches and matching_subkeys:
        log.info(
            "GPG keyid '%s' matches both primary and subkey material; "
            "refusing ambiguous identity.",
            sig_keyid,
        )
        return None

    if len(matching_subkeys) > 1:
        log.info(
            "GPG keyid '%s' matches %d subkeys; refusing ambiguous identity.",
            sig_keyid,
            len(matching_subkeys),
        )
        return None

    if primary_matches:
        # A top-level public key remains an explicitly supplied trust anchor,
        # including a standalone subkey represented in this legacy format.
        return pubkey_info

    if not matching_subkeys:
        log.info(
            "GPG signature issuer '%s' is not bound to the passed public key.",
            sig_keyid,
        )
        return None

    return _trusted_bundle_subkey(matching_subkeys[0], sig_keyid)


def _homedir_to_gpg_arg(homedir: str) -> str:
    """Convert a homedir path to a GPG-compatible --homedir argument.

    On Windows, path format depends on the GPG binary:
    - Native Gpg4win (.exe): accepts forward-slash Windows paths (C:/path)
    - Cygwin/MSYS2 GPG: requires cygwin-style paths (/c/path)
    See https://github.com/secure-systems-lab/securesystemslib/issues/517
    """
    if gpg_command().endswith(".exe"):
        return homedir.replace("\\", "/")
    if os.name == "nt":
        p = PureWindowsPath(homedir)
        if p.drive:
            drive_letter = p.drive[0].lower()
            rest = p.as_posix()[len(p.drive) :]
            return f"/{drive_letter}{rest}"
    return homedir.replace("\\", "/")


def create_signature(content, keyid=None, homedir=None, timeout=GPG_TIMEOUT):
    """
    <Purpose>
      Calls the gpg command line utility to sign the passed content with the key
      identified by the passed keyid from the gpg keyring at the passed homedir.

      The executed base command is defined in
      securesystemslib._gpg.constants.gpg_sign_command.

      NOTE: On not fully supported versions of GPG, i.e. versions below
      securesystemslib._gpg.constants.FULLY_SUPPORTED_MIN_VERSION the returned
      signature does not contain the full keyid. As a work around, we export the
      public key bundle identified by the short keyid to compute the full keyid
      and add it to the returned signature.

    <Arguments>
      content:
              The content to be signed. (bytes)

      keyid: (optional)
              The keyid of the gpg signing keyid. If not passed the default
              key in the keyring is used.

      homedir: (optional)
              Path to the gpg keyring. If not passed the default keyring is used.

      timeout (optional):
              gpg command timeout in seconds. Default is 10.

    <Exceptions>

      ValueError:
              If the gpg command failed to create a valid signature.

      OSError:
              If the gpg command is not present, or non-executable,
              or returned a non-zero exit code

      securesystemslib.exceptions.UnsupportedLibraryError:
              If the gpg command is not available, or
              the cryptography library is not installed.

      securesystemslib._gpg.exceptions.KeyNotFoundError:
              If the used gpg version is not fully supported
              and no public key can be found for short keyid.

    <Side Effects>
      None.

    <Returns>
      A signature dict.

    """
    if not have_gpg():  # pragma: no cover
        raise exceptions.UnsupportedLibraryError(NO_GPG_MSG)

    if not CRYPTO:  # pragma: no cover
        raise exceptions.UnsupportedLibraryError(NO_CRYPTO_MSG)

    keyarg = ""
    if keyid:
        keyarg = f"--local-user {keyid}"

    homearg = ""
    if homedir:
        homearg = f"--homedir {_homedir_to_gpg_arg(homedir)}"

    command = gpg_sign_command(keyarg=keyarg, homearg=homearg)

    gpg_process = subprocess.run(  # noqa: S603
        command,
        input=content,
        check=False,
        capture_output=True,
        timeout=timeout,
    )

    # TODO: It's suggested to take a look at `--status-fd` for proper error
    # reporting, as there is no clear distinction between the return codes
    # https://lists.gnupg.org/pipermail/gnupg-devel/2005-December/022559.html
    if gpg_process.returncode != 0:
        raise OSError(
            f"Command '{gpg_process.args}' returned "
            f"non-zero exit status '{gpg_process.returncode}', "
            f"stderr was:\n{gpg_process.stderr.decode()}."
        )

    signature_data = gpg_process.stdout
    signature = parse_signature_packet(signature_data)

    # On GPG < 2.1 we cannot derive the full keyid from the signature data.
    # Instead we try to compute the keyid from the public part of the signing
    # key or its subkeys, identified by the short keyid.
    # parse_signature_packet is guaranteed to return at least one of keyid or
    # short_keyid.
    # Exclude the following code from coverage for consistent coverage across
    # test environments.
    if not signature["keyid"]:  # pragma: no cover
        log.warning(
            "The created signature does not include the hashed subpacket"
            " '33' (full keyid). You probably have a gpg version"
            f" <{FULLY_SUPPORTED_MIN_VERSION}."
            " We will export the public keys associated with the short keyid to"
            " compute the full keyid."
        )

        short_keyid = signature["short_keyid"]

        # Export public key bundle (master key including with optional subkeys)
        public_key_bundle = export_pubkey(short_keyid, homedir)

        # Test if the short keyid matches the master key ...
        master_key_full_keyid = public_key_bundle["keyid"]
        if master_key_full_keyid.endswith(short_keyid.lower()):
            signature["keyid"] = master_key_full_keyid

        # ... or one of the subkeys, and add the full keyid to the signature dict.
        else:
            for sub_key_full_keyid in list(public_key_bundle.get("subkeys", {}).keys()):
                if sub_key_full_keyid.endswith(short_keyid.lower()):
                    signature["keyid"] = sub_key_full_keyid
                    break

    # If there is still no full keyid something went wrong
    if not signature["keyid"]:  # pragma: no cover
        raise ValueError(
            f"Full keyid could not be determined for signature '{signature}'"
        )

    # It is okay now to remove the optional short keyid to save space
    signature.pop("short_keyid", None)

    return signature


def verify_signature(signature_object, pubkey_info, content):
    """
    <Purpose>
      Verifies the passed signature against the passed content using the
      unique primary or proven-bound subkey associated with the signature's
      keyid.

      The function selects the appropriate verification algorithm (rsa or dsa)
      based on the "type" field in the passed public key object.

    <Arguments>
      signature_object:
              A signature dict.

      pubkey_info:
              A public key dict.

      content:
              The content to be verified. (bytes)

    <Exceptions>
      securesystemslib._gpg.exceptions.KeyExpirationError:
              if the passed public key has expired

      securesystemslib.exceptions.UnsupportedLibraryError:
              if the cryptography module is unavailable

    <Side Effects>
      None.

    <Returns>
      True if signature verification passes, False otherwise.
      False is also returned if the issuer keyid is missing, ambiguous, not
      present in ``pubkey_info``, or names a subkey whose bundle binding has
      not been verified. An expired but otherwise valid key raises
      KeyExpirationError.

    """
    if not CRYPTO:  # pragma: no cover
        raise exceptions.UnsupportedLibraryError(NO_CRYPTO_MSG)

    if not isinstance(signature_object, dict) or not isinstance(
        pubkey_info, dict
    ):
        log.info("Refusing GPG verification with malformed key or signature.")
        return False

    sig_keyid = signature_object.get("keyid") or signature_object.get(
        "short_keyid"
    )
    if not sig_keyid:
        log.info("Refusing GPG verification without a signature issuer keyid.")
        return False

    # Resolve the issuer to exactly one proven primary or subkey identity. An
    # unknown keyid must not fall through to verification with the primary key.
    verification_key = _select_verification_key(pubkey_info, sig_keyid)
    if verification_key is None:
        return False

    creation_time = verification_key.get("creation_time")
    validity_period = verification_key.get("validity_period")

    if (
        creation_time
        and validity_period
        and creation_time + validity_period < time.time()
    ):
        raise KeyExpirationError(verification_key)

    # The primary and a subkey may use different public-key algorithms. Select
    # the handler from the key material that will actually verify the signature.
    handler = SIGNATURE_HANDLERS[verification_key["type"]]
    return handler.verify_signature(signature_object, verification_key, content, SHA256)


def export_pubkey(keyid, homedir=None, timeout=GPG_TIMEOUT):
    """Exports a public key from a GnuPG keyring.

    Arguments:
      keyid: An OpenPGP keyid..
      homedir (optional): A path to the GnuPG home directory. If not set the
          default GnuPG home directory is used.
      timeout (optional): gpg command timeout in seconds. Default is 10.

    Raises:
      UnsupportedLibraryError: The gpg command or pyca/cryptography are not
          available.
      KeyNotFoundError: No key or subkey was found for that keyid.

    Side Effects:
      Calls system gpg command in a subprocess.

    Returns:
      An OpenPGP public key dict.

    """
    if not have_gpg():  # pragma: no cover
        raise exceptions.UnsupportedLibraryError(NO_GPG_MSG)

    if not CRYPTO:  # pragma: no cover
        raise exceptions.UnsupportedLibraryError(NO_CRYPTO_MSG)

    homearg = ""
    if homedir:
        homearg = f"--homedir {_homedir_to_gpg_arg(homedir)}"

    # TODO: Consider adopting command error handling from `create_signature`
    # above, e.g. in a common 'run gpg command' utility function
    command = gpg_export_pubkey_command(keyid=keyid, homearg=homearg)
    gpg_process = subprocess.run(  # noqa: S603
        command,
        capture_output=True,
        timeout=timeout,
        check=True,
    )

    key_packet = gpg_process.stdout
    key_bundle = get_pubkey_bundle(key_packet, keyid)

    return key_bundle


def export_pubkeys(keyids, homedir=None, timeout=GPG_TIMEOUT):
    """Exports multiple public keys from a GnuPG keyring.

    Arguments:
      keyids: A list of OpenPGP keyids.
      homedir (optional): A path to the GnuPG home directory. If not set the
          default GnuPG home directory is used.
      timeout (optional): gpg command timeout in seconds. Default is 10.

    Raises:
      TypeError: Keyids is not iterable.
      ValueError: A Keyid is not a string.
      UnsupportedLibraryError: The gpg command or pyca/cryptography are not
          available.
      KeyNotFoundError: No key or subkey was found for that keyid.

    Side Effects:
      Calls system gpg command in a subprocess.

    Returns:
      A dict of OpenPGP public key dicts as values,
      and their keyids as dict keys.


    """
    public_key_dict = {}
    for gpg_keyid in keyids:
        public_key = export_pubkey(gpg_keyid, homedir=homedir, timeout=timeout)
        keyid = public_key["keyid"]
        public_key_dict[keyid] = public_key

    return public_key_dict
