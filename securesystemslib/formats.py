"""
<Program Name>
  formats.py

<Author>
  Geremy Condra
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  Refactored April 30, 2012. -vladimir.v.diaz

<Copyright>
  2008-2011 The Tor Project, Inc
  2012-2016 New York University and the TUF contributors
  2016-2021 Securesystemslib contributors
  See LICENSE for licensing information.

<Purpose>
  Implements canonical json (OLPC) encoder.

"""

import unicodedata
from collections.abc import Callable

from securesystemslib import exceptions


def _canonical_string_encoder(string: str) -> str:
    """
    <Purpose>
      Encode 'string' to canonical string format. By using the escape sequence ('\')
      which is mandatory to use for quote and backslash. 
      backslash: \\ translates to \\\\ 
      quote: \" translates to \\".

      The string is first normalized to Unicode NFC. Canonically equivalent
      spellings (e.g. a precomposed 'é' and a decomposed 'e' followed by a
      combining acute accent) must therefore produce exactly the same
      canonical bytes, so that all consumers compute the same digest.

    <Arguments>
      string:
        The string to encode.

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      A string with the canonical-encoded 'string' embedded.
    """
    if not isinstance(string, str):
        raise exceptions.FormatError(
            "Canonical JSON strings must be str, not " + type(string).__name__
        )

    string = unicodedata.normalize("NFC", string)
    string = '"{}"'.format(string.replace("\\", "\\\\").replace('"', '\\"'))

    return string


def _encode_canonical(
    object: bool | None | str | int | tuple | list | dict, output_function: Callable
) -> None:
    # Helper for encode_canonical.  Older versions of json.encoder don't
    # even let us replace the separators.

    if isinstance(object, str):
        output_function(_canonical_string_encoder(object))
    elif object is True:
        output_function("true")
    elif object is False:
        output_function("false")
    elif object is None:
        output_function("null")
    elif isinstance(object, int):
        output_function(str(object))
    elif isinstance(object, (tuple, list)):
        output_function("[")
        if len(object):
            for item in object[:-1]:
                _encode_canonical(item, output_function)
                output_function(",")
            _encode_canonical(object[-1], output_function)
        output_function("]")
    elif isinstance(object, dict):
        # Normalize keys before sorting so that Unicode-equivalent spellings
        # sort and encode identically. Distinct keys that collapse to the same
        # normalized key would result in ambiguous duplicate JSON keys, so
        # reject them instead of publishing an ambiguous byte sequence.
        normalized_items: list[tuple[str, object]] = []
        seen_keys: set[str] = set()
        for key, value in object.items():
            if not isinstance(key, str):
                raise exceptions.FormatError(
                    "Canonical JSON object keys must be strings, not "
                    + type(key).__name__
                )

            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in seen_keys:
                raise exceptions.FormatError(
                    "Canonical JSON object contains duplicate keys after "
                    "Unicode normalization: " + repr(normalized_key)
                )

            seen_keys.add(normalized_key)
            normalized_items.append((normalized_key, value))

        normalized_items.sort(key=lambda item: item[0])

        output_function("{")
        if normalized_items:
            for key, value in normalized_items[:-1]:
                output_function(_canonical_string_encoder(key))
                output_function(":")
                _encode_canonical(value, output_function)
                output_function(",")
            key, value = normalized_items[-1]
            output_function(_canonical_string_encoder(key))
            output_function(":")
            _encode_canonical(value, output_function)
        output_function("}")
    else:
        raise exceptions.FormatError("I cannot encode " + repr(object))


def encode_canonical(
    object: bool | None | str | int | tuple | list | dict,
    output_function: Callable | None = None,
) -> str | None:
    """
    <Purpose>
      Encoding an object so that it is always has the same string format
      independent of the original format. This allows to compute always the same hash
      or signature for that object.

      Encode 'object' in canonical JSON form, as specified at
      http://wiki.laptop.org/go/Canonical_JSON .  It's a restricted
      dialect of JSON in which keys are always lexically sorted,
      there is no whitespace, floats aren't allowed, and only quote
      and backslash get escaped.  The result is encoded in UTF-8,
      and the resulting bits are passed to output_function (if provided),
      or joined into a string and returned.

      Strings and object keys are normalized to Unicode NFC before encoding,
      so canonically equivalent Unicode spellings produce one canonical byte
      sequence (and therefore one digest) on every platform.  Keys that only
      become equal after normalization are rejected as ambiguous duplicates.

      The complete result is built before it is published: it is passed to
      'output_function' exactly once, and a failed encoding never emits a
      partial result that could leak into the next object.

      Note: This function should be called prior to computing the hash or
      signature of a JSON object in securesystemslib.  For example, generating a
      signature of a signing role object such as 'ROOT_SCHEMA' is required to
      ensure repeatable hashes are generated across different json module
      versions and platforms.  Code elsewhere is free to dump JSON objects in any
      format they wish (e.g., utilizing indentation and single quotes around
      object keys).  These objects are only required to be in "canonical JSON"
      format when their hashes or signatures are needed.

      >>> encode_canonical("")
      '""'
      >>> encode_canonical([1, 2, 3])
      '[1,2,3]'
      >>> encode_canonical([])
      '[]'
      >>> encode_canonical({"A": [99]})
      '{"A":[99]}'
      >>> encode_canonical({"x" : 3, "y" : 2})
      '{"x":3,"y":2}'
      >>> encode_canonical({"name": "e\\u0301"}) == encode_canonical({"name": "\u00e9"})
      True

    <Arguments>
      object:
        The object to be encoded.

      output_function:
        The result will be passed as arguments to 'output_function'
        (e.g., output_function('result')).

    <Exceptions>
      securesystemslib.exceptions.FormatError, if 'object' cannot be encoded or
      'output_function' is not callable.

    <Side Effects>
      The complete result is fed to 'output_function()' once, if
      'output_function' is set.

    <Returns>
      A string representing the 'object' encoded in canonical JSON form.
    """

    if output_function is not None and not callable(output_function):
        raise exceptions.FormatError(
            "Could not encode " + repr(object) + ": 'output_function' is not callable"
        )

    # Encode into a private buffer first.  The caller-provided sink is only
    # touched once the object has been encoded completely, so an error halfway
    # through cannot leave a truncated result behind for the next object.
    result: list[str] = []
    try:
        _encode_canonical(object, result.append)
        encoded: str = "".join(result)

        # Fail closed if the canonical text cannot be represented as UTF-8
        # (e.g. it contains an unpaired surrogate).  This keeps the public
        # output a single, well-defined byte domain.
        encoded.encode("utf-8")

    except (TypeError, ValueError, UnicodeError, exceptions.FormatError) as e:
        message: str = "Could not encode " + repr(object) + ": " + str(e)
        raise exceptions.FormatError(message) from e

    # Return the encoded 'object' as a string.
    # Note: Implies 'output_function' is None,
    # otherwise the single complete result is sent to 'output_function'.
    if output_function is None:
        return encoded

    output_function(encoded)
    return None
