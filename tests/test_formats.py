"""
<Program Name>
  test_formats.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  January 2017 (modified from TUF's original formats.py)

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Unit test for 'formats.py'
"""

import unittest

import securesystemslib.formats


class TestFormats(unittest.TestCase):
    def test_encode_canonical(self):
        # Test conditions for valid arguments.
        encode = securesystemslib.formats.encode_canonical
        result = []
        output = result.append

        self.assertEqual('""', encode(""))
        self.assertEqual("[1,2,3]", encode([1, 2, 3]))
        self.assertEqual("[1,2,3]", encode([1, 2, 3]))
        self.assertEqual("[]", encode([]))
        self.assertEqual("{}", encode({}))
        self.assertEqual('{"A":[99]}', encode({"A": [99]}))
        self.assertEqual('{"A":true}', encode({"A": True}))
        self.assertEqual('{"B":false}', encode({"B": False}))
        self.assertEqual('{"x":3,"y":2}', encode({"x": 3, "y": 2}))

        self.assertEqual('{"x":3,"y":null}', encode({"x": 3, "y": None}))

        # Test condition with escaping " and \
        self.assertEqual('"\\""', encode('"'))
        self.assertEqual('"\\\\"', encode("\\"))
        self.assertEqual('"\\\\\\""', encode('\\"'))

        # Condition where 'encode()' sends the result to the callable
        # 'output'.
        self.assertEqual(None, encode([1, 2, 3], output))
        self.assertEqual("[1,2,3]", "".join(result))

        # Test conditions for invalid arguments.
        self.assertRaises(
            securesystemslib.exceptions.FormatError,
            encode,
            securesystemslib.exceptions.FormatError,
        )
        self.assertRaises(securesystemslib.exceptions.FormatError, encode, 8.0)
        self.assertRaises(securesystemslib.exceptions.FormatError, encode, {"x": 8.0})
        self.assertRaises(securesystemslib.exceptions.FormatError, encode, 8.0, output)

        self.assertRaises(
            securesystemslib.exceptions.FormatError,
            encode,
            {"x": securesystemslib.exceptions.FormatError},
        )

    def test_encode_canonical_normalizes_unicode(self):
        """Canonically equivalent Unicode spellings share one encoding."""
        encode = securesystemslib.formats.encode_canonical

        # Precomposed and decomposed forms of "é" must produce the same bytes.
        self.assertEqual(
            encode({"name": "\u00e9"}),
            encode({"name": "e\u0301"}),
        )

        # The same holds for keys, including their sort position.
        self.assertEqual(
            encode({"\u00e9": 1, "z": 2}),
            encode({"e\u0301": 1, "z": 2}),
        )

        # Distinct keys that normalize to the same key are ambiguous, not
        # silently emitted twice.
        self.assertRaises(
            securesystemslib.exceptions.FormatError,
            encode,
            {"\u00e9": 1, "e\u0301": 2},
        )

        # The result must be representable as UTF-8.
        self.assertRaises(
            securesystemslib.exceptions.FormatError,
            encode,
            "\ud800",
        )

    def test_encode_canonical_publishes_one_complete_result(self):
        """The sink receives exactly one result, and never a partial one."""
        encode = securesystemslib.formats.encode_canonical
        emitted = []

        # A failure halfway through must not leak a partial object.
        with self.assertRaises(securesystemslib.exceptions.FormatError):
            encode([1, 2.0, 3], emitted.append)
        self.assertEqual([], emitted)

        # The next object is encoded cleanly into the same sink.
        encode([1, 2, 3], emitted.append)
        self.assertEqual(["[1,2,3]"], emitted)


# Run unit test.
if __name__ == "__main__":
    unittest.main()
