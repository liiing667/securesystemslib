"""
<Program Name>
  hash.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  February 28, 2012.  Based on a previous version of this module.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Support secure hashing and message digests. Any hash-related routines that
  securesystemslib requires should be located in this module.  Simplifying the
  creation of digest objects, and providing a central location for hash
  routines are the main goals of this module.  Support routines implemented
  include functions to create digest objects given a filename or file object.
  Only the standard hashlib library is currently supported, but
  pyca/cryptography support will be added in the future.
"""

import hashlib
import os
import stat

from securesystemslib import exceptions
from securesystemslib.storage import FilesystemBackend

DEFAULT_CHUNK_SIZE = 4096
DEFAULT_HASH_ALGORITHM = "sha256"
DEFAULT_HASH_LIBRARY = "hashlib"
SUPPORTED_LIBRARIES = ["hashlib"]
_FILE_IDENTITY_FIELDS = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")


def _file_identity(file_stat: os.stat_result) -> tuple[object, ...]:
    """Return the metadata that binds a path to the bytes being hashed."""
    return tuple(getattr(file_stat, field) for field in _FILE_IDENTITY_FIELDS)


def _stat_open_file(file_object: object) -> os.stat_result | None:
    """Return an open file's stat result when it exposes a descriptor."""
    fileno = getattr(file_object, "fileno", None)
    if not callable(fileno):
        return None

    try:
        fd = fileno()
        return os.fstat(fd)
    except (OSError, TypeError, ValueError):
        # Non-filesystem and test double file objects need not expose a
        # descriptor.  digest_filename() still hashes them through the backend.
        return None


def _confirmed_file_stat(
    filename: str, file_object: object, storage_backend: object
) -> os.stat_result | None:
    """Validate and return identity metadata for a stock filesystem file."""
    if not isinstance(storage_backend, FilesystemBackend):
        return None

    file_stat = _stat_open_file(file_object)
    if file_stat is None:
        return None

    if not stat.S_ISREG(file_stat.st_mode):
        raise ValueError(f"Refusing to digest non-regular file: {filename!r}")
    if file_stat.st_size < 0:
        raise ValueError(f"File has a negative length: {filename!r}")

    return file_stat


def _verify_file_identity(
    filename: str, file_object: object, initial_stat: os.stat_result | None
) -> None:
    """Ensure the completed read covered one stable, complete file."""
    if initial_stat is None:
        return

    tell = getattr(file_object, "tell", None)
    try:
        bytes_read = tell() if callable(tell) else None
    except (OSError, ValueError):
        bytes_read = None

    # A premature EOF/short read must not be published as a complete digest
    # even if the hash object itself looks well-formed.
    if (
        not isinstance(bytes_read, int)
        or isinstance(bytes_read, bool)
        or bytes_read < 0
        or bytes_read != initial_stat.st_size
    ):
        raise ValueError(f"File was not read completely: {filename!r}")

    final_stat = _stat_open_file(file_object)
    if final_stat is None or _file_identity(initial_stat) != _file_identity(
        final_stat
    ):
        raise ValueError(
            f"File changed while its digest was calculated: {filename!r}"
        )

    try:
        path_stat = os.stat(filename)
    except OSError as exc:
        raise ValueError(
            f"Digested file no longer has a stable path: {filename!r}"
        ) from exc

    if (path_stat.st_dev, path_stat.st_ino) != (
        initial_stat.st_dev,
        initial_stat.st_ino,
    ):
        raise ValueError(
            "File was replaced while its digest was calculated: "
            f"{filename!r}"
        )


# If `pyca_crypto` is installed, add it to supported libraries
try:
    import binascii

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes as _pyca_hashes

    # Dictionary of `pyca/cryptography` supported hash algorithms.
    PYCA_DIGEST_OBJECTS_CACHE = {
        "sha224": _pyca_hashes.SHA224,
        "sha256": _pyca_hashes.SHA256,
        "sha384": _pyca_hashes.SHA384,
        "sha512": _pyca_hashes.SHA512,
    }

    SUPPORTED_LIBRARIES.append("pyca_crypto")

    class PycaDiggestWrapper:
        """
        <Purpose>
          A wrapper around `cryptography.hazmat.primitives.hashes.Hash` which adds
          additional methods to meet expected interface for digest objects:

            digest_object.digest_size
            digest_object.hexdigest()
            digest_object.update('data')
            digest_object.digest()

        <Properties>
          algorithm:
            Specific for `cryptography.hazmat.primitives.hashes.Hash` object.

          digest_size:
            Returns original's object digest size.

        <Methods>
          digest(self) -> bytes:
            Calls original's object `finalize` method and returns digest as bytes.
            NOTE: `cryptography.hazmat.primitives.hashes.Hash` allows calling
            `finalize` method just once on the same instance, so everytime `digest`
            methods is called, we replace internal object (`_digest_obj`).

          hexdigest(self) -> str:
            Returns a string hex representation of digest.

          update(self, data) -> None:
            Updates digest object data by calling the original's object `update`
            method.
        """

        def __init__(self, digest_obj):
            self._digest_obj = digest_obj

        @property
        def algorithm(self):
            return self._digest_obj.algorithm

        @property
        def digest_size(self):
            return self._digest_obj.algorithm.digest_size

        def digest(self):
            digest_obj_copy = self._digest_obj.copy()
            digest = self._digest_obj.finalize()
            self._digest_obj = digest_obj_copy
            return digest

        def hexdigest(self):
            return binascii.hexlify(self.digest()).decode("utf-8")

        def update(self, data):
            self._digest_obj.update(data)

except ImportError:  # pragma: no cover
    pass


def digest(algorithm=DEFAULT_HASH_ALGORITHM, hash_library=DEFAULT_HASH_LIBRARY):
    """
    <Purpose>
      Provide the caller with the ability to create digest objects without having
      to worry about crypto library availability or which library to use.  The
      caller also has the option of specifying which hash algorithm and/or
      library to use.

      # Creation of a digest object using defaults or by specifying hash
      # algorithm and library.
      digest_object = securesystemslib.hash.digest()
      digest_object = securesystemslib.hash.digest('sha384')
      digest_object = securesystemslib.hash.digest('sha256', 'hashlib')

      # The expected interface for digest objects.
      digest_object.digest_size
      digest_object.hexdigest()
      digest_object.update('data')
      digest_object.digest()

      # Added hash routines by this module.
      digest_object = securesystemslib.hash.digest_fileobject(file_object)
      digest_object = securesystemslib.hash.digest_filename(filename)

    <Arguments>
      algorithm:
        The hash algorithm (e.g., 'sha256', 'sha512').

      hash_library:
        The crypto library to use for the given hash algorithm (e.g., 'hashlib').

    <Exceptions>
      securesystemslib.exceptions.UnsupportedAlgorithmError, if an unsupported
      hashing algorithm is specified, or digest could not be generated with given
      the algorithm.

      securesystemslib.exceptions.UnsupportedLibraryError, if an unsupported
      library was requested via 'hash_library'.

    <Side Effects>
      None.

    <Returns>
      Digest object

      e.g.
        hashlib.new(algorithm) or
        PycaDiggestWrapper object
    """

    # Was a hashlib digest object requested and is it supported?
    # If so, return the digest object.
    if hash_library == "hashlib" and hash_library in SUPPORTED_LIBRARIES:
        try:
            if algorithm == "blake2b-256":
                return hashlib.new("blake2b", digest_size=32)
            else:
                return hashlib.new(algorithm)

        except (ValueError, TypeError):
            # ValueError: the algorithm value was unknown
            # TypeError: unexpected argument digest_size (on old python)
            raise exceptions.UnsupportedAlgorithmError(algorithm)

    # Was a pyca_crypto digest object requested and is it supported?
    elif hash_library == "pyca_crypto" and hash_library in SUPPORTED_LIBRARIES:
        try:
            hash_algorithm = PYCA_DIGEST_OBJECTS_CACHE[algorithm]()
            return PycaDiggestWrapper(
                _pyca_hashes.Hash(hash_algorithm, default_backend())
            )

        except KeyError:
            raise exceptions.UnsupportedAlgorithmError(algorithm)

    # The requested hash library is not supported.
    else:
        raise exceptions.UnsupportedLibraryError(
            "Unsupported"
            " library requested.  Supported hash"
            " libraries: " + repr(SUPPORTED_LIBRARIES)
        )


def digest_fileobject(
    file_object,
    algorithm=DEFAULT_HASH_ALGORITHM,
    hash_library=DEFAULT_HASH_LIBRARY,
    normalize_line_endings=False,
):
    """
    <Purpose>
      Generate a digest object given a file object.  The new digest object
      is updated with the contents of 'file_object' prior to returning the
      object to the caller.

    <Arguments>
      file_object:
        File object whose contents will be used as the data
        to update the hash of a digest object to be returned.

      algorithm:
        The hash algorithm (e.g., 'sha256', 'sha512').

      hash_library:
        The library providing the hash algorithms (e.g., 'hashlib').

      normalize_line_endings: (default False)
        Whether or not to normalize line endings for cross-platform support.
        Note that this results in ambiguous hashes (e.g. 'abc\n' and 'abc\r\n'
        will produce the same hash), so be careful to only apply this to text
        files (not binary), when that equivalence is desirable and cannot result
        in easily-maliciously-corrupted files producing the same hash as a valid
        file.

    <Exceptions>
      securesystemslib.exceptions.FormatError, if the arguments are
      improperly formatted.

      securesystemslib.exceptions.UnsupportedAlgorithmError, if an unsupported
      hashing algorithm was specified via 'algorithm'.

      securesystemslib.exceptions.UnsupportedLibraryError, if an unsupported
      crypto library was specified via 'hash_library'.

    <Side Effects>
      None.

    <Returns>
      Digest object

      e.g.
        hashlib.new(algorithm) or
        PycaDiggestWrapper object
    """
    # Digest object returned whose hash will be updated using 'file_object'.
    # digest() raises:
    # securesystemslib.exceptions.UnsupportedAlgorithmError
    # securesystemslib.exceptions.UnsupportedLibraryError
    digest_object = digest(algorithm, hash_library)

    chunk_size = DEFAULT_CHUNK_SIZE
    if (
        isinstance(chunk_size, bool)
        or not isinstance(chunk_size, int)
        or chunk_size <= 0
    ):
        raise ValueError("hash read length must be a positive integer")

    # Defensively seek to beginning, as there's no case where we don't
    # intend to start from the beginning of the file.
    file_object.seek(0)

    # Read the contents of the file object in at most 4096-byte chunks.
    # Update the hash with the data read from each chunk and return after
    # the entire file is processed.
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break

        if normalize_line_endings:
            while data[-1:] == b"\r":
                c = file_object.read(1)
                if not c:
                    break

                data += c

            data = (
                data
                # First Windows
                .replace(b"\r\n", b"\n")
                # Then Mac
                .replace(b"\r", b"\n")
            )

        if not isinstance(data, bytes):
            digest_object.update(data.encode("utf-8"))

        else:
            digest_object.update(data)

    return digest_object


def digest_filename(
    filename,
    algorithm=DEFAULT_HASH_ALGORITHM,
    hash_library=DEFAULT_HASH_LIBRARY,
    normalize_line_endings=False,
    storage_backend=None,
):
    """
    <Purpose>
      Generate a digest object, update its hash using a file object
      specified by filename, and then return it to the caller.

    <Arguments>
      filename:
        The filename belonging to the file object to be used.

      algorithm:
        The hash algorithm (e.g., 'sha256', 'sha512').

      hash_library:
        The library providing the hash algorithms (e.g., 'hashlib').

      normalize_line_endings:
        Whether or not to normalize line endings for cross-platform support.

      storage_backend:
        An object which implements
        securesystemslib.storage.StorageBackendInterface. When no object is
        passed a FilesystemBackend will be instantiated and used.

    <Exceptions>
      securesystemslib.exceptions.UnsupportedAlgorithmError, if the given
      'algorithm' is unsupported.

      securesystemslib.exceptions.UnsupportedLibraryError, if the given
      'hash_library' is unsupported.

      securesystemslib.exceptions.StorageError, if the file cannot be opened.

      ValueError, if the path is a symbolic link or non-regular file, has an
      invalid length, cannot be read completely, or changes identity while
      its digest is being calculated.

    <Side Effects>
      None.

    <Returns>
      Digest object

      e.g.
        hashlib.new(algorithm) or
        PycaDiggestWrapper object
    """
    if storage_backend is None:
        storage_backend = FilesystemBackend()

    # Validate the algorithm before touching the filesystem.  An unknown
    # algorithm/library must never be able to produce a returned digest object.
    digest(algorithm, hash_library)

    # Open 'filename' in read+binary mode.  The stock filesystem backend opens
    # it with O_NOFOLLOW and rejects symlinks.  When an fd is available, bind
    # the returned digest to that one file identity and re-check it after read.
    with storage_backend.get(filename) as file_object:
        initial_stat = _confirmed_file_stat(
            filename, file_object, storage_backend
        )

        # Create digest_object and update its hash data from file_object.
        # digest_fileobject() raises:
        # securesystemslib.exceptions.UnsupportedAlgorithmError
        # securesystemslib.exceptions.UnsupportedLibraryError
        digest_object = digest_fileobject(
            file_object, algorithm, hash_library, normalize_line_endings
        )

        _verify_file_identity(filename, file_object, initial_stat)

    return digest_object
