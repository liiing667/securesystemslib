"""
<Program Name>
  storage.py

<Author>
  Joshua Lock <jlock@vmware.com>

<Started>
  April 9, 2020

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provides an interface for filesystem interactions, StorageBackendInterface.
"""

from __future__ import annotations

import errno
import logging
import os
import secrets
import shutil
import stat
from abc import ABCMeta, abstractmethod
from collections.abc import Iterator
from contextlib import contextmanager
from typing import IO, Any, BinaryIO

from securesystemslib import exceptions

logger = logging.getLogger(__name__)


class StorageBackendInterface(metaclass=ABCMeta):
    """
    <Purpose>
    Defines an interface for abstract storage operations which can be implemented
    for a variety of storage solutions, such as remote and local filesystems.
    """

    @abstractmethod
    @contextmanager
    def get(self, filepath: str) -> Iterator[BinaryIO]:
        """
        <Purpose>
          A context manager for 'with' statements that is used for retrieving files
          from a storage backend and cleans up the files upon exit.

            with storage_backend.get('/path/to/file') as file_object:
              # operations
            # file is now closed

        <Arguments>
          filepath:
            The full path of the file to be retrieved.

        <Exceptions>
          securesystemslib.exceptions.StorageError, if the file does not exist or is
          no accessible.

        <Returns>
          A ContextManager object that emits a file-like object for the file at
          'filepath'.
        """
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def put(self, fileobj: IO, filepath: str, restrict: bool | None = False) -> None:
        """
        <Purpose>
          Store a file-like object in the storage backend.
          The file-like object is read from the beginning, not its current
          offset (if any).

        <Arguments>
          fileobj:
            The file-like object to be stored.

          filepath:
            The full path to the location where 'fileobj' will be stored.

          restrict:
            Whether the file should be created with restricted permissions.
            What counts as restricted is backend-specific. For a filesystem on a
            UNIX-like operating system, that may mean read/write permissions only
            for the user (octal mode 0o600). For a cloud storage system, that
            likely means Cloud provider specific ACL restrictions.

        <Exceptions>
          securesystemslib.exceptions.StorageError, if the file can not be stored.

        <Returns>
          None
        """
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def remove(self, filepath: str) -> None:
        """
        <Purpose>
          Remove the file at 'filepath' from the storage.

        <Arguments>
          filepath:
            The full path to the file.

        <Exceptions>
          securesystemslib.exceptions.StorageError, if the file can not be removed.

        <Returns>
          None
        """
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def getsize(self, filepath: str) -> int:
        """
        <Purpose>
          Retrieve the size, in bytes, of the file at 'filepath'.

        <Arguments>
          filepath:
            The full path to the file.

        <Exceptions>
          securesystemslib.exceptions.StorageError, if the file does not exist or is
          not accessible.

        <Returns>
          The size in bytes of the file at 'filepath'.
        """
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def create_folder(self, filepath: str) -> None:
        """
        <Purpose>
          Create a folder at filepath and ensure all intermediate components of the
          path exist.
          Passing an empty string for filepath does nothing and does not raise an
          exception.

        <Arguments>
          filepath:
            The full path of the folder to be created.

        <Exceptions>
          securesystemslib.exceptions.StorageError, if the folder can not be
          created.

        <Returns>
          None
        """
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def list_folder(self, filepath: str) -> list[str]:
        """
        <Purpose>
          List the contents of the folder at 'filepath'.

        <Arguments>
          filepath:
            The full path of the folder to be listed.

        <Exceptions>
          securesystemslib.exceptions.StorageError, if the file does not exist or is
          not accessible.

        <Returns>
          A list containing the names of the files in the folder. May be an empty
          list.
        """
        raise NotImplementedError  # pragma: no cover


class FilesystemBackend(StorageBackendInterface):
    """
    <Purpose>
      A concrete implementation of StorageBackendInterface which interacts with
      local filesystems using Python standard library functions.

      Filesystem mutations are confined to the current working directory and
      symbolic links are never written through. A write is prepared in a
      temporary file and atomically replaces its destination only after the
      complete contents have been flushed to disk.
    """

    # As FilesystemBackend is effectively a stateless wrapper around various
    # standard library operations, we only ever need a single instance of it.
    # That single instance is safe to be (re-)used by all callers. Therefore
    # implement the singleton pattern to avoid uneccesarily creating multiple
    # objects.
    _instance = None

    def __new__(cls, *args: Any, **kwargs: Any) -> FilesystemBackend:
        if cls._instance is None:
            cls._instance = object.__new__(cls, *args, **kwargs)
        return cls._instance

    @staticmethod
    def _is_within(root: str, path: str) -> bool:
        """Return whether path is root itself or a descendant of root."""
        try:
            return os.path.commonpath((root, path)) == root
        except ValueError:
            # Raised on Windows when the paths are on different drives.
            return False

    @classmethod
    def _restricted_path(cls, filepath: str, confine_to_cwd: bool) -> str:
        """
        Resolve filepath and reject paths that escape their allowed directory.

        Relative paths are always confined to the current working directory.
        Absolute read paths are allowed for backwards compatibility, but must
        resolve inside their real parent directory. Storage mutations
        additionally confine absolute paths to the current working directory.
        """
        path = os.path.abspath(filepath)
        cwd = os.path.realpath(os.getcwd())
        real_path = os.path.realpath(path)

        if os.path.isabs(filepath) and not confine_to_cwd:
            # An absolute read path is explicit, but its parent must still
            # resolve to a real directory containing the target.
            root = os.path.realpath(os.path.dirname(path))
            allowed = cls._is_within(root, real_path)
        else:
            root = cwd
            allowed = cls._is_within(root, path) and cls._is_within(root, real_path)

        if not allowed:
            raise exceptions.StorageError(
                f"Path {filepath!r} is outside the authorized directory"
            )

        return path

    @staticmethod
    def _reject_symlink(path: str, filepath: str, action: str) -> None:
        """Reject an existing symbolic link instead of acting through it."""
        try:
            mode = os.lstat(path).st_mode
        except FileNotFoundError:
            return
        except OSError as e:
            raise exceptions.StorageError(f"Can't access file {filepath}") from e

        if stat.S_ISLNK(mode):
            raise exceptions.StorageError(
                f"Refusing to {action} symbolic link {filepath}"
            )

    @staticmethod
    def _create_temporary_file(directory: str, restrict: bool) -> tuple[int, str]:
        """
        Create a new temporary file in directory and return its fd and path.

        O_EXCL (and O_NOFOLLOW where available) ensure that an attacker cannot
        pre-create the temporary path as a symlink. The mode is applied by the
        kernel, so the caller's umask is honored for non-restricted files.
        """
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        mode = stat.S_IRUSR | stat.S_IWUSR if restrict else 0o777
        for _ in range(100):
            name = f".securesystemslib-{secrets.token_hex(8)}.tmp"
            temporary_path = os.path.join(directory, name)
            try:
                fd = os.open(temporary_path, flags, mode)
            except FileExistsError:
                continue
            return fd, temporary_path

        raise OSError(errno.EEXIST, "Could not create a temporary file", directory)

    @staticmethod
    def _sync_directory(directory: str) -> None:
        """Best-effort fsync of a directory after an atomic rename."""
        if not hasattr(os, "O_DIRECTORY"):
            return

        try:
            dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            return

        try:
            os.fsync(dir_fd)
        except OSError:
            pass
        finally:
            os.close(dir_fd)

    @contextmanager
    def get(self, filepath: str) -> Iterator[BinaryIO]:
        path = self._restricted_path(filepath, confine_to_cwd=False)
        self._reject_symlink(path, filepath, "read through")
        file_object = None
        try:
            file_object = open(path, "rb")
            yield file_object
        except OSError as e:
            raise exceptions.StorageError(f"Can't open {filepath}") from e
        finally:
            if file_object is not None:
                file_object.close()

    def put(self, fileobj: IO, filepath: str, restrict: bool | None = False) -> None:
        path = self._restricted_path(filepath, confine_to_cwd=True)
        self._reject_symlink(path, filepath, "write through")

        directory = os.path.dirname(path)
        temporary_fd: int | None = None
        temporary_path: str | None = None

        try:
            # If we are passed an open file, seek to the beginning such that we
            # are copying the entire contents
            if not fileobj.closed:
                fileobj.seek(0)

            # Write the complete new contents next to the destination first.
            # Until the atomic replace below succeeds, the old file is intact.
            temporary_fd, temporary_path = self._create_temporary_file(
                directory, bool(restrict)
            )
            with os.fdopen(temporary_fd, "wb") as destination_file:
                temporary_fd = None
                shutil.copyfileobj(fileobj, destination_file)
                # Force the destination file to be written to disk from Python's
                # internal and the operating system's buffers. os.fsync() should
                # follow flush().
                destination_file.flush()
                os.fsync(destination_file.fileno())

            # os.replace() atomically replaces a regular file (or a symlink
            # itself) without writing through it. If this fails, the previous
            # file remains untouched.
            os.replace(temporary_path, path)
            temporary_path = None
            self._sync_directory(directory)
        except Exception as e:
            raise exceptions.StorageError(f"Can't write file {filepath}") from e
        finally:
            if temporary_fd is not None:
                try:
                    os.close(temporary_fd)
                except OSError:
                    pass
            if temporary_path is not None:
                try:
                    os.unlink(temporary_path)
                except OSError:
                    pass

    def remove(self, filepath: str) -> None:
        path = self._restricted_path(filepath, confine_to_cwd=True)
        self._reject_symlink(path, filepath, "remove")

        try:
            os.remove(path)
        except OSError as e:
            raise exceptions.StorageError(f"Can't remove file {filepath}") from e

    def getsize(self, filepath: str) -> int:
        path = self._restricted_path(filepath, confine_to_cwd=False)
        self._reject_symlink(path, filepath, "inspect")
        try:
            return os.path.getsize(path)
        except OSError as e:
            raise exceptions.StorageError(f"Can't access file {filepath}") from e

    def create_folder(self, filepath: str) -> None:
        if not filepath:
            raise exceptions.StorageError(
                "Can't create a folder with an empty filepath!"
            )

        path = self._restricted_path(filepath, confine_to_cwd=True)
        try:
            os.makedirs(path)
        except OSError as e:
            # 'OSError' raised if the leaf directory already exists or cannot be
            # created. Check for case where 'filepath' has already been created and
            # silently ignore.
            if e.errno == errno.EEXIST:
                pass
            else:
                raise exceptions.StorageError(
                    f"Can't create folder at {filepath}"
                ) from e

    def list_folder(self, filepath: str) -> list[str]:
        path = self._restricted_path(filepath, confine_to_cwd=False)
        self._reject_symlink(path, filepath, "list")
        try:
            return os.listdir(path)
        except OSError as e:
            raise exceptions.StorageError(f"Can't list folder at {filepath}") from e
