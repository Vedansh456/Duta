"""
Duta filesystem core.

Provides permission-controlled listing, reading, creating, and editing
of UTF-8 text files inside an explicitly selected workspace.

This is a prototype, not a security boundary against a hostile local user.
Use operating-system sandboxing for stronger security.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import tempfile
from typing import Iterable


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class DutaError(Exception):
    """Base exception for Duta errors."""


class AccessDeniedError(DutaError):
    """Raised when an operation is not allowed by the configured policy."""


class UnsafePathError(DutaError):
    """Raised when a path is invalid or escapes the workspace."""


# ---------------------------------------------------------------------------
# Default exclusions
# ---------------------------------------------------------------------------

# Skip development environments, dependencies, version-control internals,
# and generated build files.
DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "node_modules",
    ".idea",
    ".vscode",
    "dist",
    "build",
}

# Common sensitive filenames that must not be accessed by default.
DEFAULT_EXCLUDED_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "secrets.json",
}

# File types that Duta's text operations will not access by default.
DEFAULT_EXCLUDED_SUFFIXES = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".sqlite",
    ".db",
    ".exe",
    ".dll",
    ".bin",
    ".zip",
    ".7z",
    ".rar",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".pdf",
    ".docx",
    ".xlsx",
    ".pptx",
}

# Keep this list synchronized with config.py and the CLI.
SUPPORTED_PERMISSIONS = {"list", "read", "create", "edit"}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FileEntry:
    """A file or directory relative to the workspace root."""

    path: str
    kind: str
    size_bytes: int | None = None


# ---------------------------------------------------------------------------
# Duta filesystem core
# ---------------------------------------------------------------------------

class Duta:
    """
    Permission-controlled access to files inside one workspace.

    Example:
        duta = Duta("./my-project")
        duta.allow(
            "src/**/*.py",
            permissions=("list", "read", "edit"),
        )
        print(duta.read("src/main.py"))

    Supported permissions:
        list   - list matching files and directories
        read   - read an existing text file
        create - create a new text file without overwriting
        edit   - replace the contents of an existing text file

    Patterns must be relative to the workspace and use glob syntax.
    """

    def __init__(
        self,
        workspace: str | os.PathLike[str],
        *,
        exclude_dirs: Iterable[str] = DEFAULT_EXCLUDED_DIRS,
        exclude_names: Iterable[str] = DEFAULT_EXCLUDED_NAMES,
        exclude_suffixes: Iterable[str] = DEFAULT_EXCLUDED_SUFFIXES,
        max_read_bytes: int = 1_000_000,
    ) -> None:
        # Resolve the workspace to one absolute path.
        raw_root = Path(workspace).expanduser()

        try:
            self._root = raw_root.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise UnsafePathError(
                f"Workspace does not exist or cannot be resolved: {workspace}"
            ) from exc

        if not self._root.is_dir():
            raise UnsafePathError("Workspace must be an existing directory.")

        # Give this instance its own copies of the exclusion settings.
        self._exclude_dirs = set(exclude_dirs)
        self._exclude_names = set(exclude_names)
        self._exclude_suffixes = {
            suffix.lower() for suffix in exclude_suffixes
        }

        # Apply one byte limit to reading, creating, and editing.
        if (
            isinstance(max_read_bytes, bool)
            or not isinstance(max_read_bytes, int)
            or max_read_bytes < 1
        ):
            raise ValueError("max_read_bytes must be a positive integer.")

        self._max_read_bytes = max_read_bytes

        # Each rule contains a normalized pattern and its granted permissions.
        self._rules: list[tuple[str, frozenset[str]]] = []

    # -----------------------------------------------------------------------
    # Permission rules
    # -----------------------------------------------------------------------

    def allow(
        self,
        pattern: str,
        *,
        permissions: Iterable[str] = ("list", "read"),
    ) -> None:
        """Grant explicit permissions for paths matching a relative pattern."""

        normalized = self._normalize_pattern(pattern)

        try:
            perms = frozenset(permissions)
        except TypeError as exc:
            raise ValueError(
                "Permissions must be an iterable of permission names."
            ) from exc

        # Reject empty permission sets and unsupported permission names.
        if not perms or not perms <= SUPPORTED_PERMISSIONS:
            supported = ", ".join(sorted(SUPPORTED_PERMISSIONS))
            raise ValueError(
                f"Permissions must be non-empty and drawn from: {supported}."
            )

        self._rules.append((normalized, perms))

    def _normalize_pattern(self, pattern: str) -> str:
        """Validate and normalize a workspace-relative glob pattern."""

        if not isinstance(pattern, str) or not pattern.strip():
            raise ValueError("Pattern must be a non-empty relative path.")

        pattern = pattern.replace("\\", "/").strip()

        # Reject absolute paths, including Windows drive paths.
        if pattern.startswith("/") or (
            len(pattern) > 1 and pattern[1] == ":"
        ):
            raise UnsafePathError(
                "Allow patterns must be relative to the workspace."
            )

        # Reject parent-directory traversal.
        if ".." in pattern.split("/"):
            raise UnsafePathError("Allow patterns cannot contain '..'.")

        normalized = pattern.removeprefix("./")

        if not normalized:
            raise ValueError("Pattern must identify a path.")

        return normalized

    @staticmethod
    def _glob_matches(path: str, pattern: str) -> bool:
        """
        Match a relative path using glob-style syntax.

        '*' and '?' do not cross directory separators.
        '**/' matches zero or more directory levels.

        Examples:
            src/*.py       matches src/main.py
            src/*.py       does not match src/nested/main.py
            src/**/*.py    matches src/main.py
            src/**/*.py    matches src/nested/main.py
            **/*.py        matches main.py and src/main.py
        """
        regex_parts: list[str] = []
        index = 0

        while index < len(pattern):
            # A double star followed by a slash can match zero or more
            # complete directory levels.
            if pattern[index:index + 3] == "**/":
                regex_parts.append("(?:.*/)?")
                index += 3
                continue

            # A standalone double star can match any characters.
            if pattern[index:index + 2] == "**":
                regex_parts.append(".*")
                index += 2
                continue

            char = pattern[index]

            if char == "*":
                regex_parts.append("[^/]*")

            elif char == "?":
                regex_parts.append("[^/]")

            elif char == "[":
                closing = pattern.find("]", index + 1)

                if closing != -1:
                    character_class = pattern[index + 1:closing]

                    if character_class.startswith("!"):
                        character_class = "^" + character_class[1:]

                    # Escape backslashes in the character class so the
                    # generated regular expression remains valid.
                    character_class = character_class.replace("\\", r"\\")
                    regex_parts.append("[" + character_class + "]")
                    index = closing

                else:
                    # Treat an unmatched opening bracket literally.
                    regex_parts.append(r"\[")

            else:
                regex_parts.append(re.escape(char))

            index += 1

        try:
            return re.fullmatch("".join(regex_parts), path) is not None
        except re.error:
            # A malformed glob should not accidentally grant permission.
            return False

    def _is_allowed(self, relative_path: str, permission: str) -> bool:
        """Check whether any rule grants a permission for a relative path."""

        return any(
            permission in permissions
            and self._glob_matches(relative_path, pattern)
            for pattern, permissions in self._rules
        )

    # -----------------------------------------------------------------------
    # Status API
    # -----------------------------------------------------------------------

    def status(self) -> dict[str, object]:
        """
        Return a snapshot of this Duta instance's configuration.

        This reports configured rules, not filesystem contents.
        Changing the returned dictionary does not change Duta's policy.
        """
        granted_operations = sorted({
            permission
            for _, granted in self._rules
            for permission in granted
        })

        return {
            "workspace": str(self._root),
            "permission_rule_count": len(self._rules),
            "rules": [
                {
                    "pattern": pattern,
                    "permissions": sorted(granted),
                }
                for pattern, granted in self._rules
            ],
            "granted_operations": granted_operations,
            "max_read_bytes": self._max_read_bytes,
            "excluded_directory_count": len(self._exclude_dirs),
            "excluded_filename_count": len(self._exclude_names),
            "excluded_suffix_count": len(self._exclude_suffixes),
        }

    # -----------------------------------------------------------------------
    # Path validation and exclusions
    # -----------------------------------------------------------------------

    def _check_exclusions(self, relative_path: str) -> None:
        """Reject excluded directories, names, and file types."""

        parts = Path(relative_path).parts

        if not parts:
            raise UnsafePathError("Path must identify a file or directory.")

        # Check parent directories against the exclusion list.
        if any(part in self._exclude_dirs for part in parts[:-1]):
            raise AccessDeniedError(
                "This path is inside an excluded directory."
            )

        # Check the target filename and extension.
        if (
            parts[-1] in self._exclude_names
            or Path(relative_path).suffix.lower() in self._exclude_suffixes
        ):
            raise AccessDeniedError(
                "This file type or name is excluded by default."
            )

    def _resolve(self, relative_path: str) -> tuple[Path, str]:
        """
        Resolve an existing path inside the workspace.

        The target must already exist. This method is used by read() and
        edit(). create() separately validates the existing parent directory.
        """

        if not isinstance(relative_path, str) or not relative_path.strip():
            raise UnsafePathError("Path must be a non-empty relative path.")

        normalized = relative_path.replace("\\", "/")

        # Reject absolute paths and parent-directory traversal.
        if normalized.startswith("/") or (
            len(normalized) > 1 and normalized[1] == ":"
        ):
            raise UnsafePathError("Absolute paths are not allowed.")

        if ".." in normalized.split("/"):
            raise UnsafePathError("Path traversal is not allowed.")

        try:
            candidate = (self._root / normalized).resolve(strict=True)

        except FileNotFoundError:
            # Keep missing-file errors distinct from unsafe-path errors.
            raise

        except (OSError, RuntimeError) as exc:
            raise UnsafePathError(
                "Path could not be resolved safely."
            ) from exc

        try:
            # Ensure the resolved target remains inside the workspace.
            relative = candidate.relative_to(self._root).as_posix()

        except ValueError as exc:
            raise UnsafePathError(
                "Path resolves outside the workspace."
            ) from exc

        # Reject excluded paths even when a permission rule matches them.
        self._check_exclusions(relative)

        return candidate, relative

    def _validate_content(self, content: str) -> bytes:
        """Validate text content and enforce the configured byte limit."""

        if not isinstance(content, str):
            raise TypeError("File content must be a string.")

        # Measure encoded bytes, not the number of Unicode characters.
        data = content.encode("utf-8")

        if len(data) > self._max_read_bytes:
            raise AccessDeniedError(
                f"Content exceeds the configured limit of "
                f"{self._max_read_bytes} bytes."
            )

        return data

    # -----------------------------------------------------------------------
    # Listing
    # -----------------------------------------------------------------------

    def tree(self, *, max_entries: int = 5000) -> list[FileEntry]:
        """Return authorized files and directories without reading contents."""

        if (
            isinstance(max_entries, bool)
            or not isinstance(max_entries, int)
            or max_entries < 1
        ):
            raise ValueError("max_entries must be a positive integer.")

        entries: list[FileEntry] = []

        # Do not follow directory symlinks while walking the workspace.
        for current, directories, filenames in os.walk(
            self._root,
            followlinks=False,
        ):
            current_path = Path(current)

            # Exclude protected directories and symbolic links from traversal.
            directories[:] = sorted(
                name
                for name in directories
                if name not in self._exclude_dirs
                and not (current_path / name).is_symlink()
            )

            for name in sorted(directories + filenames):
                full_path = current_path / name

                # Do not list symbolic links.
                if full_path.is_symlink():
                    continue

                try:
                    resolved = full_path.resolve(strict=True)
                    relative = resolved.relative_to(self._root).as_posix()

                except (OSError, RuntimeError, ValueError):
                    continue

                # Skip excluded names and file extensions.
                if name in self._exclude_names:
                    continue

                if full_path.suffix.lower() in self._exclude_suffixes:
                    continue

                if full_path.is_dir():
                    # A directory can be listed if a list rule matches the
                    # directory itself or could match a descendant.
                    allowed = self._directory_is_listable(relative)

                    if allowed:
                        entries.append(FileEntry(relative, "directory"))

                elif full_path.is_file() and self._is_allowed(
                    relative,
                    "list",
                ):
                    try:
                        size = full_path.stat().st_size
                    except OSError:
                        continue

                    entries.append(FileEntry(relative, "file", size))

                # Stop once the requested entry limit is reached.
                if len(entries) >= max_entries:
                    return entries

        return entries

    def _directory_is_listable(self, relative_directory: str) -> bool:
        """
        Determine whether a directory is relevant to a list permission rule.

        This allows Duta to show intermediate directories needed to navigate
        toward explicitly permitted files without exposing every directory.
        """
        if self._is_allowed(relative_directory, "list"):
            return True

        directory_prefix = relative_directory.rstrip("/") + "/"

        for pattern, permissions in self._rules:
            if "list" not in permissions:
                continue

            # A literal rule rooted inside this directory means the directory
            # may be needed to navigate to an allowed descendant.
            if pattern.startswith(directory_prefix):
                return True

            # For wildcard rules, test whether a representative descendant
            # path could match. This is a visibility heuristic, not a formal
            # glob-language intersection algorithm.
            if any(
                self._glob_matches(
                    f"{relative_directory}/{probe}",
                    pattern,
                )
                for probe in (
                    "__duta_probe__.py",
                    "main.py",
                    "nested/main.py",
                    "package/__duta_probe__.txt",
                )
            ):
                return True

        return False

    # -----------------------------------------------------------------------
    # Reading
    # -----------------------------------------------------------------------

    def read(self, relative_path: str) -> str:
        """Read one explicitly authorized UTF-8 text file."""

        path, relative = self._resolve(relative_path)

        if not self._is_allowed(relative, "read"):
            raise AccessDeniedError(
                f"Read permission has not been granted for '{relative}'."
            )

        if not path.is_file():
            raise AccessDeniedError("Only files can be read.")

        try:
            data = path.read_bytes()

            # Check the size after reading in case the file changed.
            if len(data) > self._max_read_bytes:
                raise AccessDeniedError(
                    "File exceeds the configured read limit."
                )

            return data.decode("utf-8")

        except UnicodeDecodeError as exc:
            raise AccessDeniedError(
                "File is not valid UTF-8 text and will not be returned."
            ) from exc

        except OSError as exc:
            raise DutaError(f"Could not read file: {relative}") from exc

    # -----------------------------------------------------------------------
    # Creating
    # -----------------------------------------------------------------------

    def create(self, relative_path: str, content: str) -> None:
        """Create a new UTF-8 text file without overwriting an existing file."""

        # Validate the content and its size before touching the filesystem.
        self._validate_content(content)

        if not isinstance(relative_path, str) or not relative_path.strip():
            raise UnsafePathError("Path must be a non-empty relative path.")

        normalized = relative_path.replace("\\", "/")

        if normalized.startswith("/") or (
            len(normalized) > 1 and normalized[1] == ":"
        ):
            raise UnsafePathError("Absolute paths are not allowed.")

        if ".." in normalized.split("/"):
            raise UnsafePathError("Path traversal is not allowed.")

        relative = Path(normalized)

        if relative.name in ("", ".", ".."):
            raise UnsafePathError("A valid filename is required.")

        try:
            # The parent directory must already exist.
            parent = (self._root / relative.parent).resolve(strict=True)
            parent_relative = parent.relative_to(self._root)

        except (OSError, RuntimeError, ValueError) as exc:
            raise UnsafePathError(
                "Parent directory does not exist or resolves outside "
                "the workspace."
            ) from exc

        if not parent.is_dir():
            raise UnsafePathError("Parent path must be a directory.")

        target = parent / relative.name
        relative_target = (parent_relative / relative.name).as_posix()

        # Check exclusions before checking the permission rule.
        self._check_exclusions(relative_target)

        if not self._is_allowed(relative_target, "create"):
            raise AccessDeniedError(
                f"Create permission has not been granted for "
                f"'{relative_target}'."
            )

        try:
            # Exclusive mode refuses to overwrite an existing file and
            # refuses to follow an existing target symlink.
            with target.open(
                "x",
                encoding="utf-8",
                newline="",
            ) as file:
                file.write(content)

        except FileExistsError as exc:
            raise AccessDeniedError(
                "The target already exists; Duta will not overwrite it."
            ) from exc

        except OSError as exc:
            raise DutaError(
                f"Could not create file: {relative_target}"
            ) from exc

    # -----------------------------------------------------------------------
    # Editing
    # -----------------------------------------------------------------------

    def edit(self, relative_path: str, content: str) -> None:
        """
        Replace the contents of an existing UTF-8 text file.

        Editing requires explicit edit permission. This implementation does
        not require read permission as well; edit permission authorizes the
        core to inspect the existing file for text and size validation.
        """

        # Validate replacement content and its byte size.
        self._validate_content(content)

        # Resolve the existing file and apply workspace/exclusion checks.
        path, relative = self._resolve(relative_path)

        if not self._is_allowed(relative, "edit"):
            raise AccessDeniedError(
                f"Edit permission has not been granted for '{relative}'."
            )

        if not path.is_file():
            raise AccessDeniedError("Only existing files can be edited.")

        try:
            # Confirm that the current file is UTF-8 text within the limit.
            original_data = path.read_bytes()

            if len(original_data) > self._max_read_bytes:
                raise AccessDeniedError(
                    "Existing file exceeds the configured read limit."
                )

            try:
                original_data.decode("utf-8")

            except UnicodeDecodeError as exc:
                raise AccessDeniedError(
                    "Binary or non-UTF-8 files cannot be edited."
                ) from exc

            # Create a temporary file in the same directory so replacement
            # occurs on the same filesystem.
            temporary_path: Path | None = None

            try:
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    newline="",
                    dir=path.parent,
                    prefix=".duta-edit-",
                    suffix=".tmp",
                    delete=False,
                ) as temporary_file:
                    temporary_path = Path(temporary_file.name)
                    temporary_file.write(content)

                # Preserve the original file's permission bits where possible.
                original_mode = path.stat().st_mode
                os.chmod(temporary_path, original_mode)

                # Replace the original only after the new contents are written.
                os.replace(temporary_path, path)

            finally:
                # Remove a leftover temporary file after a failed operation.
                if (
                    temporary_path is not None
                    and temporary_path.exists()
                ):
                    try:
                        temporary_path.unlink()
                    except OSError:
                        pass

        except OSError as exc:
            raise DutaError(f"Could not edit file: {relative}") from exc