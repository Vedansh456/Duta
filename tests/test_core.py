import tempfile
import unittest
from pathlib import Path

from duta import Duta, AccessDeniedError, UnsafePathError


class DutaCoreTests(unittest.TestCase):
    """Tests for Duta's file access and permission controls."""

    def setUp(self):
        """Create a temporary workspace for each test."""
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

        (self.root / "src").mkdir()
        (self.root / "src" / "main.py").write_text(
            "print('hello')", encoding="utf-8"
        )
        (self.root / "notes.txt").write_text(
            "private notes", encoding="utf-8"
        )
        (self.root / ".env").write_text(
            "SECRET=value", encoding="utf-8"
        )

        self.duta = Duta(self.root)

    def tearDown(self):
        """Remove the temporary workspace after each test."""
        self.temp.cleanup()

    # ---------------------------------------------------------
    # Reading tests
    # ---------------------------------------------------------

    def test_read_allowed_file(self):
        self.duta.allow("src/**/*.py")

        self.assertEqual(
            self.duta.read("src/main.py"),
            "print('hello')",
        )

    def test_read_denied_without_allow_rule(self):
        with self.assertRaises(AccessDeniedError):
            self.duta.read("notes.txt")

    def test_traversal_rejected(self):
        self.duta.allow("**/*.txt")

        with self.assertRaises(UnsafePathError):
            self.duta.read("../outside.txt")

    def test_sensitive_file_excluded_even_if_allowed(self):
        self.duta.allow("**/*")

        with self.assertRaises(AccessDeniedError):
            self.duta.read(".env")

    def test_read_permission_can_be_omitted(self):
        self.duta.allow("src/**/*.py", permissions=("list",))

        with self.assertRaises(AccessDeniedError):
            self.duta.read("src/main.py")

    # ---------------------------------------------------------
    # File creation tests
    # ---------------------------------------------------------

    def test_create_authorized_file(self):
        self.duta.allow("src/**/*.py", permissions=("create",))

        self.duta.create("src/new_feature.py", "print('created')")

        self.assertEqual(
            (self.root / "src" / "new_feature.py").read_text(
                encoding="utf-8"
            ),
            "print('created')",
        )

    def test_create_denied_without_permission(self):
        with self.assertRaises(AccessDeniedError):
            self.duta.create(
                "src/new_feature.py",
                "not authorized",
            )

    def test_create_does_not_overwrite_existing_file(self):
        self.duta.allow("src/**/*.py", permissions=("create",))

        with self.assertRaises(AccessDeniedError):
            self.duta.create(
                "src/main.py",
                "overwrite attempt",
            )

        self.assertEqual(
            (self.root / "src" / "main.py").read_text(
                encoding="utf-8"
            ),
            "print('hello')",
        )

    # ---------------------------------------------------------
    # File editing tests
    # ---------------------------------------------------------

    def test_edit_authorized_file(self):
        """An explicitly authorized edit should update the file."""
        self.duta.allow("src/**/*.py", permissions=("edit",))

        self.duta.edit("src/main.py", "print('updated')")

        self.assertEqual(
            (self.root / "src" / "main.py").read_text(
                encoding="utf-8"
            ),
            "print('updated')",
        )

    def test_edit_denied_without_permission(self):
        """Editing without permission must leave the file unchanged."""
        with self.assertRaises(AccessDeniedError):
            self.duta.edit(
                "src/main.py",
                "unauthorized change",
            )

        self.assertEqual(
            (self.root / "src" / "main.py").read_text(
                encoding="utf-8"
            ),
            "print('hello')",
        )

    def test_edit_sensitive_file_denied_even_if_allowed(self):
        """Explicit permissions must not override sensitive exclusions."""
        self.duta.allow(".env", permissions=("edit",))

        with self.assertRaises(AccessDeniedError):
            self.duta.edit(".env", "SECRET=changed")

        self.assertEqual(
            (self.root / ".env").read_text(encoding="utf-8"),
            "SECRET=value",
        )

    def test_edit_does_not_create_missing_file(self):
        """Editing must not silently create a missing file."""
        self.duta.allow("src/**/*.py", permissions=("edit",))

        with self.assertRaises(FileNotFoundError):
            self.duta.edit("src/missing.py", "new content")

        self.assertFalse(
            (self.root / "src" / "missing.py").exists()
        )

    def test_edit_rejects_oversized_content(self):
        """Editing must reject content exceeding the configured limit."""
        self.duta = Duta(self.root, max_read_bytes=10)
        self.duta.allow("src/**/*.py", permissions=("edit",))

        with self.assertRaises(AccessDeniedError):
            self.duta.edit("src/main.py", "x" * 11)

        # The original file must remain unchanged.
        self.assertEqual(
            (self.root / "src" / "main.py").read_text(
                encoding="utf-8"
            ),
            "print('hello')",
        )


if __name__ == "__main__":
    unittest.main()