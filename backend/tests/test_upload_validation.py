"""Unit tests for the practice-text upload validation rules.

These tests exercise validate_upload directly. They do not create a
database, touch the real vault or write any files to disk.
"""

import hashlib
import unittest

from backend.app.security.upload_validation import (
    MAX_UPLOAD_BYTES,
    validate_upload,
)


CONTENT = b"Fictional SecureVault practice note.\n"


class UploadValidationTests(unittest.TestCase):

    def test_accepts_simple_text_file(self):
        metadata = validate_upload("notes.txt", CONTENT)

        self.assertEqual(metadata["filename"], "notes.txt")
        self.assertEqual(metadata["size_bytes"], len(CONTENT))
        self.assertEqual(
            metadata["sha256"],
            hashlib.sha256(CONTENT).hexdigest()
        )

    def test_metadata_contains_only_expected_keys(self):
        metadata = validate_upload("notes.txt", CONTENT)

        self.assertEqual(
            set(metadata),
            {"filename", "size_bytes", "sha256"}
        )

    def test_hash_changes_with_content(self):
        first = validate_upload("notes.txt", b"first version")
        second = validate_upload("notes.txt", b"second version")

        self.assertNotEqual(first["sha256"], second["sha256"])

    def test_rejects_empty_filename(self):
        with self.assertRaises(ValueError):
            validate_upload("", CONTENT)

    def test_rejects_filename_over_100_characters(self):
        with self.assertRaises(ValueError):
            validate_upload("a" * 97 + ".txt", CONTENT)

    def test_accepts_filename_of_exactly_100_characters(self):
        metadata = validate_upload("a" * 96 + ".txt", CONTENT)

        self.assertEqual(len(metadata["filename"]), 100)

    def test_rejects_directory_paths(self):
        for filename in (
            "folder/notes.txt",
            "folder\\notes.txt",
            "..\\notes.txt",
        ):
            with self.subTest(filename=filename):
                with self.assertRaises(ValueError):
                    validate_upload(filename, CONTENT)

    def test_rejects_non_txt_extension(self):
        for filename in ("notes.md", "notes.txt.exe", "notes"):
            with self.subTest(filename=filename):
                with self.assertRaises(ValueError):
                    validate_upload(filename, CONTENT)

    def test_rejects_reserved_device_names(self):
        for filename in ("con.txt", "NUL.txt", "LPT1.txt"):
            with self.subTest(filename=filename):
                with self.assertRaises(ValueError):
                    validate_upload(filename, CONTENT)

    def test_rejects_reserved_device_names_with_extra_segments(self):
        # Windows ignores the extension, so these still resolve to devices.
        for filename in (
            "CON.backup.txt",
            "com1.daily.txt",
            "aux.v2.txt",
        ):
            with self.subTest(filename=filename):
                with self.assertRaises(ValueError):
                    validate_upload(filename, CONTENT)

    def test_accepts_names_that_only_start_with_reserved_tokens(self):
        for filename in ("console.txt", "lpt10.txt", "nullable.txt"):
            with self.subTest(filename=filename):
                metadata = validate_upload(filename, CONTENT)
                self.assertEqual(metadata["filename"], filename)

    def test_rejects_non_bytes_content(self):
        with self.assertRaises(ValueError):
            validate_upload("notes.txt", "plain string")

    def test_rejects_empty_content(self):
        with self.assertRaises(ValueError):
            validate_upload("notes.txt", b"")

    def test_accepts_content_at_size_limit(self):
        content = b"a" * MAX_UPLOAD_BYTES

        metadata = validate_upload("notes.txt", content)

        self.assertEqual(metadata["size_bytes"], MAX_UPLOAD_BYTES)

    def test_rejects_content_over_size_limit(self):
        content = b"a" * (MAX_UPLOAD_BYTES + 1)

        with self.assertRaises(ValueError):
            validate_upload("notes.txt", content)

    def test_rejects_invalid_utf8(self):
        with self.assertRaises(ValueError):
            validate_upload("notes.txt", b"\xff\xff\xff")

    def test_rejects_nul_bytes(self):
        with self.assertRaises(ValueError):
            validate_upload("notes.txt", b"before\x00after")


if __name__ == "__main__":
    unittest.main()
