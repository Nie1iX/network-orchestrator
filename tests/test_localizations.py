import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("localizations", ROOT / "scripts/generate-localizations.py")
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)


class CatalogValidationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.write("en", {"Hello {name}": "Hello {name}"})

    def write(self, tag, messages):
        (self.path / f"{tag}.json").write_text(json.dumps({"name": tag, "messages": messages}))

    def test_new_language_needs_only_a_catalog_and_can_be_partial(self):
        self.write("de", {})
        catalogs = generator.load_catalogs(self.path)
        self.assertIn("de", catalogs)
        self.assertEqual(catalogs["de"]["direction"], "ltr")

    def test_missing_or_renamed_placeholders_are_rejected(self):
        self.write("ru", {"Hello {name}": "Привет {username}"})
        with self.assertRaisesRegex(ValueError, "Placeholder mismatch"):
            generator.load_catalogs(self.path)

    def test_unknown_keys_are_rejected(self):
        self.write("ru", {"typo": "Ошибка"})
        with self.assertRaisesRegex(ValueError, "Unknown message key"):
            generator.load_catalogs(self.path)

    def test_duplicate_json_keys_are_rejected(self):
        (self.path / "ru.json").write_text('{"name":"ru","messages":{"Home":"A","Home":"B"}}')
        with self.assertRaisesRegex(ValueError, "Duplicate key"):
            generator.load_catalogs(self.path)

    def test_plural_forms_require_other_and_matching_parameters(self):
        self.write("en", {"routes": {"one": "{count} route", "other": "{count} routes"}})
        self.write("ru", {"routes": {"one": "{count} маршрут"}})
        with self.assertRaisesRegex(ValueError, "other"):
            generator.load_catalogs(self.path)

    def test_invalid_plural_rules_are_rejected(self):
        self.write("de", {})
        data = json.loads((self.path / "de.json").read_text())
        data["pluralRules"] = [{"category": "one", "when": {"mod": 0}}]
        (self.path / "de.json").write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "positive integer"):
            generator.load_catalogs(self.path)


if __name__ == "__main__":
    unittest.main()
