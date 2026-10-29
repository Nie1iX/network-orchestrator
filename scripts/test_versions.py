"""Run with: python3 -m unittest scripts/test_versions.py"""
import json
import pathlib
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import versions  # noqa: E402

CRATE = '[package]\nname = "x"\nversion.workspace = true\nedition.workspace = true\n\n[dependencies]\nserde = { version = "1" }\n'
TOML = "".join(f'[{line}]\nversion = "0.10.0"\n\n' for line in versions.LINES)


class VersionsTest(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        (self.dir / "versions.toml").write_text(TOML)
        for crate in list(versions.CRATES) + list(versions.SHARED_CRATES):
            (self.dir / crate).mkdir(parents=True)
            (self.dir / crate / "Cargo.toml").write_text(CRATE)
        self.repo = versions.Repo(self.dir)

    def test_sync_writes_each_crate_its_lines_version_and_shared_ones_a_placeholder(self):
        self.repo.set_version("linux", "0.11.2")
        cargo = lambda c: (self.dir / c / "Cargo.toml").read_text()
        self.assertIn('version = "0.11.2"', cargo("crates/daemon"))
        self.assertIn('version = "0.10.0"', cargo("crates/core"))
        self.assertIn('version = "0.0.0"', cargo("crates/cli"))
        # Only the package version changes, not a dependency's.
        self.assertIn('serde = { version = "1" }', cargo("crates/daemon"))
        conf = json.loads((self.dir / "src-tauri/tauri.linux.conf.json").read_text())
        self.assertEqual(conf["version"], "0.11.2")
        win = json.loads((self.dir / "src-tauri/tauri.windows.conf.json").read_text())
        self.assertEqual(win["version"], "0.10.0")

    def test_check_reports_drift_and_passes_after_sync(self):
        self.assertTrue(self.repo.check())
        self.repo.sync()
        self.assertEqual(self.repo.check(), [])
        (self.dir / "crates/core/Cargo.toml").write_text(CRATE.replace("version.workspace = true", 'version = "9.9.9"'))
        self.assertEqual(len(self.repo.check()), 1)

    def test_sync_keeps_other_keys_of_a_tauri_config(self):
        path = self.dir / "src-tauri/tauri.linux.conf.json"
        path.write_text(json.dumps({"bundle": {"x": 1}}))
        self.repo.sync()
        data = json.loads(path.read_text())
        self.assertEqual(data["bundle"], {"x": 1})
        self.assertEqual(data["version"], "0.10.0")

    def test_bad_input_is_refused(self):
        with self.assertRaises(SystemExit):
            self.repo.set_version("linux", "1.2")
        with self.assertRaises(SystemExit):
            self.repo.set_version("freebsd", "1.2.3")

    def test_affected_maps_files_to_lines(self):
        self.assertEqual(versions.affected(["crates/core/src/xray.rs"]), ["core"])
        self.assertEqual(versions.affected(["crates/cli/src/linux/hold.rs"]), ["linux"])
        self.assertEqual(versions.affected(["crates/cli/src/connect.rs"]), ["macos"])
        self.assertEqual(
            versions.affected(["src-tauri/src/lib.rs", "macos/README.md"]),
            ["macos", "linux", "windows"],
        )
        self.assertEqual(versions.affected(["docs/testing.md", "README.md"]), [])


if __name__ == "__main__":
    unittest.main()
