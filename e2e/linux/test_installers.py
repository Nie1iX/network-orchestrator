"""Real APT transitions, only inside run_installers.sh's disposable container.

Packages contain synthetic text files, not VPN executables or systemd units.
Only systemctl is faked; APT, dpkg, version queries and auto marks are real.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.test_linux_installers import DAEMON, deb, fixture_source  # noqa: E402


@unittest.skipUnless(os.environ.get("NETORCH_INSTALLER_APT_E2E") == "1" and Path("/.dockerenv").exists(),
                     "Requires run_installers.sh's disposable container")
class InstallerAptTest(unittest.TestCase):
    def test_install_update_reuse_and_remove_one_client(self):
        arch = subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "bin"
            tools.mkdir()
            service_log = root / "service.log"
            systemctl = tools / "systemctl"
            systemctl.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$NETORCH_SERVICE_LOG"\n')
            systemctl.chmod(0o755)
            env = {**os.environ, "PATH": str(tools) + ":" + os.environ["PATH"],
                   "NETORCH_SERVICE_LOG": str(service_log), "DEBIAN_FRONTEND": "noninteractive"}

            def version(package):
                return subprocess.check_output(["dpkg-query", "-W", "-f=${Version}", package], text=True)

            def build(release):
                source = root / ("source-" + release)
                fixture_source(source, release)
                packages = root / release
                packages.mkdir()
                for package in [DAEMON, "netorch", "network-orchestrator"]:
                    deb(packages / f"{package}.deb", package, release, arch)
                subprocess.run([sys.executable, str(source / "scripts/package-linux-installers.py"),
                                "--daemon", str(packages / f"{DAEMON}.deb"),
                                "--cli", str(packages / "netorch.deb"),
                                "--gui", str(packages / "network-orchestrator.deb"),
                                "--output-dir", str(packages)], env=env, check=True)
                return packages

            old, new = build("0.10.0"), build("0.10.1")

            def install(packages, package, release, check=True):
                return subprocess.run(["sh", str(packages / f"{package}-{release}-{arch}.run"), "--yes"],
                                      env=env, check=check)

            # An installation owns user data independently of client packages.
            profiles = Path.home() / ".local/share/com.netmanager.app/profiles.json"
            profiles.parent.mkdir(parents=True)
            profiles.write_text('{"profiles": []}\n')
            install(old, "netorch", "0.10.0")
            install(old, "network-orchestrator", "0.10.0")
            self.assertEqual(version(DAEMON), "0.10.0")

            install(new, "netorch", "0.10.1")
            self.assertEqual(version("netorch"), "0.10.1")
            self.assertEqual(version(DAEMON), "0.10.1")
            self.assertEqual(version("network-orchestrator"), "0.10.0")
            daemon_fixture = Path(f"/usr/share/netorch-installer-fixture/{DAEMON}.txt")
            daemon_fixture.write_text("Must survive installing/updating another client")
            install(new, "network-orchestrator", "0.10.1")
            self.assertEqual(daemon_fixture.read_text(), "Must survive installing/updating another client")
            install(new, "netorch", "0.10.1")
            self.assertEqual(daemon_fixture.read_text(), "Must survive installing/updating another client")
            self.assertNotEqual(install(old, "netorch", "0.10.0", check=False).returncode, 0)
            self.assertEqual(version("netorch"), "0.10.1")
            self.assertIn(DAEMON, subprocess.check_output(["apt-mark", "showauto"], text=True).splitlines())
            subprocess.run(["apt-get", "--yes", "remove", "network-orchestrator"], check=True, env=env)
            self.assertEqual(version("netorch"), "0.10.1")
            self.assertEqual(version(DAEMON), "0.10.1")
            self.assertEqual(profiles.read_text(), '{"profiles": []}\n')
            self.assertNotIn("restart", service_log.read_text())


if __name__ == "__main__":
    if os.environ.get("NETORCH_INSTALLER_APT_E2E") != "1" or not Path("/.dockerenv").exists():
        sys.exit("Use e2e/linux/run_installers.sh; never run this scenario on the host.")
    unittest.main()
