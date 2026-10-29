#!/usr/bin/env python3
"""Release lines of Network Orchestrator (see docs/versioning.md).

versions.toml holds one version per line: core, macos, linux, windows.

  versions.py get <line>              print a line's version
  versions.py set <line> <X.Y.Z>      change it and sync everything
  versions.py sync                    write the versions into the crates and configs
  versions.py check                   exit 1 if any crate or config drifted
  versions.py affected [<git-range>]  lines touched by the changed files
"""
import json
import pathlib
import re
import subprocess
import sys

LINES = ("core", "macos", "linux", "windows")

# Crates that belong to one line carry that line's version in Cargo.toml.
CRATES = {
    "crates/core": "core",
    "crates/engine": "core",
    "crates/macos-bridge": "macos",
    "crates/macos-helper": "macos",
    "crates/daemon": "linux",
}
# Crates shipped by two lines: Cargo.toml says 0.0.0 and the build script
# reads versions.toml for the target operating system.
SHARED_CRATES = {
    "crates/cli": ("macos", "linux"),
    "src-tauri": ("linux", "windows"),
}
SHARED_PLACEHOLDER = "0.0.0"
# Tauri merges tauri.<platform>.conf.json into tauri.conf.json, so each
# platform's bundle gets its own line's version.
TAURI_CONFIGS = {
    "linux": "src-tauri/tauri.linux.conf.json",
    "windows": "src-tauri/tauri.windows.conf.json",
}
# Which lines a changed file belongs to, first match wins.
PATH_LINES = [
    ("crates/core/", ("core",)),
    ("crates/engine/", ("core",)),
    ("crates/macos-bridge/", ("macos",)),
    ("crates/macos-helper/", ("macos",)),
    ("macos/", ("macos",)),
    ("crates/daemon/", ("linux",)),
    ("packaging/", ("linux",)),
    ("e2e/linux/", ("linux",)),
    ("crates/cli/src/linux/", ("linux",)),
    ("crates/cli/", ("macos",)),
    ("src-tauri/", ("linux", "windows")),
    ("src/", ("linux", "windows")),
    ("locales/", ("macos", "linux", "windows")),
    ("design/", ("macos", "linux", "windows")),
]
SEMVER = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")


class Repo:
    def __init__(self, root):
        self.root = pathlib.Path(root)

    def versions(self):
        # versions.toml is [line] / version = "x" only, so no TOML library
        # (the system Python on macOS is too old to have one).
        data, section = {}, None
        for raw in (self.root / "versions.toml").read_text().splitlines():
            text = raw.split("#", 1)[0].strip()
            header = re.fullmatch(r"\[([a-z]+)\]", text)
            if header:
                section = header.group(1)
                continue
            pair = re.fullmatch(r'version\s*=\s*"([^"]*)"', text)
            if pair and section:
                data.setdefault(section, {})["version"] = pair.group(1)
        out = {}
        for line in LINES:
            version = data.get(line, {}).get("version")
            if not version or not SEMVER.match(version):
                raise SystemExit(f"versions.toml: [{line}] needs a version like 1.2.3")
            out[line] = version
        return out

    def expected(self):
        """Every managed file and the version it must carry."""
        versions = self.versions()
        out = {}
        for crate, line in CRATES.items():
            out[f"{crate}/Cargo.toml"] = versions[line]
        for crate in SHARED_CRATES:
            out[f"{crate}/Cargo.toml"] = SHARED_PLACEHOLDER
        for line, path in TAURI_CONFIGS.items():
            out[path] = versions[line]
        return out

    def _read_version(self, relative):
        text = (self.root / relative).read_text()
        if relative.endswith(".json"):
            return json.loads(text).get("version")
        match = re.search(r'(?ms)^\[package\].*?^version\s*=\s*"([^"]+)"', text)
        return match.group(1) if match else None

    def check(self):
        problems = []
        for relative, want in self.expected().items():
            path = self.root / relative
            if not path.exists():
                problems.append(f"{relative}: missing (run sync)")
                continue
            have = self._read_version(relative)
            if have != want:
                problems.append(f"{relative}: {have!r}, versions.toml says {want!r}")
        return problems

    def sync(self):
        changed = []
        for relative, want in self.expected().items():
            path = self.root / relative
            if relative.endswith(".json"):
                document = {}
                if path.exists():
                    document = json.loads(path.read_text())
                if document.get("version") == want and path.exists():
                    continue
                document = {"version": want, **{k: v for k, v in document.items() if k != "version"}}
                path.write_text(json.dumps(document, indent=2) + "\n")
            else:
                text = path.read_text()
                new = re.sub(
                    r'(?ms)(^\[package\].*?^)(version\.workspace\s*=\s*true|version\s*=\s*"[^"]*")',
                    lambda m: f'{m.group(1)}version = "{want}"',
                    text,
                    count=1,
                )
                if new == text:
                    continue
                path.write_text(new)
            changed.append(relative)
        return changed

    def set_version(self, line, version):
        if line not in LINES:
            raise SystemExit(f"unknown line {line!r}; one of {', '.join(LINES)}")
        if not SEMVER.match(version):
            raise SystemExit(f"{version!r} is not a semantic version like 1.2.3")
        path = self.root / "versions.toml"
        text = path.read_text()
        new, count = re.subn(
            rf'(?ms)(^\[{line}\].*?^version\s*=\s*)"[^"]*"', rf'\g<1>"{version}"', text, count=1
        )
        if count != 1:
            raise SystemExit(f"versions.toml has no [{line}] version")
        path.write_text(new)
        return self.sync()


def lines_for(path):
    for prefix, lines in PATH_LINES:
        if path.startswith(prefix):
            return lines
    return ()


def affected(paths):
    """Lines touched by `paths`; core changes reach every product."""
    found = set()
    for path in paths:
        found.update(lines_for(path))
    return [line for line in LINES if line in found]


def main(argv):
    repo = Repo(pathlib.Path(__file__).resolve().parent.parent)
    if not argv:
        print(__doc__)
        return 2
    command, rest = argv[0], argv[1:]
    if command == "get" and len(rest) == 1:
        print(repo.versions()[rest[0]])
    elif command == "set" and len(rest) == 2:
        for path in repo.set_version(*rest):
            print("updated", path)
    elif command == "sync":
        for path in repo.sync():
            print("updated", path)
    elif command == "check":
        problems = repo.check()
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if problems else 0
    elif command == "affected":
        span = rest[0] if rest else "origin/main...HEAD"
        files = subprocess.check_output(
            ["git", "-C", str(repo.root), "diff", "--name-only", span], text=True
        ).split()
        print(" ".join(affected(files)))
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
