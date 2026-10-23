# Versioning and releases

## Version number

The app follows [Semantic Versioning 2.0.0](https://semver.org/):
`MAJOR.MINOR.PATCH`.

The only source of truth is `[workspace.package].version` in the root
`Cargo.toml`. Every crate inherits it (`version.workspace = true`); Tauri,
`.deb`/`.rpm`/Arch packages and the macOS bundle read it at build time. Do not
copy the version into `package.json`, `tauri.conf.json` or Swift sources.

The app has no public API, so "breaking" is defined by what users and their
data depend on, not by function signatures. A change is **breaking (MAJOR)**
when, after updating, a user must do something or loses something:

- stored data (profiles, vault, settings, journal) cannot be read by the new
  version without a manual step, or cannot be migrated automatically;
- a feature, platform, backend, protocol or setting is removed, or its
  behavior changes so existing profiles, routing rules or `netorch`
  commands/flags/`--json` output stop working as before;
- the app, CLI, privileged helper or daemon stop being compatible with each
  other (`PROTOCOL_VERSION` break) so a partial update leaves a broken install;
- the minimum supported OS version is raised.

Internal refactors, UI redesigns, new options and anything migrated
automatically are not breaking.

| Change | Commit | Bump | Example |
| --- | --- | --- | --- |
| Bug fix, security fix, performance improvement | `fix`, `perf` | PATCH | `1.1.0 → 1.1.1` |
| New user-visible feature, platform or backend | `feat` | MINOR | `1.1.1 → 1.2.0` |
| Breaking change (see above) | `feat!`/`fix!` or `BREAKING CHANGE:` footer | MAJOR | `1.2.0 → 2.0.0` |
| `docs`, `chore`, `style`, `refactor`, `test`, `ci`, `build` | — | none by themselves | — |

While the version is `0.y.z` (pre-1.0), breaking changes bump MINOR instead
of MAJOR, and `docs`/`build`/`test` changes that ship in a release are
covered by a PATCH bump.

Document format versions (`PROFILE_DOCUMENT_VERSION`, `JOURNAL_VERSION`,
`PROTOCOL_VERSION`, …) and pinned backend versions (`MANAGED_XRAY_VERSION`)
are independent of the app version. Changing one of them is a reason to bump
the app version, not a replacement for it.

Pre-release builds may use SemVer suffixes such as `0.3.0-beta.1`.

## Commits

Commit messages follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/),
in English, imperative mood, with a scope where it helps:

```text
<type>(<scope>): <Summary without a trailing period>

<Optional body: why the change is needed and what it affects.>

<Optional footer: BREAKING CHANGE: what breaks and how to migrate.>
```

Types and their effect on the version:

| Type | Meaning | Bump |
| --- | --- | --- |
| `feat` | new feature | MINOR |
| `fix` | bug fix | PATCH |
| `perf` | performance improvement | PATCH |
| `feat!` / `fix!` / `BREAKING CHANGE:` footer | breaking change | MAJOR |
| `docs`, `chore`, `style`, `refactor`, `test`, `build`, `ci` | service changes | none |

Common scopes: `core`, `daemon`, `app`, `ui`, `i18n`, `macos`, `linux`,
`windows`, `xray`, `openvpn`, `wireguard`, `cli`, `e2e`, `packaging`,
`release`.

Rules:

- Every commit has a type prefix. Messages like `fix`, `last commit` or
  `Edit foo.rs` are not allowed: tooling that builds the changelog and
  decides the version skips them, so the work would never reach a release.
- One commit is one logical change and one type. Do not mix `feat` and `fix`
  in a single commit; split them.
- A breaking change always carries `!` and/or a `BREAKING CHANGE:` footer
  that says what breaks for the user and how to migrate.
- Run the quality gate from `AGENTS.md` before pushing; a red gate blocks the
  release.
- Releases are cut only from `main`. Work happens on a personal branch and
  reaches `main` through a pull request; never push to `main` directly.
- How commits are counted depends on how the PR is merged: with **squash**
  the PR title is the only commit and must carry the type prefix; with
  **merge** or **fast-forward** every commit of the branch is read, so each
  one needs its own prefix.

## Release steps

A version bump happens after a group of related commits, not in every commit:

1. Move the entries under `## [Unreleased]` in `CHANGELOG.md` to a new
   `## [X.Y.Z] - YYYY-MM-DD` section
   ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format).
2. Set the new version in the root `Cargo.toml` and refresh `Cargo.lock`
   (`cargo check --workspace`).
3. Run the quality gate from `AGENTS.md`.
4. Commit only the version bump and changelog:
   `chore(release): X.Y.Z`.
5. Create an annotated tag: `git tag -a vX.Y.Z -m "Network Orchestrator X.Y.Z"`.

Tags are pushed only together with the release branch after review; never push
directly to `main`.
