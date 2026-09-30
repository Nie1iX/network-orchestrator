# Versioning and releases

## Version number

The app follows [Semantic Versioning 2.0.0](https://semver.org/):
`MAJOR.MINOR.PATCH`.

The only source of truth is `[workspace.package].version` in the root
`Cargo.toml`. Every crate inherits it (`version.workspace = true`); Tauri,
`.deb`/`.rpm`/Arch packages and the macOS bundle read it at build time. Do not
copy the version into `package.json`, `tauri.conf.json` or Swift sources.

While the version is `0.y.z`, the project is pre-1.0:

| Change | Bump | Example |
| --- | --- | --- |
| Bug fix, security fix, build/test/docs-only change that ships | PATCH | `0.1.1 → 0.1.2` |
| New user-visible feature, new platform or backend | MINOR | `0.1.2 → 0.2.0` |
| Incompatible change: store/journal format without migration, daemon protocol break, removed feature or setting | MINOR (pre-1.0) | `0.2.0 → 0.3.0` |

From `1.0.0` onward, incompatible changes bump MAJOR, features bump MINOR and
fixes bump PATCH.

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
```

Types: `feat`, `fix`, `perf`, `refactor`, `style`, `test`, `docs`, `build`,
`ci`, `chore`. Mark incompatible changes with `!` after the type/scope and a
`BREAKING CHANGE:` footer. Common scopes: `core`, `daemon`, `app`, `ui`,
`i18n`, `macos`, `linux`, `windows`, `xray`, `openvpn`, `wireguard`, `e2e`,
`packaging`, `release`.

Each commit is one logical change. `feat` commits map to MINOR, `fix`/`perf`
to PATCH and `!` to an incompatible bump, as in the table above.

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
