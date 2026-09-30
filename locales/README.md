# Shared interface translations

Tauri and SwiftUI use the same JSON catalogs. The filename is a language tag
(`en.json`, `ru.json`, `pt-BR.json`); `name` is the native language name shown
in Settings. System, English and Russian are available initially. Selection
is saved separately by each client and changes the interface without restarting
or remounting its forms. System falls back to English if none of the preferred
system languages are available.

## Add a language

1. Copy `locales/en.json` to a new file, for example `locales/de.json`.
2. Change `name` to `Deutsch` and translate **message values**, preserving keys.
3. Set `direction` (`ltr` or `rtl`) and adjust `pluralRules` for the language.
4. Run `npm run i18n:generate` and `npm run test:i18n`.
5. Build the required client. The new language appears in both selectors
   automatically; no Swift or React language list needs editing.

You may omit messages from a partial translation: they fall back to English.
Do not use empty strings for missing translations. Generated outputs are
`src/i18n/catalog.generated.ts` and the native `Resources/Localizations.json`.
Do not edit these outputs directly. Both builds run `i18n:check` and reject
stale outputs, duplicate or unknown message keys and changed placeholders.

## Messages and arguments

Keys are stable English source identifiers, similar to gettext message IDs.
Keep a key when polishing its displayed English value. Use a distinct key
for meanings that need different translations (e.g. `System interfaces` versus
the `System` preference). Add every new message to `en.json` first; literal
calls in the clients are checked against this catalog.

```tsx
tr("Connecting {name}", { name: profile.name })
tr("{count} routes", { count: routes.length })
```

```swift
L10n.text("Connecting {name}", ["name": profile.name])
L10n.text("{count} routes", ["count": String(routes.count)])
```

Use named placeholders; translations may reorder them but must preserve the
names. Inserted values remain literal text and are never interpreted as HTML
or another template. Never translate profile names, interface identifiers,
addresses, configuration paths, protocol values or IPC command identifiers.
For static widgets such as native `AppHeading`/`AppInput`, pass a catalog key;
the widget translates it at render time. Preserve raw selection values and
translate only the displayed label.

## Plural forms

A plural message is an object with CLDR category names. `other` is required;
every form must use the same placeholders, including `count`.

```json
"{count} routes": {
  "one": "{count} маршрут",
  "few": "{count} маршрута",
  "many": "{count} маршрутов",
  "other": "{count} маршрута"
}
```

Both clients evaluate the catalog's rules in order against the absolute count.
The first matching category wins; otherwise `other` is used. Rules support
`all`/`any` arrays of conditions, `integer`, `mod`, inclusive `range` and
`notRange`. Use the existing English/Russian rules as examples. An empty
`pluralRules` list selects `other` for every count. All grammar rules are data;
adding a language with different plural forms does not require client code.

## Verification and boundaries

`npm run test:i18n` checks fallback, regional system tags, plural forms, literal
arguments and catalog validation. Swift tests cover packaged catalogs and
language persistence in temporary preferences. `NETORCH_DESIGN_PREVIEWS`
renders both languages and themes using synthetic data, without modifying
real preferences or starting VPNs. Browser checks exercise live switching and
selection surviving navigation/reload.

Application-owned UI labels, validation messages and dialogs are localized.
Product/protocol names and technical values remain unchanged. Raw errors and
diagnostic messages returned by Rust, a VPN executable or the OS retain their
original text unless they have a matching catalog entry. System dialogs use
the OS's button labels. Translating arbitrary backend text requires structured
message codes rather than guessing from strings.
