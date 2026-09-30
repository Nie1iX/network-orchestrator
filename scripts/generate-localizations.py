#!/usr/bin/env python3
"""Validate shared translations and generate the React and native resource catalogs."""
import argparse
import json
import math
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
PLACEHOLDER = re.compile(r"\{([A-Za-z][A-Za-z0-9_]*)\}")
CATEGORIES = {"zero", "one", "two", "few", "many", "other"}


def read_json(path):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate key: {key}")
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError(f"Invalid JSON number: {value}")
    return json.loads(path.read_text(), object_pairs_hook=unique_pairs, parse_constant=invalid_constant)


def validate_condition(value):
    if not isinstance(value, dict) or not value:
        raise ValueError("A plural condition must be a nonempty object")
    if value.keys() - {"all", "any", "integer", "mod", "range", "notRange"}:
        raise ValueError("Unknown plural condition field")
    for name in ("all", "any"):
        if name in value:
            if not isinstance(value[name], list) or not value[name]:
                raise ValueError(f"Plural {name} must be a nonempty array")
            for child in value[name]:
                validate_condition(child)
    if "integer" in value and not isinstance(value["integer"], bool):
        raise ValueError("Plural integer must be a boolean")
    if "mod" in value and (type(value["mod"]) is not int or value["mod"] <= 0):
        raise ValueError("Plural mod must be a positive integer")
    for name in ("range", "notRange"):
        if name in value:
            bounds = value[name]
            if (not isinstance(bounds, list) or len(bounds) != 2
                    or any(type(v) not in (int, float) or not math.isfinite(v) for v in bounds)
                    or bounds[0] > bounds[1]):
                raise ValueError(f"Invalid plural {name}")


def variants(message):
    if isinstance(message, str) and message:
        return [message]
    if (not isinstance(message, dict) or "other" not in message
            or message.keys() - CATEGORIES
            or any(not isinstance(v, str) or not v for v in message.values())):
        raise ValueError("Message must be text or plural forms with an 'other' fallback")
    return list(message.values())


def load_catalogs(directory):
    catalogs = {}
    for path in sorted(directory.glob("*.json")):
        data = read_json(path)
        tag = path.stem
        if not re.fullmatch(r"[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*", tag):
            raise ValueError(f"Invalid language tag: {tag}")
        if data.keys() - {"name", "direction", "pluralRules", "messages"}:
            raise ValueError(f"Unknown catalog field in {tag}")
        if not isinstance(data.get("name"), str) or not data["name"]:
            raise ValueError(f"Missing native language name in {tag}")
        data.setdefault("direction", "ltr")
        data.setdefault("pluralRules", [])
        if data["direction"] not in ("ltr", "rtl"):
            raise ValueError(f"Invalid text direction in {tag}")
        if not isinstance(data["pluralRules"], list):
            raise ValueError(f"Invalid plural rules in {tag}")
        seen = set()
        for rule in data["pluralRules"]:
            if (not isinstance(rule, dict) or rule.keys() != {"category", "when"}
                    or rule["category"] not in CATEGORIES - {"other"}
                    or rule["category"] in seen):
                raise ValueError(f"Invalid/duplicate plural category in {tag}")
            seen.add(rule["category"])
            validate_condition(rule["when"])
        if not isinstance(data.get("messages"), dict):
            raise ValueError(f"Missing messages in {tag}")
        catalogs[tag] = data
    if "en" not in catalogs:
        raise ValueError("The English fallback catalog is required")
    base = catalogs["en"]["messages"]
    for tag, data in catalogs.items():
        for key, message in data["messages"].items():
            if key not in base:
                raise ValueError(f"Unknown message key in {tag}: {key}")
            expected = set(PLACEHOLDER.findall(variants(base[key])[0]))
            for text in variants(message):
                if set(PLACEHOLDER.findall(text)) != expected:
                    raise ValueError(f"Placeholder mismatch in {tag}: {key}")
            if isinstance(message, dict) and "count" not in expected:
                raise ValueError(f"Plural message requires a count placeholder: {key}")
    return catalogs


def validate_source_keys(catalogs):
    pattern = re.compile(r'(?:\btr|L10n\.text)\(\s*("(?:\\.|[^"\\])*")')
    paths = list((ROOT / "src").rglob("*.tsx")) + list((ROOT / "src").rglob("*.ts"))
    paths += list((ROOT / "macos/Sources").rglob("*.swift"))
    for path in paths:
        for match in pattern.finditer(path.read_text()):
            key = json.loads(match[1])
            if key not in catalogs["en"]["messages"]:
                raise ValueError(f"Unregistered UI message in {path.relative_to(ROOT)}: {key}; add it to locales/en.json")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        catalogs = load_catalogs(ROOT / "locales")
        validate_source_keys(catalogs)
    except (ValueError, TypeError, KeyError) as error:
        raise SystemExit(str(error)) from error
    encoded = json.dumps(catalogs, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    outputs = {
        ROOT / "src/i18n/catalog.generated.ts":
            '// Generated by scripts/generate-localizations.py; edit locales/*.json.\n'
            'import type { Catalogs } from "./engine.ts";\n'
            'export const catalogs: Catalogs = ' + encoded.rstrip() + ';\n',
        ROOT / "macos/Sources/NetworkOrchestrator/Resources/Localizations.json": encoded,
    }
    for path, expected in outputs.items():
        if args.check:
            if not path.exists() or path.read_text() != expected:
                raise SystemExit("Stale localization output; run npm run i18n:generate")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(expected)


if __name__ == "__main__":
    main()
