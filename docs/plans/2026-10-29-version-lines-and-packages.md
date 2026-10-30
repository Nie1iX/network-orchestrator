# Линии версий и раздельные пакеты (2026-10-29)

Правила версий — в `docs/versioning.md`; здесь — решения, порядок работ и что
проверено.

## Решения владельца

1. Четыре линии версий: **core**, **macos**, **linux**, **windows**. В линию
   macOS входят приложение и `netorch` для macOS, в линию Linux — приложение,
   демон и `netorch` для Linux, в линию Windows — приложение. Все линии
   стартуют с **0.10.0**; до этого версия была одна на всё (`CHANGELOG.md`
   остаётся историей до 0.10.0).
2. Четыре changelog'а: `changelog/{core,macos,linux,windows}.md`.
3. Пакеты Linux: **демон, приложение и CLI — отдельные пакеты**. При установке
   приложения или CLI подходящий демон не трогается; отсутствующий или
   устаревший ставится или заменяется.
4. macOS: `netorch` остаётся внутри `.app` (одна линия с приложением).
   Отдельный артефакт откладывается, потому что установка helper'а
   привязана к бандлу.
5. Windows: CLI нет, линия содержит только приложение.

## Версии и сборка

`versions.toml` — единственный источник; `scripts/versions.py`
(`get`/`set`/`sync`/`check`/`affected`) переносит его в `Cargo.toml` крейтов
одной линии и в `src-tauri/tauri.<linux|windows>.conf.json` (Tauri сам
объединяет платформенный конфиг с основным). У `crates/cli` и `src-tauri` две
линии, поэтому в их `Cargo.toml` стоит `0.0.0`, а `build.rs`
(`build-support/product_version.rs`) подставляет версию линии целевой ОС в
`NETORCH_VERSION`. Проверка расхождений — в `quality gate` и в CI.

Версия ядра (`net_manager_core::VERSION`) показывается в `netorch version`;
продукт указывает в changelog, какую версию ядра он включает.

## Совместимость клиента и демона

`net_manager_engine::linux_compat` проверяет рукопожатие перед командами,
которые идут к демону: другой `PROTOCOL_VERSION` — отказ; нет метода из
`REQUIRED_METHODS` — отказ; демон старше по `major.minor` — предупреждение;
демон новее по `major` — предупреждение. `netorch version` печатает вердикт
(и в `--json`). Список методов берётся из `capabilities` демона, а не из
сравнения номеров, поэтому проверка остаётся верной и при независимых
версиях.

## Пакеты Linux

| Пакет | Содержимое | Зависимости |
| --- | --- | --- |
| `network-orchestrator-daemon` | демон, systemd-юнит, tmpfiles, polkit-политика, закреплённый Xray | `systemd`, `polkitd`, `iproute2`; `Replaces`/`Breaks` `network-orchestrator (<< 0.10.1)` |
| `network-orchestrator` | приложение (Tauri) | `network-orchestrator-daemon (>= X.Y.0)` + библиотеки |
| `netorch` | CLI, автодополнения bash/zsh/fish | `network-orchestrator-daemon (>= X.Y.0)` |

`X.Y` — `major.minor` линии Linux. Менеджер пакетов делает именно то, что
нужно: подходящий демон уже стоит — ничего не происходит; нет или старый —
ставится/обновляется демон. Прежний единый пакет `network-orchestrator`
(содержал демон) заменяется через `Replaces`/`Breaks`. Для одиночного файла
`.deb` (без репозитория) зависимость не подтянется сама: демон нужно
поставить вместе, `apt install ./network-orchestrator-daemon_*.deb ./netorch_*.deb`.

Сборка: `scripts/package-linux-deb.sh` (демон и CLI из готовых бинарников,
`dpkg-deb`), приложение — Tauri (`scripts/build-linux-deb.sh`).

## Проверено (Ubuntu 24.04, контейнеры на work-pc)

См. итог в changelog линии Linux и в отчёте о работе; сценарии установки:
A CLI без демона, B демон и CLI вместе, C подходящий демон уже стоит,
D слишком старый демон, E прежний единый пакет.

## Не сделано и риски

- Сборка приложения (Tauri) без демона внутри и с зависимостью на демон не
  проверена: нужны dev-библиотеки WebKitGTK, на машине разработки их нет.
- Пакеты `.rpm` (Fedora) и Arch (`PKGBUILD` с несколькими пакетами) — по
  этому же образцу, отдельным шагом.
- macOS: пакет `.pkg`/установщик не делается; Windows: NSIS-установщик берёт
  версию из `tauri.windows.conf.json` — на Windows не собирался.
- Хост-ОС без `systemd`/`polkitd` пакет демона не поставит (зависимости).
