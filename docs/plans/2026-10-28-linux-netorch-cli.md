# CLI `netorch` для Linux: Fedora и Ubuntu (2026-10-28)

**Статус (2026-10-29):** этапы 1, 2 и 2б реализованы; работает на work-pc
(Ubuntu 24.04) с реальным демоном. `ls`, `status`, `add`, `rm`, `rename`,
`up`, `down`, `endpoints`, `use`, `switch`, `refresh`, `test`, `completions`;
фоновый сторож `hold` (демон снимает туннель через 30 с после выхода
последнего клиентского процесса пользователя); текстовый агент polkit для SSH.
Тесты на фейковом демоне идут и на macOS (фича `linux-engine`).

Не сделано: `--role/--networks/--dns-domains`, проверка конфликтов через
`connect_plan`, запоминание паролей OpenVPN, Xray SOCKS и статические
маршруты (этап 3), `doctor` и проверка реального трафика после `up`,
установка демона без GUI и пакеты (этап 4).

Продолжение `docs/plans/2026-10-15-19-netorch-cli.md` (macOS). Тот же бинарник
`netorch`, те же команды и `--json`, профили общие с GUI.

## Что уже есть

- `net_manager_engine::linux_engine::LinuxEngine`: connect / disconnect /
  status для WireGuard, OpenVPN и Xray TUN через сокет демона
  (`/run/network-orchestrator/…`, polkit). Роли проверяются и в клиенте, и в
  демоне.
- `net_manager_engine::linux`: построители запросов к демону (общие с
  `src-tauri`), `CredentialSource` для паролей OpenVPN.
- `core::connect_plan`: конфликты, маршруты, интерфейсы, auto-connect.
- `core::profiles::ProfileStore`, `ConfigVault`, `profile_import`,
  `subscription` — чистая логика без UI.
- `crates/cli`: clap-команды, `target` (разбор аргумента: профиль / ссылка /
  файл), `render`, `prompt`, `runstate` — платформенно-нейтральны. Остальное
  (`ctx`, `library`, `connect`, `route`, `service`, `system`) завязано на
  macOS bridge и helper.

## Чего не хватает

1. `main.rs` собирается только под macOS aarch64; на Linux печатает отказ.
2. Импорт (ссылка, подписка, `.conf`/`.ovpn`) на Linux живёт в
   `src-tauri/src/commands/profiles.rs` (`import_configs_into`,
   `import_share_link`, `import_subscription_into`): частично в `core`,
   частично на Tauri `State`. CLI не может вызвать его без Tauri.
3. Xray SOCKS/HTTP и статические маршруты на Linux оркестрируются в процессе
   клиента (`src-tauri`), а не в `engine`.
4. Нет установки демона без пакета GUI, нет `doctor` и completions под Linux.
5. Пароли OpenVPN: `CredentialSource` в GUI — keyring/хранилище приложения;
   для CLI нужен stdin-вариант (как `--auth-stdin` на macOS).

## Принципы

- Тот же бинарник и CLI-контракт; Linux-специфика — в `crates/cli/src/linux/`
  и `crates/engine` (`linux*`). macOS-код не трогаем.
- `netorch` — **непривилегированный клиент демона**, как GUI. `sudo` для
  `up` не нужен; polkit спрашивает через агент (в SSH без агента — понятная
  ошибка с подсказкой). Режима «исполнители в процессе под root» на Linux нет:
  демон уже штатный способ, а пакет ставит его всегда.
- Под root `netorch` не пишет в каталог данных пользователя (как на macOS).
- Секреты не в аргументах и не в логах; stdin для паролей.
- Тесты без реальных туннелей: `Privileged` с фейком, временные каталоги.
  Docker-E2E `e2e/linux` — для демона и сквозного `netorch up/down`.

## Каталог данных

GUI (Tauri `app_data_dir`, идентификатор `com.netmanager.app`):
`$XDG_DATA_HOME/com.netmanager.app` (по умолчанию
`~/.local/share/com.netmanager.app`); dev-вариант
`com.netmanager.app.dev`. Переопределение: `--data-dir` /
`NETORCH_DATA_DIR`. Под `sudo` — домашний каталог `SUDO_UID`.

## Этапы

### Этап 1: каркас и туннели через демон (WG, OpenVPN, Xray TUN)

1. Общая сборка: `main.rs` компилируется на `macos+aarch64` и `linux`; общие
   модули (`args`, `target`, `render`, `prompt`, `runstate`) без `cfg`.
2. `linux/ctx`: корень данных, `ProfileStore`, `ConfigVault`, `find`.
3. `ls`, `status [target]`, `up <saved>`, `down [target|--all]`,
   `completions`. `up` использует `LinuxEngine`, `connect_plan` для проверки
   конфликтов, `--role/--networks/--dns-domains` для вторичных туннелей,
   `--auth-stdin` для OpenVPN.
4. Тесты на `Privileged`-фейке (RED → GREEN): ошибки демона превращаются в
   понятные сообщения, роль secondary без сетей отклоняется до запроса,
   `--json` не содержит секретов.
5. `cargo check/clippy/test` под `x86_64-unknown-linux-gnu`; ручная проверка
   в `e2e/linux`.

### Этап 2: библиотека профилей без Tauri (сделано 2026-10-28: `add`, `rm`, `rename`, `up <link|url|file>`)

1. Вынести из `src-tauri/commands/profiles.rs` в `crates/core` (или новый
   `crates/library`) чистые функции импорта: файлы `.conf`/`.ovpn`,
   `vless://`/`hysteria2://`, подписка (`fetch` + `import_body`),
   переименование, удаление (с очисткой хранилища конфигов). `src-tauri`
   вызывает те же функции — без изменения поведения.
2. `netorch add`, `rm`, `rename`, `up <link|url|file>`, `test`
   (задержки и exit IP).
3. Блокировка `.instance.lock` в каталоге данных, как на macOS, чтобы GUI и
   CLI не правили профили одновременно.

### Этап 2б: серверы внутри подписки (сделано 2026-10-28)

`endpoints`, `use`, `switch`, `refresh`, `test`, `up --endpoint`; выбор без
аргумента на терминале — построчный фильтр (без raw-режима и зависимостей),
не полноэкранный TUI. Режим «Авто» провайдера (балансировщик и
`burstObservatory`) демон не принимает: белый список ключей Xray-конфига в
`crates/daemon/src/xray.rs`; вместо него `test` + `switch`.

Подписки с готовыми Xray-конфигами (`xray-json`, Geodema/Remnawave) демон
отклонял целиком (0 из 93). Решение (вариант А, 2026-10-28):
`core::xray::tun_compatible_config` сводит конфиг к одному серверу
(`proxy` + `freedom`), отбрасывая правила, DNS, observatory и policy панели;
пул «Авто» отказывается с подсказкой. Применяется в
`prepare_linux_xray_tun_params`, то есть и в GUI, и в CLI. Проходит 92 из 93;
регрессия на дрейф списков ключей: `crates/daemon/tests/tun_panel_configs.rs`.
`netorch test` меряет именно этот упрощённый конфиг.

### Этап 3: пользовательские режимы (Xray SOCKS/HTTP, статические маршруты)

1. Перенести оркестрацию Xray SOCKS и статических маршрутов из `src-tauri`
   в `engine` (за трейтами `UserRuntime`), `src-tauri` переходит на неё.
2. `netorch up` для Xray SOCKS — foreground-процесс (state-файл в
   `$XDG_RUNTIME_DIR/netorch-up/`), `--system-proxy` для GNOME/KDE через
   общий код `core::system_proxy`.
3. Статические маршруты через демон.

### Этап 4: сервис, doctor, пакеты

1. `netorch doctor`: демон запущен и версия протокола совпадает, polkit-агент,
   `wireguard-tools`/`openvpn`/`systemd-resolved`, установленный Xray.
2. `sudo netorch service status|restart` (тонкая обёртка над `systemctl`).
   Установку демона выполняют пакеты, не CLI.
3. `netorch route lookup|check`, правила маршрутов, `logs`, `backend`.
4. Пакеты: `/usr/bin/netorch` в `.deb` (Ubuntu), `.rpm` (Fedora), Arch;
   completions для bash/zsh/fish; man-страница.

## Совместимость Fedora / Ubuntu

- Бинарник статически не зависит от дистрибутива (glibc); собираем на
  старейшей поддерживаемой базе (Ubuntu 22.04 LTS) и проверяем на Fedora 44
  через `E2E_DISTRO=fedora`.
- Различия — только в `doctor` и подсказках: `apt install wireguard-tools
  openvpn` против `dnf install wireguard-tools openvpn`; SELinux (Fedora) не
  должен блокировать сокет демона — проверить в E2E.
- Путь сокета, polkit action и имя юнита одинаковы на обоих дистрибутивах.

## Открытые вопросы

1. Группа/правило polkit для запуска без агента (SSH, headless):
   `pkexec`-подобный запрос не сработает; нужна ли отдельная группа
   `netorch` с `auth_self_keep` — решение владельца.
2. `--detach` для Xray SOCKS: systemd user unit или foreground only.
3. Нужен ли `netorch` на Windows — вне этого плана.

## Критерии готовности этапа 1

- `netorch ls/status/up/down` работают с профилем WireGuard и OpenVPN, ранее
  добавленным в GUI, на Ubuntu и Fedora в `e2e/linux`.
- `cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings`,
  `cargo test --workspace` зелёные на macOS и Linux.
- `docs/platform-matrix.md`, `docs/macos-vs-linux-tauri-diff.md` и
  `CHANGELOG.md` обновлены.
