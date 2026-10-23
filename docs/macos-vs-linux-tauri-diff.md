# macOS (нативный клиент) и Linux (Tauri): различия

Состояние: `main` на `b6bb2f8`, версия 0.8.7. Ветка `fix/roman/2026-09-30`
полностью влита в `main` (PR #2), поэтому отдельных коммитов у неё нет.
Приоритет — macOS: реализация и отладка там более полные. Список составлен по
коду, а `docs/platform-matrix.md` использован только как ориентир. Места, где
матрица расходится с кодом, отмечены в разделе 9.

Обозначения: ✅ есть · ⚠️ частично или не проверено · ❌ нет.

## 1. Архитектурные различия

1. **UI.** macOS: SwiftUI/AppKit (`macos/`), без WebView и без HTTP-сервера.
   Linux: Tauri 2 + React/TypeScript (`src/`, `src-tauri/`).
2. **Связь UI с ядром.** macOS: JSON C ABI (`crates/macos-bridge`), вызывается
   из Swift actor, метод `netorch_call`. Linux: Tauri-команды
   (`src-tauri/src/commands/*`, около 100 штук в `generate_handler`).
3. **Слой бизнес-логики.** macOS: типизированный `Engine`
   (`crates/engine`), общий для приложения и CLI. Linux: логика живёт в самом
   Tauri-крейте (`commands/tunnels.rs` ≈3000 строк, `profiles.rs` ≈2900,
   `diagnostics.rs` ≈2000) и `AppState` с runtime-mutex. Общего слоя с macOS нет.
4. **Привилегированная часть.** macOS: launchd-демон `crates/macos-helper`,
   регистрация через `SMAppService.daemon`, проверка подписи и пути приложения.
   Linux: `crates/daemon` (systemd + polkit + Unix socket).
   Протокол у обоих `daemon_protocol`, но набор методов разный.
5. **Привилегии в процессе приложения.** Оба клиента работают без root.
   Исключения на macOS: `netorch` под `sudo` (запускает executors helper'а в
   своём процессе), а также `networksetup` и `scutil` на уровне пользователя.
6. **Как поднимается сетевой стек.** macOS: helper сам создаёт `utun` и
   передаёт fd в Xray (`XRAY_TUN_FD`); WireGuard работает в процессе helper'а
   (userspace, `boringtun`). Linux: netlink-мутации в демоне, `wg`/`ip` из
   `wireguard-tools`, TUN создаёт Xray сам по сгенерированному демоном конфигу.
7. **Модель подключений.** macOS: один primary-тоннель плюс secondary-тоннели,
   которые несут только заданные сети (`TunnelRole`, `networks`). Linux: можно
   запускать несколько профилей одновременно, но роли primary/secondary нет.
8. **Хранилище учётных данных.** macOS: пароли OpenVPN в login Keychain.
   Linux: Secret Service (GNOME Keyring / KWallet), а при его отсутствии — память
   процесса (`openvpn_credentials.rs`). Настройка polkit (`vpn_auth_mode`)
   отвечает только за запрос пароля администратора.
9. **Распространение.** macOS: `.app` собирается `scripts/build-macos-native.sh`,
   подпись ad-hoc, нотаризации нет, arm64 only. Linux: `.deb`, `.rpm`, Arch
   (PKGBUILD).
10. **Установка Xray.** macOS: arm64, скачивание или локальный zip, в
    пользовательский каталог. Linux: x86_64, архив отдаётся демону
    (`xray.install`), он ставит root-owned файлы в `/usr/lib/network-orchestrator/xray`.
11. **Загрузка данных ОС.** macOS: `getifaddrs` и `net-route` (read-only
    инвентарь интерфейсов и маршрутов). Linux: rtnetlink через демон, полная
    картина таблиц и правил.
12. **Тестирование.** macOS: Swift-тесты (`macos/Tests`), офлайн-рендеры 64 PNG,
    `scripts/macos-dev.sh`. Linux: Docker-E2E (`e2e/linux`) и браузерный
    sandbox (`npm run dev:sandbox`).

## 2. Бэкенды и тоннели

| Возможность | macOS | Linux |
|---|---|---|
| Xray, режим SOCKS/HTTP на loopback | ✅ | ✅ |
| Xray TUN | ✅ через helper, один за раз | ✅ управляется демоном, `xrayMode: "tun"` по умолчанию |
| WireGuard | ✅ userspace в helper | ✅ через `wireguard-tools` и демон |
| OpenVPN | ✅ закреплённая копия из бандла, root, без script-хуков | ✅ системный `openvpn` через демон |
| Static routes (`none`) | ❌ executor не написан | ✅ |
| Hysteria2, `vless://`, подписки | ✅ | ✅ |
| NetBird | ✅ через CLI пользователя | ✅ строка в Services (общий код `core::netbird`) |
| Tailscale | ✅ CLI плюс guard `tailscale.protect` | ✅ LocalAPI через демон, без guard'а |
| Чужие VPN-сервисы (incy и др.) | ✅ `scutil --nc start/stop` | ❌ |
| NetworkManager VPN | ❌ | ✅ `nm.list`, `nm.setActive` |
| Primary/secondary тоннели с сетями | ✅ | ✅ (WG, OpenVPN, Xray TUN; демон проверяет и применяет, split DNS через routing-домены) |
| Внешний интерфейс с bypass для endpoint | ❌ | ✅ (`attach`, bypass `/32`, `/128`) |
| Always-on до входа в систему | ❌ | ✅ только WG и static routes |
| Условные правила (CondRules) | ❌ | ✅ |
| Установка backend'ов | ✅ Xray, OpenVPN из бандла | ⚠️ только Xray в managed-режиме, WG и OpenVPN берутся из пакетов |
| Импорт стандартного WireGuard `.conf` из UI | ✅ | ✅ (в матрице помечено «только Windows», см. раздел 9) |

## 3. Сеть, DNS и маршруты

1. **Per-link DNS.** macOS: helper пишет DNS для тоннеля (resolver-слой,
   `dns.rs`, `resolver.rs`, `dnsquery.rs`). Linux: `systemd-resolved` через
   `dns.rs` демона. Реализации разные, и это не общий код.
2. **Таблицы маршрутов и правил.** macOS: только список системных маршрутов.
   Linux: `net.tables` (все таблицы и policy rules), `net_route_add/del`,
   `net_rule_add/del`, `net_explain`.
3. **DNS-диагностика.** Linux: `net_dns_status`, `net_dns_probe`. macOS:
   вкладка DNS на странице Network (`dns_status` из `scutil --dns`,
   `dns_probe`: реальный запрос к серверу, который система выбрала бы для имени,
   с путём и признаком fake-IP), плюс `user_network_settings`.
4. **Intents (`net_intent_*`).** Только Linux.
5. **Policy-маршрутизация и Xray routing.** macOS: редактор правил Xray
   (`RoutingRulesEditor`), `set_routing_rules`, `check_route`, разбор Happ-routing,
   командой `netorch route set`. Linux: те же правила плюс bulk CIDR,
   geo-списки (`geo_assets.rs`), `xray_test_route`.
6. **Восстановление после сбоя.** macOS: helper откатывает маршруты и DNS
   упавшего тоннеля при своём старте (`recovery.cleanup` вручную), UI-запроса
   нет. Linux: `RecoveryPrompt` в UI, отчёт и очистка (`get_recovery_report`,
   `cleanup_recovery`), journal владения в демоне.

## 4. Системные функции

1. **Системный прокси.** macOS: `networksetup` для аппаратных сервисов, с
   snapshot и откатом; не действует, пока packet-tunnel VPN (incy) главный.
   Linux: ✅ GNOME через `gsettings`, KDE через `kwriteconfig` (`system_proxy::linux`); на других окружениях скрыт.
2. **Автозапуск при входе.** macOS: `SMAppService.mainApp`. Linux:
   `tauri-plugin-autostart`.
3. **Tray / menu bar.** Linux: ✅ трей (`tray.rs`, переключение профилей из
   меню). macOS: ✅ `MenuBarExtra` (переключатель на каждое подключение, «Отключить все», открыть окно); Swift-часть не собиралась на Linux.
4. **Автоподключение при старте.** Linux: `auto_connect.rs` (флаг
   `autoConnect` в профиле). macOS: ✅ перенесено (флаг в профиле, запуск один раз при старте, переключатель в карточке подключения); Swift-часть не собиралась на Linux.
5. **Обновление приложения.** Linux: пакетный менеджер (`appUpdates` не
   включён). macOS: кнопка в Настройках отключена, план Sparkle описан в
   `docs/plans/2026-10-15-12-macos-auto-update.md` и не реализован.
6. **Режимы приложения** (combined / orchestrator / manager). Только Linux
   (Settings → Profiles). В macOS переключателя нет.
7. **Single-instance.** Linux: `tauri-plugin-single-instance`. macOS:
   `.instance.lock` в каталоге данных (общий с `netorch`).
8. **Запрос прав.** Linux: polkit, настраиваемый режим (`get/set_vpn_auth_mode`).
   macOS: одноразовое одобрение helper'а в System Settings.

## 5. Пользовательский интерфейс

| Экран / функция | macOS | Linux |
|---|---|---|
| Главная (Home) с кнопкой «подключить последний профиль» | ✅ | ✅ (`Home.tsx`, перенесено) |
| Список подключений master–detail | ✅ | ✅ (Profiles) |
| Sets (сохранённые комбинации) | ✅ (UserDefaults) | ✅ (localStorage) |
| Импорт файла, ссылки, подписки | ✅ | ✅ (`ImportModal`, пакетный) |
| Задержка по endpoint'ам подписки | ✅ | ✅ |
| Exit IP | ✅ (на Home) | ✅ (`ExitIpPanel`, вкладка Monitor) |
| Открыть отдельный Chrome через подключение | ✅ | ❌ (решено не переносить) |
| Копирование `HTTP(S)_PROXY` / `ALL_PROXY` | ✅ | ✅ (на Home, у активных профилей) |
| Вкладка Monitor (графики, трафик) | ✅ страница Monitor: график, скорости туннелей, Exit IP | ✅ |
| Вкладка Logs (лог приложения и демона) | ✅ страница Logs: события приложения, логи подключений, helper'а, NetBird и импорта; фильтры по уровню и тексту | ✅ полная |
| Вкладка Routes: карта, дерево, таблица, flow, lookup | ✅ шесть вкладок | ✅ |
| Вкладка Network: интерфейсы, throughput | ✅ плюс вкл/выкл интерфейса через helper и вкладка DNS | ✅ плюс управление состоянием интерфейса |
| Вкладка Conditions | ❌ | ✅ |
| Диагностика профиля (`diagnose_profile`) | ✅ «Diagnostics» в меню подключения: helper, Xray, статус, handshake, DNS/IPv6, владение helper'а, путь до endpoint'а, анализ конфигурации | ✅ полный отчёт |
| `IntentsPanel`, `SystemTables`, `NmConnectionPanel` | ❌ | ✅ |
| Темы System/Light/Dark, RU/EN | ✅ | ✅ (общие токены и локали) |

## 6. CLI

1. `netorch` (`crates/cli`) есть только на macOS: профили, import, `up`/`down`,
   routing rules, `doctor`, `service install`, `test`.
2. На Linux CLI нет. Для него в `crates/engine` нужны адаптеры `Privileged` и
   `UserRuntime` под демон.

## 7. Безопасность и границы привилегий

1. macOS: helper проверяет подпись и путь клиента. Xray TUN запускается только
   от консольного пользователя (группы, gid, uid сбрасываются до exec), только
   из хеш-проверенной пользовательской установки. OpenVPN запускается от root
   только из закреплённой копии (SHA-256 зашит в helper) и без script-хуков.
2. Linux: проверка через polkit и peer credentials, root-owned Xray-пакет.
3. macOS bridge остаётся непривилегированным: методы `daemon_protocol` в него
   добавлять нельзя.
4. Секреты: общие правила (ConfigVault, redaction). На macOS отдельно —
   Keychain для OpenVPN и stdin/подсказка для `netorch` вместо аргументов.

## 8. Что нужно перенести с macOS на Linux (кандидаты, по убыванию пользы)

1. Общий `Engine` вместо логики внутри `src-tauri` (основа для CLI): начато. Построители запросов к демону вынесены в `crates/engine/src/linux.rs` (их использует и `src-tauri`), поверх них `LinuxEngine` (connect/disconnect/status для WG, OpenVPN, Xray TUN). Решения о подключении (конфликты с запущенными тоннелями, какие маршруты ставить, к какому интерфейсу привязывать) вынесены в `core::connect_plan` и общие для приложения и будущего CLI. Остаются: оркестрация Xray SOCKS и статических маршрутов в процессе клиента, geo-списки, запоминание учётных данных, сам CLI `netorch` для Linux.
2. ~~Роли primary/secondary и сети secondary-тоннелей.~~ Перенесено (см. раздел 2).
3. CLI `netorch` для Linux.
4. ~~Home-экран и быстрый реконнект последнего профиля.~~ Перенесено.
5. ~~NetBird~~ перенесён; управление чужими VPN-сервисами (`scutil --nc`) на Linux не имеет аналога, покрывается NetworkManager.
6. Tailscale guard: на Linux не нужен, Tailscale сам ставит policy-правила (`5270 lookup 52`, `5210 fwmark … lookup main`), приоритетнее правил VPN проекта. Не переносится без E2E в контейнере.
7. ~~Экспорт `*_PROXY`~~ перенесён; открытие браузера через подключение сознательно не переносится.
8. ~~Системный прокси для GNOME/KDE~~ Перенесено.

## 9. Расхождения между кодом и `docs/platform-matrix.md`

1. ~~Нет строк для Home и `*_PROXY`~~ исправлено в матрице.
2. ~~«WireGuard `.conf` import» только Windows~~ исправлено.
3. ~~Устаревший блок Observability~~ исправлено.
4. ~~Блок «plausibly-working… unverified»~~ исправлено.
5. Строка «Recovery prompt» для macOS ⚠️ сформулирована верно, но стоит
   добавить, что откат делает helper при старте.
6. В `get_platform_capabilities` (Tauri) нет полей для NetBird, роли тоннеля и
   Home; при синхронизации матрицы нужно решить, относятся ли они к Tauri.
7. `capabilities` в `crates/macos-bridge/src/lib.rs` возвращает
   `networkMutations: false`, хотя helper мутирует маршруты и DNS. Поле
   отстаёт от реальности.

## 10. Замечание вне задачи

В `macos/README.md`, строка 5, после слов «in this» вклеен адрес
`https://sub.<домен>/...` с токеном, продублированный дважды. Файл
закоммитован (последний коммит — `52ad2c0`). Если это реальная подписка, токен
стоит считать скомпрометированным и убрать из истории.

## 11. Порядок переноса Linux-функций на macOS

Правило: логика, которую можно проверить без macOS, сначала живёт в
`crates/core` с тестами (запускаются на Linux); `macos-bridge` и Swift
остаются тонкими обёртками. Код моста и Swift на Linux не собирается, поэтому
каждый шаг ниже требует сборки и прогона `scripts/macos-dev.sh check|test` на
macOS перед коммитом.

1. ✅ Автоподключение при старте (`core::connect_plan::auto_connect_candidates`,
   `ProfileStore::set_auto_connect`, команда `set_auto_connect`, Swift).
2. ✅ Меню-бар (Tray): `MenuBarExtra`, фоновый опрос состояния перенесён из `ContentView` в `AppModel.startMonitoring()`.
3. ✅ Recovery: при запуске `recovery_report` (`core::recovery::helper_report` + `Engine::recovery_report`) показывает диалог с остатками, «Clean up» вызывает `recovery.cleanup`. Попутно исправлено: `recover()` в helper'е убивал живой туннель.
4. ✅ Logs и Monitor: Monitor (`ThroughputSampler`, метод моста `interfaces`) и Logs (`LogLines`; источники — события приложения (`AppLog`), лог каждого подключения (у WireGuard — `wireguard.log`, который пишет helper), лог helper'а, NetBird и импорта).
5. ✅ Диагностика профиля: `core::diagnostics` (проверки как чистые функции), `Engine::diagnose`, метод моста `diagnose`, лист в Swift. Общие проверки (путь до endpoint'а, статический анализ, endpoints/listeners, системный прокси) открыты как публичные функции; `src-tauri/.../diagnostics.rs` пока на своей копии — переключить его на них можно там, где собирается Tauri (Linux/Windows), и удалить дубликат.
6. ⏸ Режимы приложения (combined/orchestrator/manager): отложено до п.9. Режим — только UI-фильтр (`localStorage`): `orchestrator` прячет управляемые бэкенды и блокирует подключение всего, кроме статических маршрутов (`none`); `manager` прячет список NetworkManager. На macOS бэкенда `none` и внешнего интерфейса пока нет, поэтому `orchestrator` заблокировал бы все подключения, а `manager` скрывал бы лишь incy/NetBird/Tailscale. Вернуться после п.9.
7. Сеть. Решено разбить: **7a ✅ DNS-диагностика** (`core::dns_diag`,
   `core::dns_probe`, методы моста `dns_status`/`dns_probe`, вкладка DNS; без
   helper'а и привилегий). **7b ✅** — включение/выключение интерфейса через
   helper (`link.set_state`: нельзя loopback и устройство туннеля, которым
   управляет helper; кнопка в карточке интерфейса с подтверждением, усиленным для
   интерфейса с default route). Таблицы и правила на macOS не имеют
   аналога (один FIB), `route add/del` и explain отложены до п.8–9.
8. Intents и Conditions — поверх п.7 (оценка условий по адресам интерфейсов,
   `SCDynamicStore` вместо netlink).
9. Static routes, always-on, внешний интерфейс с bypass, geo-списки.

NetworkManager-панель не переносится: на macOS аналога нет.
