# Спецификация: доведение приложения до полноценного клиента (Ubuntu-first)

**Дата:** 2026-09-22 · **Статус:** согласовано (решения владельца — §8)

## 0. Цель и Definition of Done

Одно desktop-приложение, которое объединяет:

1. **Xray-клиент** — импорт share-link/подписок, выбор endpoint, SOCKS/HTTP
   inbound, TUN-режим, domain/IP routing rules (базовые сценарии v2rayN /
   Nekoray / Hiddify);
2. **WireGuard-клиент** — импорт `.conf`, split и full tunnel, DNS, статус handshake;
3. **OpenVPN-клиент** — импорт `.ovpn`, логин/пароль, pushed routes/DNS,
   split и full tunnel;
4. **менеджер локальных маршрутов** — статические CIDR-маршруты через
   выбранный интерфейс/шлюз, их сохранение и повторное применение, route map.

Целевая платформа приёмки — **Ubuntu 26.04 LTS** (GNOME/Wayland,
systemd-resolved, NetworkManager — на VM). **Ubuntu-first:** Windows не
блокирует этапы, временная поломка Windows-функциональности допустима;
паритет — отдельной фазой после приёмки на Ubuntu (§8, Q4).

**DoD:**

- все юзеркейсы из §6 проходят на чистой Ubuntu 26.04 VM с приложением,
  установленным из `.deb`; smoke-набор (Q6) проходит на Debian stable и Arch;
- quality gate из `AGENTS.md` зелёный на Linux;
- Linux E2E harness (§5.I) на Docker-стенде зелёный;
- README/`docs/security.md`/`docs/testing.md`/`AGENTS.md` описывают Linux.

## 1. Текущее состояние (снимок 2026-09-22)

Проверено в этой сессии на Ubuntu 26.04:

- **executed:** `cargo check --workspace --all-targets` — ок (включая
  `src-tauri`, webkit2gtk 2.52 / gtk3 уже установлены); `cargo test
  --workspace` — 213 (core) + 64 (app) + 12 (linux-helper) passed;
  `npm run build` — ок.
- **executed:** `pkexec` не установлен (есть только `polkitd`); linux-helper
  и polkit policy не установлены; `openvpn` не установлен; `wg`/`wg-quick`
  и `xray` 26.3.27 есть.
- Изменения Linux-порта (`policy.rs`, `vpn.rs`, `config_security.rs`, …,
  `crates/linux-helper`) лежат незакоммиченными в `main`.

| Возможность | Windows | Ubuntu | Основание |
|---|---|---|---|
| Explorer: интерфейсы, маршруты, LPM lookup, auto-refresh | есть | есть (netlink) | inspected + тесты |
| Explorer: interface up/down | есть | **сломано**: `ip link` без привилегий | inspected `explorer.rs:808` |
| Профили, vault, ревизии | есть (ACL + DPAPI) | есть (chmod 600/700, plaintext Xray) | inspected |
| Static-routes профиль | есть | через `pkexec` + helper (не установлен) | inspected |
| Маршруты с gateway (`via`) | **нет** (NextHop = 0, on-link) | **нет** (`ip route … dev`) | inspected `policy.rs:228,433` |
| WireGuard connect | `wireguard.exe` service | **нет** (ищет `wireguard.exe`) | inspected `vpn.rs:297` |
| OpenVPN connect | child + Job Object | запускается от пользователя → нет прав на tun | inferred |
| OpenVPN `auth-user-pass` | нет UI для ввода | нет | inspected (только vault asset) |
| Xray SOCKS | есть | должно работать без root | inferred, не прогонялось |
| Xray TUN | есть (Wintun) | **сломано**, см. B2/B3 | executed/inferred |
| Xray протоколы | только `vless://` (tcp/ws/grpc; none/tls/reality) | то же | inspected `xray.rs:69-75` |
| Подписки | только `vless://`, без refresh | то же | inspected `profiles.rs:517` |
| DNS туннеля (WG `DNS=`, OpenVPN `dhcp-option`) | не применяется | не применяется | inspected (нет кода) |
| Full tunnel без петли | не решено явно | не решено | inferred, см. B6 |
| System proxy | есть (HKCU) | отказались (план 2026-09-22-01) | — |
| Auto-connect | поле `auto_connect` есть, **не используется** | то же | inspected grep |
| Tray, автозапуск | нет | нет | inspected |
| Recovery после краша | WG-сервисы, маршруты, proxy | только маршруты; дочерние процессы не удерживаются | inspected |
| Managed Xray install | Windows x86_64 | нет | inspected `system.rs` cfg |
| Пакет | NSIS | `.deb`/AppImage без helper'а и policy | inspected `tauri.conf.json` |
| Updater | `endpoints: []` — фактически выключен | то же | inspected |

## 2. Дефекты и блокеры, найденные при обзоре

| ID | Проблема | Последствие | Тег |
|---|---|---|---|
| B1 | `probe_openvpn_routes` вызывает `resolve_openvpn_executable(None)` и игнорирует настроенный путь | probe не находит OpenVPN, если путь задан вручную | inspected `tunnels.rs:519` |
| B2 | TUN inbound генерируется с `interfaceName`/`ip`/`mtu`, а Xray 26 ожидает `name`/`MTU` и **не назначает IP** | интерфейс будет `xray0`, приложение ждёт `xray-tun` → timeout; адреса нет | inferred (json-теги из бинарника xray 26.3.27); подтвердить E2E |
| B3 | `xray run -test` с TUN inbound пытается создать устройство | без `CAP_NET_ADMIN` валидация падает: `failed to create server > operation not permitted` | **executed** |
| B4 | `is_elevated()` на не-Windows всегда `Ok(true)` | UI не предупреждает; TUN/OpenVPN падают поздно с EPERM | inspected `elevation.rs:137` |
| B5 | OpenVPN запускается как обычный child | на Linux нет прав на создание tun/ifconfig | inferred (openvpn не установлен) |
| B6 | Full tunnel (`0.0.0.0/0`, `redirect-gateway`, Xray TUN) ставится обычным маршрутом без исключения транспорта | трафик самого туннеля до сервера уходит в туннель → петля. На Linux kernel WG/OpenVPN/Xray не привязывают сокет к физическому интерфейсу | inferred |
| B7 | DNS туннелей не применяется | full tunnel: DNS идёт мимо туннеля (leak) или внутренние имена не резолвятся | inspected |
| B8 | Маршруты ставятся по одному процессу `pkexec` на маршрут | медленно на больших списках, частичный откат через ту же цепочку | inspected `policy.rs` |
| B9 | Маршрут всегда on-link (без next hop) | статический маршрут через Ethernet/Wi-Fi с шлюзом не работает (ARP на каждый адрес) | inspected |
| B10 | OpenVPN без `interface_name` → маршруты не ставятся (только notice) | pushed routes теряются | inspected `tunnels.rs:337` |
| B11 | Поле `auto_connect` не используется; нет tray | нет «включил и забыл» | inspected |
| B12 | Пользовательские `.ovpn` `up`/`down`, WG `PostUp`/`PreUp` | при запуске от root = выполнение произвольного кода | inferred (относится к будущему root-запуску) |
| B13 | AppImage не может установить daemon, systemd unit и polkit policy | tunnel-функции в AppImage невозможны | inferred |
| B14 | Название продукта: «Network Orchestrator» / «Network Manager» / «Network Explorer» | путаница в UI, пакете, polkit | inspected |
| B15 | `csp: null` | нет CSP | inspected |

## 3. Архитектурные решения

### D1. Привилегированный слой на Linux (главное решение)

Помимо маршрутов root/`CAP_NET_ADMIN` нужны для OpenVPN, WireGuard
(создание link, `wg setconf`), Xray TUN, DNS (`resolvectl`) и interface
up/down. Посылка плана 2026-09-22-01 («root нужен только для маршрутов»)
больше не выполняется, поэтому одноразовые вызовы `pkexec helper route-add`
не подходят для долгоживущих root-процессов.

**Решение (владелец, 2026-09-22): системная служба.** Так устроены
NetworkManager, Mullvad и Tailscale.

- `network-orchestrator-daemon`: новый crate, который вырастает из
  `crates/linux-helper` и линкует `net-manager-core`. Работает как systemd
  unit `network-orchestrator.service` от root с hardening:
  `CapabilityBoundingSet` ограничен сетевыми capabilities, `ProtectSystem=strict`,
  `ReadWritePaths` только на свои каталоги. Совместимость hardening'а с
  OpenVPN/Xray/resolved проверяется в E2E.
- **Разделение ответственности.** Профили и vault остаются в приложении (в
  домашнем каталоге пользователя). Runtime на Linux переезжает в daemon:
  `TunnelManager`, `PolicyManager`, DNS, журнал владения. На connect
  приложение передаёт профиль и содержимое конфига. `RuntimeState` в
  `src-tauri` работает через абстракцию: in-process на Windows, daemon client
  на Linux.
- **Транспорт.** Unix socket `/run/network-orchestrator/daemon.sock`,
  версионированный JSON-протокол (запрос/ответ + поток событий статуса,
  который заменяет polling в UI). Клиент идентифицируется через
  `SO_PEERCRED`, каждое действие авторизуется через polkit
  `CheckAuthorization`.
- **Polkit actions.** Как у NetworkManager:
  - `…connect-profile` (свои туннели) — `allow_active=yes`;
  - `…system-network` (static routes на физических интерфейсах,
    interface up/down) — `auth_admin_keep`;
  - `allow_any`/`allow_inactive` — `auth_admin`.
- **Жизненный цикл.** Туннели принадлежат daemon'у (с учётом uid владельца)
  и **переживают закрытие и краш UI**. При старте UI подключается к daemon'у
  и получает текущее состояние. Опционально «always-on»-профили поднимаются
  при загрузке системы (§5.F3).
- **Crash safety.** Daemon ведёт журнал владения. После рестарта (systemd
  `Restart=on-failure`) он сначала убирает leftovers, потом заново поднимает
  always-on-профили.
- Разовый `pkexec linux-helper route-add` и зависимость от `pkexec`
  удаляются.

### D2. Full tunnel без петли (Linux)

Схема как у `wg-quick`: маршруты туннеля кладутся в отдельную таблицу `T`
(на профиль), правила `ip rule add not fwmark M table T` +
`ip rule add table main suppress_prefixlength 0`. Транспорт каждого
backend'а помечается `M`: WG — `wg set <if> fwmark M`, OpenVPN — `--mark M`,
Xray — `streamSettings.sockopt.mark` на всех outbound'ах, кроме
`freedom`/`blackhole`. Схема устойчива к смене сети, в отличие от «/32 до
endpoint через текущий шлюз».
Split-маршруты, не покрывающие endpoint, остаются в `main`, как сейчас.
**Следствие:** route map и lookup на Linux должны учитывать `ip rule` и
таблицы, а не только `main`.

### D3. DNS

systemd-resolved per-link: `resolvectl dns <if> …`, `resolvectl domain <if>
~.` для full tunnel (default-route), конкретные домены для split,
`resolvectl revert <if>` при отключении. Источники DNS: WG `DNS =`, OpenVPN
`dhcp-option DNS/DOMAIN`, Xray TUN — DNS из профиля (по умолчанию `1.1.1.1`).
Все вызовы идут через daemon. На Debian systemd-resolved по умолчанию не
включён: если resolved не активен, daemon сообщает об этом в diagnostics, а
UI предупреждает, что DNS туннеля не применён (подсказка `apt install
systemd-resolved`). Fallback на `resolvconf` не делаем.

### D4. Xray TUN

Xray запускается через daemon от root. IP-адрес, MTU, маршруты и DNS
назначает приложение, Xray только создаёт устройство. Схема inbound —
`{"protocol":"tun","settings":{"name":…,"MTU":…}}`. Loop prevention по D2
(`sockopt.mark`). `-test` запускается в daemon'е.

### D5. Сторонний код от root запрещён

- WireGuard поднимаем без `wg-quick`: `ip link add … type wireguard`,
  `wg setconf` с очищенным конфигом (`Address`/`DNS`/`MTU`/`Table`
  разбираем сами), `PreUp`/`PostUp`/`PreDown`/`PostDown` игнорируем и
  показываем предупреждение.
- OpenVPN: принудительно `--script-security 1`, вырезаем
  `up`/`down`/`route-up`/`ipchange`/`plugin` с предупреждением.
- Daemon запускает только исполняемые файлы, которые принадлежат root и
  недоступны пользователю на запись: `/usr/sbin/openvpn`, `/usr/bin/wg`,
  `/usr/sbin/ip`, `resolvectl`, managed Xray (hash-verified) или системный
  Xray. Пользовательский `~/.local/bin/xray` в TUN-режиме не запускается
  (для SOCKS — можно, это не root).
- Конфиги копируются в `/run/network-orchestrator/<uid>/…` (0600, root), удаляются при disconnect.

## 4. Нефункциональные требования

- Никаких секретов в логах/ошибках (текущие redaction-хелперы
  распространяются на daemon и его ответы).
- Любая мутация транзакционна: при ошибке откатываются все шаги connect
  (links, rules, routes, DNS, процессы).
- Отказ в polkit-окне приводит к понятной ошибке без частично применённого
  состояния.
- Connect split-туннеля ≤ 5 с при доступном сервере; 1000 маршрутов
  ставятся одним batch-вызовом ≤ 2 с.
- Обычные тесты не мутируют систему (правило `AGENTS.md`); daemon тестируется
  через fake executor, реальные мутации — только в E2E на VM.

## 5. Функциональные требования

### A. Privileged daemon (Linux)

- A1. Протокол: handshake с версией; команды высокого уровня
  `profile.connect/disconnect/status` (конфиг приходит в запросе),
  `routes.apply/remove` (batch: table, via, metric, IPv4/6),
  `link.set_state`, `openvpn.probe`, `xray.test`, `owned.list`,
  `recovery.report/cleanup`, `subscribe` (события статуса). Низкоуровневые
  операции (`ip`, `wg`, `resolvectl`) остаются внутри daemon'а и наружу не
  выставляются.
- A2. Валидация каждого аргумента (как сейчас в `linux-helper`), allowlist
  исполняемых файлов (D5), лимиты на размер запроса.
- A3. Авторизация: `SO_PEERCRED` → polkit `CheckAuthorization` по action'у
  (см. D1). Пользователь видит и управляет только своими туннелями.
- A4. Журнал владения `/var/lib/network-orchestrator/state.json` (atomic
  write). После рестарта daemon'а leftovers убираются, always-on-профили
  поднимаются заново.
- A5. Дочерние процессы (OpenVPN, Xray) живут в cgroup unit'а. При
  остановке службы systemd их гасит; daemon сначала делает graceful teardown
  (routes/rules/DNS/links).
- A6. `LinuxRouteExecutor`, interface up/down и tunnel-операции в UI идут
  через daemon client. `is_elevated`/`restart_elevated` на Linux заменяются
  на `daemon_status` (установлен / запущен / версия совместима). UI
  показывает понятную ошибку и подсказку, если daemon недоступен.
- A7. Dev-сценарий: `scripts/install-linux-daemon-dev.sh` (binary + unit +
  policy, согласованные пути) вместо `install-linux-helper-dev.sh`;
  `NETWORK_ORCHESTRATOR_SOCKET` для запуска daemon'а из `target/` на VM.

### B. WireGuard (Linux)

- B1. Connect по D5: link `wg-<short-id>` (≤15 байт, детерминированно),
  адреса, MTU, `wg setconf`, up; AllowedIPs expansion (Stage 3) сохраняется.
- B2. Full tunnel по D2, DNS по D3.
- B3. Health: `wg show <if> dump` → latest handshake, rx/tx (переиспользовать
  парсер Windows dump).
- B4. Resolver backend: `wg` вместо `wireguard.exe`; backend status и
  подсказка `sudo apt install wireguard-tools`.
- B5. Import `.conf` (есть); discovery `/etc/wireguard/*.conf` через daemon —
  опционально.

### C. OpenVPN (Linux)

- C1. Запуск через daemon: `--dev tun --dev-type tun` с детерминированным
  именем `ovpn-<short-id>` (закрывает B10), `--route-nopull`,
  `--script-security 1`, `--mark M` для full tunnel.
- C2. Credentials: для `auth-user-pass` без файла UI запрашивает логин/пароль
  (и passphrase ключа), с опцией «запомнить» (Secret Service/libsecret или
  vault 0600). Передаются через временный файл в `/run/...` (0600), который
  удаляется после handshake.
- C3. Management interface (unix socket) для состояния
  (`CONNECTING/CONNECTED/RECONNECTING`), bytecount и pushed-опций вместо
  парсинга лога.
- C4. Pushed routes, `redirect-gateway def1` → 0/1+128/1 в таблице `T` по D2;
  pushed DNS по D3.
- C5. Исправить B1; probe на Linux идёт через daemon.
- C6. Reconnect (`ping-restart`, persist-tun) отражается в статусе;
  маршруты не теряются.

### D. Xray

- D1. Парсеры share-link (Q3): `vless` (добавить `xhttp`, `httpupgrade`,
  `raw`, `alpn`, `allowInsecure`, `spx`) и `hysteria2://`/`hy2://`. В
  бинарнике Xray 26.3.27 есть Hysteria (inspected: `strings`); точную схему
  outbound для pinned-версии проверить до реализации. Остальные схемы в
  подписке пропускаются с понятным счётчиком «пропущено N».
- D2. Подписки: все поддержанные схемы; base64 и plain; ручной refresh и
  refresh по интервалу; сохранение выбранного endpoint'а по стабильному ключу;
  показ `subscription-userinfo` (трафик/срок).
- D3. Latency test: TCP connect до endpoint + «real delay» через временный
  SOCKS (GET `generate_204`); сортировка; опционально auto-select лучшего.
- D4. Inbound: mixed SOCKS+HTTP на loopback (сейчас только SOCKS).
- D5. TUN: исправить B2/B3 по D4; interface/IP/routes/DNS назначает
  приложение.
- D6. Routing presets: «private/LAN direct», `geoip:<cc>`/`geosite:<cat>`
  direct/proxy/block поверх существующих `domain_policies`. Нужны
  `geoip.dat`/`geosite.dat`.
- D7. Managed Xray для linux-x86_64: pinned version + SHA-256 (как на
  Windows), вместе с geo-файлами; без auto-update.

### E. Локальные маршруты

- E1. Next hop: маршрут `via <gateway>` для не point-to-point интерфейсов
  (закрывает B9, в том числе на Windows); по умолчанию шлюз берётся из
  текущего default route интерфейса.
- E2. Bulk-ввод CIDR (вставка/файл), дедупликация и агрегация, IPv6.
- E3. Применение при старте (`auto_connect`) и повторное применение, когда
  интерфейс снова поднялся (через route watcher).
- E4. Route map/lookup показывают, какой профиль владеет маршрутом и какое
  правило/таблица выиграли (с учётом D2).

### F. Жизненный цикл и UI

- F1. `auto_connect`: при логине пользователя (запуск UI или user-агент)
  профили поднимаются по порядку с учётом конфликтов; уже поднятые daemon'ом
  повторно не трогаются.
- F2. System tray: статус, connect/disconnect по профилю, открыть окно, quit.
  Закрытие окна и quit UI туннели **не** рвут (они принадлежат daemon'у);
  отдельный пункт «Disconnect all».
- F3. Автозапуск UI при логине (`tauri-plugin-autostart`). Опционально
  always-on-профили поднимаются при загрузке, до логина: конфиг копируется в
  `/var/lib/network-orchestrator/profiles/<uid>/` (0600) по явному действию
  пользователя.
- F4. Logout/выключение: daemon корректно сворачивает туннели при остановке
  службы. UI при SIGTERM просто выходит.
- F5. Смена сети (Wi-Fi ↔ Ethernet), suspend/resume: статус обновляется,
  туннели восстанавливаются или честно показывают failed.
- F6. `get_platform_capabilities`: UI скрывает system proxy, DPAPI-импорт,
  «Restart as administrator»; Linux-тексты («Wintun» → «TUN»), подсказки
  `apt install`.
- F7. Diagnostics на Linux: `wg show`, OpenVPN management state, Xray process
  + listener, `resolvectl status <if>`, проверка rules/routes.
- F8. Recovery на Linux: leftover links (`wg-*`, `ovpn-*`, TUN), rules, routes,
  DNS — из журнала daemon'а, cleanup через daemon.
- F9. Единое название продукта (B14) в UI, пакете, polkit, путях.

### G. Пакетирование (Ubuntu)

- G1. `.deb` (tauri bundle): приложение + daemon
  (`/usr/libexec/network-orchestrator/daemon`) + systemd unit + polkit policy;
  postinst — `systemctl enable --now`, prerm — `stop` + teardown.
  `Depends: polkitd, iproute2, systemd-resolved`,
  `Recommends: wireguard-tools, openvpn`. Путь `/usr/local/...` остаётся
  только для dev-скрипта.
- G2. Arch Linux: `PKGBUILD` (в репозитории, `packaging/arch/`), который
  ставит те же файлы по тем же путям, что и `.deb`: daemon, unit, polkit
  policy. `depends=(webkit2gtk-4.1 polkit iproute2 systemd)`,
  `optdepends=(wireguard-tools openvpn)`, `install`-скрипт с
  `systemctl enable --now`. Сначала проверяем локально (`makepkg -si` на Arch
  VM/контейнере); публикация в AUR — отдельное решение.
- G2a. AppImage не собираем (tunnel-функции без daemon'а невозможны, B13):
  `bundle.targets` на Linux → только `deb`.
- G3. Auto-update через `tauri-plugin-updater` на Linux отключаем: обновления
  идут через пакетный менеджер (`apt`/`pacman`). Updater остаётся только на
  Windows.
- G4. CSP вместо `null` (B15).
- G5. Uninstall (`apt remove`) останавливает daemon (с teardown), удаляет
  unit, binary и policy; пользовательские данные остаются, `purge` удаляет
  `/var/lib/network-orchestrator`.
- G6. Совместимость версий UI и daemon: handshake отклоняет несовместимую
  версию протокола с понятной ошибкой (актуально после частичного
  обновления).

### H. Безопасность

- Всё из D5 плюс: daemon не принимает произвольные пути вне
  `/run/network-orchestrator/<uid>`; ответы daemon'а редактируются.
- `docs/security.md`: Linux threat model (polkit, daemon, секреты в
  `~/.local/share/...` 0600, опционально libsecret).

### I. Тестирование

- Unit: TDD с fake daemon/executor (RED/GREEN, как сейчас).
- **Linux E2E harness** (`--ignored` + env ack): Docker-стенд. На машине
  разработки нет KVM, а LXD не установлен (executed). Два контейнера на
  отдельной docker network:
  - `client` — Ubuntu 26.04 с systemd, daemon, polkit и resolved;
  - `server` — WG peer, OpenVPN server (PKI генерирует тест), Xray
    VLESS/Reality и Hysteria2 server.

  Контейнеры запускаются с `--cap-add NET_ADMIN --device /dev/net/tun`, без
  `--privileged`. Проверено (executed 2026-09-22): внутри такого контейнера
  работают WireGuard link с `fwmark`, отдельная таблица маршрутов с
  `ip rule` и TUN; маршруты и интерфейсы хоста не меняются. Стенд покрывает
  split, full tunnel (нет петли), DNS, crash cleanup и рестарт daemon'а.
  Приёмка §6 — отдельно, на чистой Ubuntu (VM или железо).
- UI smoke: ручной чек-лист §6, опционально `tauri-driver` + WebKitWebDriver.
- `AGENTS.md`: добавить Linux gate и правила безопасности для `linux_e2e`.

## 6. Юзеркейсы для приёмки на Ubuntu 26.04

| UC | Сценарий | Ожидаемый результат |
|---|---|---|
| 01 | Установка `.deb` на чистую VM, запуск | Приложение стартует; Explorer показывает интерфейсы, маршруты, lookup |
| 02 | Backend status | wg/openvpn/xray найдены или есть подсказка `apt install`; managed Xray ставится с проверкой hash |
| 03 | WG split (`AllowedIPs=10.0.0.0/24`) | Без запроса пароля (active session); маршрут есть; handshake виден; остальной трафик идёт напрямую; disconnect всё убирает |
| 04 | WG full (`0.0.0.0/0`, `DNS=`) | Весь трафик и DNS идут через туннель; endpoint доступен (нет петли); disconnect восстанавливает всё |
| 05 | WG с policy routes уже AllowedIPs | Ставятся только policy routes |
| 06 | OpenVPN `.ovpn` с inline certs, pushed split routes | Connect; pushed routes установлены на `ovpn-*` |
| 07 | OpenVPN `auth-user-pass` | Запрос логина/пароля; неверный пароль — понятная ошибка, без leftovers |
| 08 | OpenVPN `redirect-gateway def1` + pushed DNS | Full tunnel без петли, DNS через туннель |
| 09 | VLESS Reality link → SOCKS/HTTP | `curl --socks5`/`--proxy http://` работают |
| 10 | Подписка с VLESS + Hysteria2 (+ неподдерживаемые схемы) | Группа, «пропущено N», latency test, смена endpoint, refresh |
| 11 | Domain routing (SOCKS) | Домен X через proxy, остальное direct; geoip preset работает |
| 12 | Xray TUN | Все приложения идут через proxy; нет петли; DNS работает; disconnect восстанавливает |
| 13 | Static routes: `203.0.113.0/24 via <gw> dev eth0` | Маршрут с next hop; применяется при старте (auto-connect) и после flap интерфейса |
| 14 | Параллельно: WG split + Xray SOCKS + static routes | Всё работает одновременно; второй full tunnel блокируется как конфликт |
| 15 | Route map/lookup | Видно predicted vs effective, какой профиль/таблица выигрывает |
| 16 | `kill -9` UI | Туннели продолжают работать; новый UI показывает актуальное состояние и управляет ими |
| 17 | `kill -9` daemon'а | systemd перезапускает его; leftovers по журналу убраны, always-on-профили подняты заново; UI переподключается |
| 18 | Смена сети во время full tunnel | Туннель восстанавливается или честно показывает failed; нет «мёртвого» default route |
| 19 | Suspend/resume | То же, что 18 |
| 20 | Auto-connect, tray, «Disconnect all», reboot с always-on-профилем | Профили поднимаются при логине; always-on — до логина; «Disconnect all» всё убирает |
| 21 | Diagnostics | Осмысленные Linux-данные по каждому backend'у; логи редактированы |
| 22 | Отказ в polkit-окне (static routes на `eth0`); daemon остановлен | Понятная ошибка; ничего не применено; UI подсказывает, как запустить службу |
| 23 | Interface up/down из Explorer | Работает через daemon |
| 24 | `apt remove` при активных туннелях | Туннели корректно свёрнуты; unit, daemon и policy удалены; нет leftovers в сети |
| 25 | Второй пользователь на той же машине | Не видит и не может управлять чужими туннелями |

## 7. Этапы реализации

Каждый этап — отдельный план в `docs/plans/`, TDD и полный gate.

| # | Этап | Содержание | Закрывает |
|---|---|---|---|
| S0 | Linux baseline | Закоммитить текущий Linux-порт; `npm run tauri dev` на Ubuntu; `get_platform_capabilities` + UI gating; фикс B1 | B1, F6 |
| S1 | Daemon | Crate, systemd unit, socket + `SO_PEERCRED` + polkit, протокол и события, журнал/recovery, runtime-абстракция в `src-tauri`; миграция маршрутов (batch, `via`, tables); interface up/down; dev-install скрипт | B4, B8, B9, A*, E1 |
| S2 | Linux E2E harness | Docker-стенд client/server; сначала daemon + маршруты | I |
| S3 | WireGuard Linux + D2 + D3 | Кернельный WG, fwmark/tables, resolvectl | B6, B7, B* WG, UC 03–05 |
| S4 | OpenVPN Linux | Запуск в daemon'е, script-security, credentials, mark, DNS, management | B5, B10, B12, UC 06–08 |
| S5 | Xray | TUN fix, парсеры, подписки/refresh, latency, mixed inbound, presets, managed Xray linux | B2, B3, UC 09–12 |
| S6 | Lifecycle | auto-connect, always-on, tray, re-attach UI, network change, diagnostics | B11, UC 16–21, 25 |
| S7 | Пакет и приёмка | `.deb` + unit + polkit + deps, CSP, название, updater, документация; полный прогон §6 на чистой VM | B13–B15, UC 01, 22–24 |

## 8. Решения владельца и открытые вопросы

Решено 2026-09-22:

- **Q1 → системная служба** (D1). Туннели переживают UI; возможны always-on
  до логина.
- **Q2 → system proxy на Linux не делаем.** «Все приложения» закрывает TUN,
  отдельные приложения — SOCKS/HTTP inbound.
- **Q3 → из новых протоколов только Hysteria2**, плюс доработка VLESS
  transports.
- **Q4 → Ubuntu-first.** Windows допускается временно сломать; паритет —
  отдельной фазой.

- **Q5 → kill switch — будущая опциональная функция**, сейчас не делаем.
  Архитектура (D2: отдельные таблицы и `ip rule`) не должна мешать добавить
  его позже.
- **Q6 → Ubuntu/Debian и Arch.** `.deb` + `PKGBUILD` (G1–G2); AppImage и
  Linux auto-update не делаем (G2a, G3). DoD: пакеты ставятся и проходят §6
  на Ubuntu 26.04; на Debian stable и Arch — smoke-проверка UC 01, 03, 09,
  12, 13, 24.

## 9. Вне scope

macOS; process-based routing; VPN chaining; альтернативные ядра
(sing-box/Mihomo); Clash/sing-box форматы подписок; vmess/trojan/shadowsocks;
system proxy на Linux; мобильные платформы; kill switch (будущая опция, Q5); AppImage; Linux
auto-update; Windows-паритет новых фич до отдельной фазы.
