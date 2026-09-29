# Находки первого боевого прогона на Fedora 44 desktop (2026-09-28)

**Статус:** findings по мотивам первого запуска `.rpm` на живой машине
(KDE Plasma, Wayland, SELinux enforcing не проверялся). Все теги —
`executed` на этом хосте, если не указано иное.

## Что подтвердилось на реальном железе

- daemon: systemd unit, сокет, версионированный протокол, `owned.list`,
  `alwaysOn.list`, `settings.get` — работают.
- Explorer: реальные интерфейсы через netlink, включая IPv6-адреса и
  чужие туннели (`happ-xray`, `wg-kzn2`, `tailscale0`).
- polkit end-to-end: `routes.apply` → KDE-диалог пароля → маршрут в ядре
  (`proto 79`) → `routes.remove` чисто снимает.
- Xray TUN lifecycle: tun-интерфейс `xray-*`, IP назначается демоном,
  managed xray от root, `transportMark`, teardown чистый.
- Импорт `.ovpn` через файловый диалог → vault `rev-*` → карточка профиля;
  Diagnostics показывает checks.
- Recovery: после всех тестов `owned.list` пуст, процессов/интерфейсов/
  маршрутов не осталось.
- **Scoped split-тест Xray TUN (боевой, 2026-09-28):** профиль с
  маршрутами на 2×/32 и правилом `domain:api.ipify.org → direct`.
  `curl api.ipify.org` → exit uplink'а, `curl checkip.amazonaws.com`
  (без правила) → exit VLESS-сервера. Sniffing SNI → routing rules →
  outbound-диспатч работают end-to-end. Teardown чистый.
- **Full-capture UI-путь (боевой, 2026-09-28):** реальная подписка →
  профиль → `Xray mode=TUN` → connect → `0.0.0.0/0` захват + DNS 1.1.1.1 →
  трафик пошёл через VLESS (включая трафик агента сессии). Правила
  приоритета 10000/10001 корректно сосуществуют с чужим `wg-kzn2`.
  Важно: профиль из подписки импортируется в `xrayMode=socks` — TUN надо
  включать руками в Edit (UX-проблема: неочевидно). И пока жив
  `happ-xray` с его правилами pri 5210–5270 — они выше наших и перехватят
  поток: два full-tunnel не уживаются, нужен detect+warn.
- **Урок фазы 2 (перехват default):** `systemctl stop happd` убивает
  процесс, но iface/правила в ядре уходят с задержкой; `Restart=always`
  + ручные попытки → окно гонки. Full-capture тесты с конкурирующими
  туннелями — только в `e2e/linux` контейнере, на живом хосте — окно
  даунтайма принимать осознанно.

## Дефекты

| ID | Проблема | Статус |
|---|---|---|
| F1 | `remote … tcp` / `proto tcp` (`tcp4`, `tcp6`) отклонялись sanitizer'ом — легальные client-алиасы OpenVPN. Ломал реальные pfSense-экспорты | **исправлено** (`is_client_proto`, 2026-09-28) |
| F2 | Allowlist отклонял обычные client-директивы: `verb`, `explicit-exit-notify`, `keepalive`, `mute`, `connect-timeout`, `ping-exit`, `ncp-ciphers`, `peer-fingerprint`, `topology`, `auth-retry`, `pull`, `float`, `route-nopull`, MTU-кнобы (`mssfix`, `fragment`, `link-mtu`) и др. | **исправлено** (там же) |
| F3 | Неудачный connect молчит в UI: daemon возвращает `InvalidParams`/failed — toggle откатывается без сообщения. Корень: `route-changed` (netlink watcher) → `refreshAll` → `setError(null)` затирал баннер; async-переход `→failed` вообще нигде не показывался. | **исправлено** (`actionError` + watcher переходов, 2026-09-28) |
| F4 | `route`/`route-ipv6` в `.ovpn` отклоняются (по дизайну — маршрутами владеет daemon), но **import не конвертирует их в policy routes профиля** — split-конфиги (`bi-zone-sep.ovpn`) теряют маршруты молча. | открыто, feature gap |
| F5 | `pkcs12`/файловые ссылки в `.ovpn` — import не подтягивает sibling-файлы и не предупреждает, что asset отсутствует. pfSense-профили упадут на connect уже на staging. | открыто |
| F6 | TLS handshake к `178.170.197.253:1194` виснет >15 c: TCP connect мгновенный, ClientHello без ответа. Ручной `openvpn` с теми же флагами — то же самое → не баг приложения. Гипотезы: MTU через `happ-xray`, сервер молчит на tcp. Перепроверить на прямом линке. | env, не app |
| F7 | TUN-inbound генерируется без `sniffing` → `domain:`/`geosite:` правила под TUN инертны (видны только IP). Это главный gap до Happ-style split. | **исправлено** (`sniffing.enabled`+`destOverride:[http,tls,quic]` на обоих генераторах; `xray run -test` на пиннённом v26.3.27 — OK) |
| F8 | UI-текст «require administrator privileges» — виндовая формулировка на Linux. | косметика |
| F9 | openvpn stdout/stderr — `Stdio::null()`: при failed нельзя прочитать причину без mgmt-парсинга. Может, держать bounded log в `/run/network-orchestrator/<uid>/` для Diagnostics. | открыто |

## Окружение: NetworkManager на хосте (2026-09-28)

- NM `active`, systemd-resolved `active`. Активный аплинк —
  `enp59s0u2` (USB-Ethernet, NM-профиль «Проводное подключение 1»);
  `wlp0s20f0u5` (Wi-Fi) под NM, но `unavailable`.
- Чужие туннели NM видит как `connected (externally)` — `happ-xray`,
  `tailscale0`, `wg-kzn2`: наблюдает, но не конфигурирует. Наши
  `xray-*`/`wg-*`/`ovpn-*` будут выглядеть так же — конфликта нет.
- `/etc/NetworkManager/conf.d/` пусто — unmanaged-правил нет. Если NM
  начнёт трогать наши линки: `unmanaged-devices=interface-name:xray-*`.
- DNS: per-link через `resolvectl` идёт в тот же resolved, куда NM пишет
  DNS физических линков — координация бесплатная.
- Риск №1 — flap аплинка (Ethernet↔Wi-Fi, DHCP-renewal, suspend): NM
  пересобирает маршруты/правила; демонский reconcile покрыт E2E в
  контейнере, но живой roaming ещё не проверен — acceptance-пункт.
- `route-changed` в приложении слушает kernel-события, которые как раз
  генерит NM — механизм затирания баннера ошибки из F3. `actionError`
  теперь от этого защищён.

## Ограничение прогона

Ввод текста в WebKitGTK через AT-SPI не принимается — текстовые поля
(Lookup, формы профиля) гонялись через daemon-сокет напрямую.

## Итерация 2: route-map fix + читаемые имена интерфейсов (2026-09-28)

### Дефекты

| ID | Проблема | Статус |
|---|---|---|
| F10 | Traffic Flow показывал «No active routes» при живых daemon-туннелях: `get_route_map` читал running-флаг из in-process `runtime.tunnels`, который на Linux пуст (туннели живут в daemon). Заодно `InterfaceMismatch`-диффы — `profile.interface_name` пуст, а реальный линк `wg-*/xray-*`. | **исправлено** — `collect_tunnel_statuses` (daemon-authoritative) используется и `get_route_map`; live `interface_name` из daemon-статуса подставляется в клон профиля до `build_route_map`. `TunnelStatus` получил поле `interfaceName`. |
| F11 | Имена линков генерились только хешем (`wg-44c5d5827e76`, `xray-f912d5057c`) — непривязуемо к профилю. | **исправлено** — `interfaceName` hint в `wireguard.connect`/`xray.connect` (optional, backwards-compatible). Демон: `tunnel_link_names()` — слаг `[a-z0-9-]` ≤15, verbatim при `wg-*`/`wg0`-виде, fallback `wg-<slug>-<hash4>` при EEXIST, hash `wg-<12hex>` при пустом/невалидном hint. Hint = `profile.interfaceName` или имя профиля; non-ASCII (напр. «🇳🇱 Нидерланды») → hash-fallback. |

### Живая верификация

- Подписка `x-hwid` → профиль `🇳🇱 ⚡ Нидерланды` → Xray mode=TUN → full-capture `0.0.0.0/0` через VLESS (NL exit `203.17.244.189`), direct/proxy-развилка по `domain:`-правилу, DNS `1.1.1.1` — подтверждено curl'ами через туннель.
- `systemctl restart network-orchestrator` при живом xray-TUN: линк/правила/DNS пережили демона (journal `applied`) — рестарт не роняет туннели.
- WG-профиль `wg-kzn2` поднят при живом NM-`wg-kzn2`: EEXIST → fallback `wg-kzn2-7e76`, `10.7.0.101/24`, 9 split-маршрутов proto 79, per-link DNS `10.10.10.2` + `~ds-lab.internal`/`~ds-mind-lab.ru`. Чужой линк не тронут.
- `ping 10.10.10.2` 2/2 @ ~40 мс — реальный трафик через туннель.

### Открыто / backlog

- Имена для xray-профилей с non-ASCII именем остаются `xray-<hash>` (нет slug). Можно транслитерировать или взять `serverDescription`/hostname из VLESS-URI.
- UX: профиль из подписки дефолтит `xrayMode=socks` → на Linux «connect» без TUN выглядит как «не работает». Варианты: дефолт `tun` для generated-профилей на Linux или явная подсказка в карточке.
- Детект чужого владельца default-route (Happ `lookup 52` pri 5210-5270 выше наших 10000/10001) → понятное «another tunnel owns default route» вместо молчаливого нетрафика.
- fakeDNS/DNS-intercept — паритет с Happ для non-TLS/UDP трафика (их пул `198.18.0.0/15`, у нас адрес тоже оттуда — инфраструктура совместима).
- F4/F5/F9 (OpenVPN) — отложено по приоритету.

## Итерация 3: дефолт TUN на Linux + Logs-таб (2026-09-28)

### Сделано

- `default_xray_mode()` в `profiles.rs`: `Tun` на Linux, `Socks` на остальных
  ОС — для импорта конфигов и профилей из подписки. Фронт: `newFormState(backend, os)`
  — ручное создание тоже дефолтит `tun` на Linux. Существующие профили не мигрируем.
- Таб **Logs** (NavRail → Advanced): app-side ring-buffer 500 событий
  (`AppState.log: Mutex<VecDeque<LogEvent>>`, не персистится), команды
  `get_logs`/`clear_logs`/`daemon_log_tail` (journald `network-orchestrator.service`,
  200 строк, severity из PRIORITY). Инструментированы `connect_profile`,
  `connect_openvpn_with_credentials`, `disconnect_profile` (wrapper + inner),
  `cleanup_recovery` (warn при снятии осиротевших owner'ов). Фронт:
  `src/components/Logs.tsx` — фильтр по уровню/строке, автопромотка, Clear,
  раскрываемый daemon-tail. Тесты: ring-limit, clear, уровни ok/err, сериализация.

### Открытые риски и пробелы (для проработки)

Зафиксировано как честный список «чего ещё нет» — по нему строим доверие:

1. **Flap/reconnect не прогонялся на железе.** Дёрнуть аплинк при живых
   Xray-TUN + WG, проверить reconcile демона, отсутствие утечек маршрутов/DNS,
   сосуществование с NM-reconnect. Покрыто только контейнерным E2E.
2. **Детект чужого full-tunnel владельца отсутствует.** При живом Happ
   (lookup 52, pri 5210–5270 < наших 10000/10001) поток молча перехватывается
   до нашей таблицы → «connect есть, трафика нет». Нужен preflight: найти
   не-owned `ip rule`/default-route владельца и отвечать читаемой ошибкой.
3. **fakeDNS / DNS-intercept нет.** Non-TLS/UDP DNS идёт по IP-правилам/аплинку;
   sniffing покрывает HTTPS/QUIC. Для паритета с Happ — backlog-фича.
4. **OpenVPN незрелый** — F4/F5/F9 отложены; конфигурационная совместимость
   и рукопожатие не проверены.
5. **UX невнятный** (замечание пользователя): вкладки/карточки/формы требуют
   переработки — отдельная итерация. Частный случай уже ловился: SOCKS-дефолт
   → «не работает» без объяснений (теперь исправлено дефолтом TUN).
6. **Ширина покрытия**: всё проверено на одной машине (Fedora 44/KDE/NM).
   Другие сети/ресолверы (не systemd-resolved), иные NM-конфиги — неизвестно.
7. **Миграции нет**: профили, созданные до итерации 3, остаются `xrayMode=socks`
   — сознательно не переписываем, но в UX может сбивать.
8. **Dev/прод разница**: `tauri dev` и RPM используют один store и один
   демон-сокет — при расхождении версий протокола нужна аккуратность
   (пока протокол backwards-compatible через `#[serde(default)]`).

### Итерация 3b: импорт RoscomVPN-роутинга + трёхпанельный редактор

- В `profiles.json` профиля подписки записан порт Happ-правил RoscomVPN
  (порядок block → proxy → direct, как `RouteOrder: block-proxy-direct`).
- `classify_routing_selector` (`xray.rs`): строки `# …` и пустые — комментарии
  (round-trip через UI); голые IP/CIDR литералы → `ip`-правила (раньше
  попадали в `domain` и никогда не матчились). Тесты добавлены.
- `ProfileFormModal`: правила теперь три textarea (Proxy/Direct/Block),
  одна строка = селектор; комментарии сохраняются в `domainPolicies`
  и переживают save→edit цикл.
- Покрытие категорий сверено с `/usr/lib/network-orchestrator/xray/v26.3.27/*.dat`
  и с `~/.local/share/Happ/routing/0/RoscomVPN/*.dat`: весь применённый набор
  подтверждён `xray run -test` (Configuration OK).
- **Итерация 3c — custom geo assets per-profile (реализовано):**
  - `Profile.xrayGeoipUrl`/`xrayGeositeUrl` (camelCase, optional) — HTTPS-only,
    валидация на save (`geo_assets::validate_geo_asset_url`), поля в форме
    (только xray+TUN).
  - `geo_assets.rs`: кэш `<data>/geoassets/<profile-id>/{geoip,geosite}.dat`
    + `meta.json`; скачивание на connect (24h freshness), atomic writes,
    лимит 64 MiB, stale-cache при неудачном рефреше, injectable fetch
    (тесты без сети). Сброс URL чистит кэш.
  - Протокол: `XrayConnectParams.geo_assets: Option<XrayGeoAssets>` —
    inline base64 (`geoipDatB64`/`geositeDatB64`), обратно-совместимо
    (`#[serde(default)]`). **Path-based вариант (`geo_asset_dir`) отменён:**
    unit демона работает с `ProtectHome=yes`/`PrivateTmp=yes`, поэтому
    `/home/artur/...` для него физически не существует — чтение кэша по
    пути давало `Internal` → «Xray spawn failed» после апдейта демона.
    Передача байтов вместо пути — единственный вариант, сохраняющий
    sandbox-границу. `MAX_FRAME_BYTES` поднят 4→32 MiB (два ~10 MiB dat
    → ~27 MiB фрейм); app перепроверяет размер фрейма после прикрепления
    ассетов.
  - Демон (`xray_process.rs`): `stage_geo_assets` декодирует base64,
    отклоняет malformed/пустой/>64 MiB (`InvalidInput` → InvalidParams),
    пишет через `write_private_file` (0600 root-owned), per-file fallback
    на managed-ассеты; `XRAY_LOCATION_ASSET` указывает на staging.
    `cleanup_stage_at` allowlist расширен geo-файлами. Тесты
    staging/fallback/malformed/oversize/cleanup добавлены.
  - `geoip:`-валидация смягчена до того же charset, что geosite
    (`[a-zA-Z0-9_-]{1,64}`) — произвольные категории (`geoip:direct`)
    разрешаются, Xray резолвит их по фактически загруженному dat на connect.
    Проверено вживую: roscomvpn `geoip.dat` содержит `DIRECT`/`PRIVATE`,
    `xray run -test` с полным verbatim-набором → Configuration OK
    (отсутствующие `whitelist/microsoft/epicgames/pinterest` — warning,
    не ошибка; мёртвые правила также и в Happ). Асимметрия Xray:
    неизвестная **geosite**-категория — warning, неизвестный **geoip**-код —
    фатальная ошибка конфига (connect упадёт с понятным сообщением,
    не молчаливым misroute).
  - Профиль подписки обновлён до **verbatim** RoscomVPN-списков (включая
    `geoip:direct`, `geosite:torrent`, `geosite:twitch-ads`) + оба geo-URL.
- **Белый экран `tauri dev` — IPv6/IPv4 рассинхрон (исправлено)**: vite
  биндился на `localhost` → Node выбирал `::1` (IPv6-only listen), а
  `devUrl: http://localhost:1420` в WebKitGTK резолвился в `127.0.0.1` →
  refused → webview получал пустой документ (`documentElement.outerHTML`
  = 39 байт, проверено через WEBKIT_INSPECTOR_HTTP_SERVER). Фикс:
  `vite.config.ts` → `host: "127.0.0.1"`, `tauri.conf.json` →
  `devUrl: http://127.0.0.1:1420`. Проверено инспектором: `#root`
  содержит рендер. Первая гипотеза (NVIDIA DMA-BUF краш) оказалась
  неверна — `WEBKIT_DISABLE_*` env не помогали.
- Не портируется без новых фич:
  - `DnsHosts` (lkfl2/lknpd.nalog.ru → статические IP) — нет генерации
    xray `dns.hosts`; backlog.
  - `DomainStrategy=IPIfNonMatch` — у нас роутинг по sniffed-domain/ip без
    fallback-резолва; поведение «unmatched → proxy» эквивалентно по итогу,
    но не по механизме.
  - `RemoteDNSType/DomesticDNSType` DoH-endpoints и split-DNS — backlog.
