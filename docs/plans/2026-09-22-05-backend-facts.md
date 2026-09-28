# Проверенные факты для Ubuntu-first спеки (2026-09-22)

Проверяли на хосте Ubuntu 26.04.1, kernel 7.0.0-31. Все мутации сети выполнялись только внутри
одноразовых docker-контейнеров (`--cap-add NET_ADMIN --device /dev/net/tun`). Проверенные бинарники:
Xray 26.3.27 (`~/.local/bin/xray`) и Xray 26.9.9 (последний релиз, скачан в scratchpad).
Исходники: Xray-core с тегами `v26.3.27` и `v26.9.9`, Xray-docs-next, OpenVPN `v2.6.14`/`v2.7.0`,
systemd `v259`, tauri-utils 2.9.3, tauri-plugin-updater 2.11.0 и tauri-bundler (`dev`).

Теги: **[exec]** — проверено запуском; **[src]** — прочитано в исходниках; **[docs]** — официальная документация;
**[inf]** — вывод, напрямую не наблюдался.

---

## 1. Xray TUN inbound

### 1.1 Схема по версиям

| Версия | Ключи `settings` | Имя по умолчанию | Linux: IP / маршруты |
|---|---|---|---|
| **26.3.27** (наш pinned) | `name`, `MTU`, `userLevel` | `xray0` | нет / нет |
| 26.4.13 | + `gateway[]`, `dns[]`, `autoSystemRoutingTable[]`, `autoOutboundsInterface` (`mtu` был массивом) | `xray0` | нет / нет (работает только `autoOutboundsInterface`) |
| 26.4.25–26.6.1 | `mtu` снова число | `xray0` | нет / нет |
| 26.6.22 | + env `XRAY_TUN_FD` (передать готовый fd) | `xray0` | нет / нет |
| 26.6.27 | — | `xray0` | нет / **да** |
| 26.7.11 | — | `xray0` | **да** / да |
| 26.7.28 … **26.9.9** | + `desc` (только Windows) | **случайное `utunNN`** (10..1024) | да / да |

[src] `infra/conf/tun.go` и `proxy/tun/tun_linux.go` на каждом теге; [exec] для 26.3.27 и 26.9.9.

- Ключи сопоставляются без учёта регистра (Go `encoding/json`), поэтому `"MTU"` и `"mtu"` работают в обеих
  версиях. [exec] Конфиг с `"mtu":1400` на 26.3.27 дал `mtu 1400`, а `"MTU":1400` на 26.9.9 тоже применился.
  В актуальной документации пишут `mtu`.
- Неизвестные ключи молча игнорируются. [exec] Текущий генератор (`interfaceName`, `ip`, `mtu`) на
  26.3.27 создаёт интерфейс **`xray0`** без адреса. На ≥26.7.28 было бы случайное `utunNN`.
- Linux, 26.3.27: `open("/dev/net/tun")` → `TUNSETIFF IFF_TUN|IFF_NO_PI` (не persistent) → netlink
  `LinkSetMTU` → `LinkSetUp`. **Адрес не назначается, маршруты не ставятся.** [src][exec]
  `ip addr` показывает только флаги `POINTOPOINT,NOARP,UP` и никакого `inet`; таблица маршрутов не меняется.
  Устройство исчезает вместе с процессом. [exec] После `-test` в `ip link` его нет.
- 26.9.9, Linux [src][exec]:
  - `gateway: ["172.19.0.1/30","fdfe:…::1/126"]` → `AddrAdd` на интерфейс.
  - `autoSystemRoutingTable: ["10.200.0.0/16"]` → маршрут `dev <tun> metric 1` в **main**.
    Таблица и правила не задаются.
  - `autoOutboundsInterface: "auto"|"<ifname>"` → `SO_BINDTODEVICE` на все исходящие сокеты, кроме
    loopback. Интерфейс выбирается по default route и отслеживается через netlink. Если задан
    `autoSystemRoutingTable`, значение неявно `"auto"`.
  - `dns` на Linux и macOS **игнорируется** (README tun: «Linux and macOS do not configure system DNS
    from the dns field»). [docs]
- Пример рабочего inbound, совместимого с 26.3.27 и 26.9.9 [exec]:
  ```json
  {"tag":"tun-in","protocol":"tun","settings":{"name":"nm-xtun0","mtu":1400}}
  ```
  `name` всегда задавать явно (≤15 байт), потому что умолчание меняется между версиями.

### 1.2 Привилегии и `-test`

- На хосте без прав: `Failed to start: main: failed to create server > operation not permitted`. В контейнере
  без `NET_ADMIN` то же самое. [exec]
- В контейнере с `NET_ADMIN`: `-test` выводит `Configuration OK`, **но по пути создаёт настоящее
  устройство** (в логе `proxy/tun: nm-xtun0 created`). [exec]
- **Коллизия:** если xray с тем же `name` уже запущен, `-test` падает с
  `failed to create server > device or resource busy`. [exec]
- Непривилегированная валидация работает: тот же конфиг **без tun inbound** проходит
  `-test` без каких-либо прав. [exec] `-dump` конфиг не валидирует (битый VLESS прошёл `-dump`,
  а `-test` его отклонил). [exec]
- 26.3.27 от uid 65534 с ambient `CAP_NET_ADMIN`: `-test` OK (`setpriv --inh-caps +net_admin
  --ambient-caps +net_admin`). Root не обязателен, достаточно capability. [exec]
- 26.3.27 от uid 65534 **без** caps на заранее созданном persistent tun (`ip tuntap add … user 65534`):
  EPERM, потому что xray сам вызывает `LinkSetMTU`. [exec]
- 26.9.9 с `XRAY_TUN_FD`: root открывает tun, настраивает MTU, up и адрес, затем `exec` xray от
  uid 65534 без capabilities. Работает (`nm-xtun0 created/up`, `Xray 26.9.9 started`). [exec]
  xray в этом режиме не трогает MTU, up и адреса (`ownsTun=false`). [src]
  Следствие: с Xray ≥26.6.22 daemon может запускать xray **не от root**. Тогда для loop prevention
  нужен `sockopt.interface`/`autoOutboundsInterface`, а не `mark` (см. §2).

## 2. Loop prevention в Xray outbound

- Поля лежат в `streamSettings.sockopt` каждого outbound [src `infra/conf/transport_internet.go`,
  `transport/internet/sockopt_linux.go`]:
  - `"mark": <int32>` → `setsockopt(SOL_SOCKET, SO_MARK)`, только Linux;
  - `"interface": "<ifname>"` → `SO_BINDTODEVICE`.
- Применяются ко всем outbound'ам, которые дозваниваются через `internet.DialSystem`: VLESS, Trojan,
  VMess, **freedom** и **hysteria**. Hysteria передаёт `streamSettings.SocketSettings` в
  `DialSystem` и для основного сокета, и для сокетов udphop. [src `transport/internet/hysteria/dialer.go:172,396,458`]
  `-test` с `mark` на freedom и hysteria проходит. [exec]
- Требования к правам:
  - `SO_MARK` от uid 65534 → `EPERM`. Root с docker-default caps (есть `NET_RAW`, нет `NET_ADMIN`) → OK. [exec]
    Документация Xray пишет «Requires CAP_NET_ADMIN». [docs] На kernel ≥5.17 достаточно
    `CAP_NET_RAW`. [inf]
  - `SO_BINDTODEVICE` от uid 65534 → OK. [exec] (без привилегий с kernel 5.7 [inf])
- Пример:
  ```json
  "streamSettings":{"network":"xhttp","security":"reality", … ,"sockopt":{"mark":51820}}
  {"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"mark":51820}}}
  ```
- Freedom тоже **обязательно** помечать. В TUN full tunnel direct-трафик (LAN/geoip-direct) иначе
  попадёт под `not fwmark M → table T → tun` и вернётся в xray. Метка не нужна только blackhole,
  потому что он не дозванивается. [inf]

## 3. Hysteria2 в Xray

- Протокол называется **`hysteria`**, а не `hysteria2`. Есть в 26.3.27 и 26.9.9. [src][docs]
- Outbound (проверен `-test` на обеих версиях [exec] и **interop с официальным сервером
  Hysteria v2.12.3**: HTTP 200 через SOCKS xray [exec]):
  ```json
  {"tag":"proxy","protocol":"hysteria",
   "settings":{"version":2,"address":"hy.example.com","port":443},
   "streamSettings":{
     "network":"hysteria", "security":"tls",
     "tlsSettings":{"serverName":"real.example.com",
                    "pinnedPeerCertSha256":"<hex sha256 of leaf DER>",
                    "alpn":["h3"]},
     "hysteriaSettings":{"version":2,"auth":"<auth>"},
     "finalmask":{
       "udp":[{"type":"salamander","settings":{"password":"<obfs-password>"}}],
       "quicParams":{"brutalUp":"50 mbps","brutalDown":"200 mbps",
                     "udpHop":{"ports":"443,5000-6000","interval":"5-10"}}},
     "sockopt":{"mark":51820}}}
  ```
- `security:"tls"` обязателен (таблица transport/security в docs). `-test` его отсутствие **не ловит**, а в runtime
  будет ошибка `tls config is nil`. [src][exec] Поэтому генератор должен проставлять его сам.
- Legacy-поля `hysteriaSettings.up/down/congestion/udphop`: 26.3.27 выдаёт warning «move to
  finalmask/quicParams» и игнорирует их. В 26.9.9 этих полей больше нет, они молча
  игнорируются. [src][exec]
- Для порт-хоппинга (`udpHop.ports`) порт выбирается случайно из списка, `settings.port` при этом
  перезаписывается. [src] `udpHop` работает только на внешнем уровне, иначе ошибка `udphop requires being at the
  outermost level`. [src]
- ALPN указывать не обязательно: interop прошёл и без `alpn`, и с `["h3"]`. Без salamander при
  obfs на сервере соединение не устанавливается. [exec] По умолчанию Xray шлёт ALPN `h2,http/1.1`. [src]
  Для единообразия лучше явно ставить `["h3"]`. [inf]

**Маппинг `hysteria2://` / `hy2://`** (официальная схема [docs v2.hysteria.network/docs/developers/URI-Scheme]):

| URI | Xray JSON | Статус |
|---|---|---|
| `auth@` (или `user:pass@`) | `hysteriaSettings.auth` (строкой как есть) | ✔ [exec] |
| host, `:port` (по умолчанию 443) | `settings.address`, `settings.port` | ✔ |
| multi-port `:443,5000-6000` | `settings.port` = первый порт, `finalmask.quicParams.udpHop.ports` = вся строка | ✔ [src][docs] (hopping не тестировали) |
| `obfs=salamander` + `obfs-password` | `finalmask.udp[{type:"salamander",settings:{password}}]` | ✔ [exec] |
| `obfs=gecko` | 26.9.9: salamander + `settings.packetSize` ("512-1200"); **в 26.3.27 нет** (поля нет, игнорируется молча → несовместимость) | ⚠ [src][docs] |
| `sni` | `tlsSettings.serverName` | ✔ |
| `insecure=1` | **не поддерживается**: `allowInsecure` в 26.3.27 — hard error после 2026-06-01, в 26.9.9 удалён | ✘ [exec] |
| `pinSHA256` | `tlsSettings.pinnedPeerCertSha256` (hex, `:` допускаются, несколько через `,`); совпадение с leaf отключает проверку CA | ✔ [exec][src] |
| `ech` | `tlsSettings.echConfigList` | ✔ [src] |
| `mport` (нестандартный, v2rayN) | как multi-port → `udpHop.ports` | ⚠ [inf] |
| `alpn` (нестандартный) | `tlsSettings.alpn` (split `,`) | ✔ [src] |
| `up`/`down` (в URI их быть не должно по спеке) | `finalmask.quicParams.brutalUp/Down` | [docs] |
| `hysteria2+realm://` | нет аналога в Xray | ✘ |

Ошибка с `allowInsecure`, воспроизведено на обеих версиях [exec]:
`The feature "allowInsecure" has been removed and migrated to "pinnedPeerCertSha256"`.

## 4. VLESS транспорты (Xray 26)

- `streamSettings.network` (в 26.9.9 есть ещё alias `method`, который имеет приоритет). Для
  совместимости с 26.3.27 писать `network`. [src]
  - `raw`/`tcp` → tcp; `xhttp`/`splithttp`; `kcp`/`mkcp`;
  - `ws`/`websocket`, `grpc`, `httpupgrade` работают, но печатают deprecation warning [exec];
  - `h2`/`h3`/`http`/`quic` удалены (ошибка). [src]
- `xhttpSettings`: `path`, `host`, `mode` ∈ `auto|packet-up|stream-up|stream-one`. Пустое значение
  означает `auto`, любое другое даёт ошибку `unsupported mode` [exec]. `extra` — JSON-объект с любыми
  полями `SplitHTTPConfig`; внешние `host/path/mode` перекрывают `extra`. [src] В `headers` нельзя класть `host`. [src]
- `httpupgradeSettings`: `path`, `host`, `headers`. [src]
- `realitySettings` (client): `serverName`, `fingerprint`, `password` (= pbk; принимается и `publicKey`),
  `shortId`, `spiderX`, `mldsa65Verify`. [src][exec]
- `tlsSettings`: `serverName`, `alpn[]`, `fingerprint`, `pinnedPeerCertSha256`, `verifyPeerCertByName`,
  `echConfigList`. [src]
- Плоская форма outbound `settings:{address,port,id,encryption}` тоже принимается 26.3.27. [exec]
- Все образцы прошли `-test` на 26.3.27 и 26.9.9: xhttp+reality+extra+spiderX, httpupgrade+tls+vcn,
  raw+reality+vision, tcp+tls+alpn. Файлы лежат в `research/cfg/`. [exec]

**Share-link параметры** (стандарт XTLS/Xray-core discussion #716, ред. 2026) [docs]:
`type` (tcp|kcp|ws|http|grpc|httpupgrade|xhttp), `encryption` (VLESS: `none`/`mlkem768x25519…`),
`flow`, `security` (none|tls|reality), `path`, `host`, `mode` (xhttp), `extra` (xhttp, URL-encoded JSON),
`fm` (finalmask JSON), `serviceName`/`mode`/`authority` (grpc), `headerType`, `mtu`/`tti` (kcp),
`fp` (по умолчанию `chrome`), `sni` (по умолчанию remote-host), `alpn` (через запятую),
`ech`, `pcs` → `pinnedPeerCertSha256`, `vcn` → `verifyPeerCertByName`,
`pbk` → reality `password`, `sid` → `shortId`, `pqv` → `mldsa65Verify`, `spx` → `spiderX`
(`spx` есть только у REALITY). Про `allowInsecure` стандарт говорит прямо: «такого параметра не было, ядро его
удалило, используйте pcs/vcn». Для `allowInsecure=1` в чужих ссылках только два честных варианта:
отклонить или показать предупреждение и потребовать pcs.

## 5. OpenVPN на Linux

- Версии [exec]: **Debian 13 — 2.6.14**, **Ubuntu 26.04 — 2.7.0**, **Arch — 2.7.7**. Поддерживать нужно
  и 2.6, и 2.7.
- `--mark 51820` работает: `ss -uanpe` показывает `fwmark:0xca6c` на транспортном сокете (2.7.0). [exec]
  Метка ставится только на зашифрованные пакеты транспорта. [docs]
- Имя устройства: `--dev ovpn-a1b2c3 --dev-type tun` создаёт `ovpn-a1b2c3`. Без `--dev-type` с
  произвольным именем получается `Error: problem with tun vs. tap setting`. [exec] `--dev` в командной строке **после**
  `--config` перекрывает `dev tun` из файла. [exec]
- **`--script-security` — действует последнее значение.** `--script-security 1 --config x.ovpn`, где в
  файле `script-security 2` + `up`: скрипт **выполнился** (на 2.6.14 и 2.7.0). [exec]
  Если `--script-security 1` стоит **после** `--config`, скрипт не выполняется. [exec]
- При уровне 1 и `up` в конфиге OpenVPN не пропускает хук молча, а завершается:
  `Failed running command (--up/--down): disallowed by script-security setting` → fatal. [exec]
  Поэтому такие директивы вырезаем, а не полагаемся на уровень.
- `plugin` **не** регулируется `--script-security`: OpenVPN пытается загрузить `.so` и при уровне 1. [exec]
- Вложенная директива `config` внутри .ovpn обрабатывается. [exec] `log /path` от root записывает файл
  по произвольному пути (0600). [exec] `--iproute` в сборке Debian 2.6 отсутствует. [exec]
- Директивы, которые запускают код [docs `script-options.rst` 2.6/2.7]: `up`, `down`, `route-up`,
  `route-pre-down`, `ipchange`, `tls-verify`, `tls-crypt-v2-verify`, `auth-user-pass-verify`,
  `client-connect`, `client-disconnect`, `learn-address`, `plugin`, `dns-updown` (2.7). Пишут или читают файлы
  от root: `log`, `log-append`, `status`, `writepid`, `replay-persist`, `ifconfig-pool-persist`,
  `tls-export-cert`, `tmp-dir`, `cd`, `chroot`, `config`, `management`, `dev-node`, `daemon`, `user`/`group`.
- **2.7 `dns-updown`:** скрипт по умолчанию `/usr/libexec/openvpn/dns-updown` запускается как *built-in*
  (`openvpn_execve_check` без `S_SCRIPT`), поэтому **разрешён при `--script-security 1`**. [src
  `run_command.c`, `dns.c`] [exec]: с `--route-noexec --script-security 1` в логе
  `/usr/libexec/openvpn/dns-updown … dns up command exited with status 0`. Отключается через
  `--dns-updown disable` [exec]. OpenVPN 2.6 такую опцию не знает и падает с `Options error`. Вариант, который работает на обеих версиях:
  `--ignore-unknown-option dns-updown --dns-updown disable`. [exec]
- `--route-nopull` отбрасывает `route`, `redirect-gateway` **и** `dhcp-option` (DNS). [docs][exec: `Options error:
  option 'dhcp-option' cannot be used in this context ([PUSH-OPTIONS])`] При этом строка
  `PUSH: Received control message: 'PUSH_REPLY,…'` (D_PUSH, verb ≥3) продолжает приходить в management
  `log`. [exec] Из неё daemon может сам разобрать pushed routes и DNS.
  `--route-noexec` сохраняет DNS-опции, но на 2.7 из-за них запустится dns-updown (см. выше).
- Management через unix socket: `--management /run/…/ovpn.sock unix [pw-file]`. Сокет создаётся
  **`srwxrwxrwx`**. [exec] `--management-client-user <u>` и `--management-client-group <g>` проверяются по peer
  credentials: root при `user=nobody` отклоняется с «UID of socket peer (0) doesn't match». [exec] Команды:
  `state` → `1790103690,CONNECTED,SUCCESS,10.8.0.2,<remote>,1194,,`, `bytecount N`, `log on all`. [exec]
- Credentials: `--auth-user-pass <file>` (2 строки: user, pass) [docs][exec parse]; `--askpass <file>` — пароль
  ключа [docs]; `--auth-nocache` [docs]. Если файл доступен группе или всем, будет warning. [exec] Альтернатива без файла:
  `--management-query-passwords` (+`--management-hold`), тогда пароль передаётся через management. [docs]
- Рекомендуемая командная строка daemon'а. Все наши флаги стоят **после** `--config`, конфиг заранее очищен [inf на основе exec выше]:
  ```
  openvpn --config /run/network-orchestrator/<uid>/<id>.ovpn \
    --dev ovpn-<id> --dev-type tun --route-nopull --script-security 1 \
    --ignore-unknown-option dns-updown --dns-updown disable \
    --mark <M> --management /run/network-orchestrator/<id>.sock unix \
    --management-client-user root --auth-nocache --verb 3
  ```

## 6. Tauri v2: Linux bundling

- `bundle.linux.deb` (tauri-utils 2.9.3, `camelCase`, `deny_unknown_fields`) [src]:
  `depends`, `recommends`, `provides`, `conflicts`, `replaces`, `files`, `section`, `priority`,
  `changelog`, `desktopTemplate`, **`preInstallScript`, `postInstallScript`, `preRemoveScript`,
  `postRemoveScript`**. Каждое из четырёх полей — путь к файлу-скрипту; он копируется в `preinst`/`postinst`/`prerm`/`postrm`
  с правами 0755. [src `debian.rs`]
- `files`: `{ "<путь в пакете>": "<исходник относительно tauri.conf.json>" }`, можно указывать каталоги. [docs]
  ```json
  "linux":{"deb":{
    "depends":["polkitd","iproute2"],
    "recommends":["systemd-resolved","wireguard-tools","openvpn"],
    "files":{
      "/usr/lib/network-orchestrator/network-orchestrator-daemon":"../target/release/network-orchestrator-daemon",
      "/usr/lib/systemd/system/network-orchestrator.service":"../packaging/linux/network-orchestrator.service",
      "/usr/share/polkit-1/actions/com.networkorchestrator.policy":"../packaging/linux/com.networkorchestrator.policy"},
    "postInstallScript":"../packaging/linux/postinst",
    "preRemoveScript":"../packaging/linux/prerm",
    "postRemoveScript":"../packaging/linux/postrm"}}
  ```
- CLI сам добавляет в `depends` пакеты `libwebkit2gtk-4.1-0` и `libgtk-3-0`. [src `tauri-cli/src/interface/rust.rs`]
  Оба имени есть в Ubuntu 26.04 и Debian 13, так же как `polkitd`, `systemd-resolved` и `iproute2`. [exec]
- Режимы файлов в data.tar выставляются через `HeaderMode::Deterministic`: исполняемые получают 0755, остальные 0644, владелец root. [src; семантика
  crate `tar` — inf] **Нет debhelper-сниппетов и conffiles**: `daemon-reload`, `enable --now`, `stop`
  и обработку аргументов `configure|upgrade|remove|purge` нужно писать вручную. [src]
- Платформенные конфиги: `tauri.linux.conf.json` и `tauri.windows.conf.json` мёржатся с базовым через JSON
  Merge Patch (RFC 7396, массивы заменяются целиком). [src `tauri-utils/src/config/parse.rs`] Поэтому
  в `tauri.linux.conf.json` достаточно `{"bundle":{"targets":["deb"]}}`, а база остаётся с `nsis`/`all`. Есть и
  альтернатива: `tauri build --bundles deb`. [inf]
- **Updater и .deb:** tauri-plugin-updater 2.11.0 поддерживает `deb` и `rpm`. [src `updater.rs:1039-1200`] Плагин проверяет
  `is_deb`, затем выполняет `pkexec dpkg -i`; при неудаче спрашивает пароль через zenity или kdialog и вызывает `sudo -S`, последний
  вариант — `sudo` в терминале. CLI подписывает `.deb` как updater-артефакт (`createUpdaterArtifacts`). [src
  `tauri-cli/src/bundle.rs sign_updaters`] Тип бандла определяется по маркеру, который bundler вшивает в бинарник.
  Бинарник, собранный без бандлера (например, Arch из `--no-bundle`), попадает в ветку AppImage. [src/inf]
  Если отключить updater на Linux, deb-пользователи останутся **без обновлений**, пока не появится APT-репозиторий.

## 7. Arch packaging

- Правила Arch [docs Arch package guidelines, Systemd, Polkit]:
  - «**Avoid** using `/usr/libexec/` for anything. Use `/usr/lib/$pkgname/` instead»;
  - units кладутся в `/usr/lib/systemd/system/`;
  - polkit actions — в `/usr/share/polkit-1/actions/`, rules для 3rd-party — в `/usr/share/polkit-1/rules.d/`;
  - в `/usr/local` пакеты ничего не ставят; `optdepends` не дублировать в `.install`.
- Автовключение служб: Arch поставляет `/usr/lib/systemd/system-preset/99-default.preset` с `disable *`
  [exec в `archlinux:latest`]. Wiki: «when a new package is installed, the user must manually enable the
  unit». [docs] `daemon-reload` выполняет pacman-хук `30-systemd-daemon-reload-system.hook`. [exec]
  Из этого следует: `.install` только печатает подсказку `systemctl enable --now network-orchestrator.service`,
  а в `pre_remove` можно выполнить `systemctl disable --now`. [inf]
- Пакеты [exec `pacman -Si`]: `webkit2gtk-4.1` 2.52.6, `gtk3`, `polkit` 127, `iproute2` 7.2.0,
  `systemd` 261.3 (resolved входит в него, по умолчанию **disabled** [exec]), `wireguard-tools`,
  `openvpn` 2.7.7. **`xray` в официальных репозиториях нет** (только AUR).
- Шаблоны Tauri [docs tauri-docs `distribute/aur.mdx`]:
  - `-bin`: `source_x86_64=(…amd64.deb)`, в `package()` распаковать `data.tar.gz` в `$pkgdir`;
  - из исходников: `tauri build -b deb`, затем `cp -a …/bundle/deb/*/data/* "$pkgdir"`.
  В обоих случаях Arch получит те же пути, что и .deb. Поэтому daemon должен лежать в `/usr/lib/network-orchestrator/`, а не в `/usr/libexec`.
- Черновик PKGBUILD (из исходников, `package()` через `install -Dm`) прошёл `makepkg --printsrcinfo`. [exec]
  Файлы: `research/arch/pkg/PKGBUILD`, `network-orchestrator.install`. Полную сборку (`makepkg -si`) не
  делали.

## 8. systemd-resolved

- CLI (resolvectl 259) [exec `--help`]:
  ```
  resolvectl dns <if> 10.8.0.53 [2001:db8::53]   # серверы для link
  resolvectl domain <if> '~.'                    # full tunnel: route-only "всё"
  resolvectl domain <if> corp.example '~int.example'  # split: search + route-only
  resolvectl default-route <if> yes|no
  resolvectl revert <if>                         # сброс всех per-link настроек
  ```
- D-Bus `org.freedesktop.resolve1` `/org/freedesktop/resolve1` `org.freedesktop.resolve1.Manager` [exec busctl
  introspect]: `SetLinkDNS(i ifindex, a(iay))`, `SetLinkDNSEx(i, a(iayqs))`, `SetLinkDomains(i, a(sb))`
  (`b=true` означает route-only, `~`), `SetLinkDefaultRoute(i, b)`, `RevertLink(i)`.
- Маршрутизация запросов [docs `systemd-resolved.service(8)`]:
  - запрос уходит на link с наиболее длинным совпавшим routing-доменом;
  - `~.` на link означает, что «другие links не рассматриваются для этих запросов (если у них нет такого же домена)»;
  - если `default-route` не задан явно, он равен false при наличии route-only домена, отличного от `~.`, иначе true.
- Root без polkit: `bus_verify_polkit_async` → `sd_bus_query_sender_privilege(call, -1)`. Если
  отправитель uid 0, а resolved работает не от root, возвращается 1 и polkit не запрашивается. [src systemd v259
  `bus-polkit.c`, `bus-convenience.c`] Используются actions `org.freedesktop.resolve1.set-dns-servers`, `set-domains`,
  `set-default-route`, `revert`. [exec, файл policy на хосте] Сам вызов через D-Bus или resolvectl в
  hardened unit требует доступа к system bus (`AF_UNIX`). [inf]
- Наличие resolved по дистрибутивам:
  - **Debian 13:** отдельный пакет `systemd-resolved`, `Priority: optional`; у `systemd` он только в Suggests; задачи
    GNOME, KDE и XFCE и `network-manager` его не тянут (`apt-get -s`). [exec] То есть **по умолчанию его нет**. Если его
    установить, postinst превратит `/etc/resolv.conf` в symlink на stub и включит службу. [exec postinst]
  - **Ubuntu 26.04:** `Priority: important`, `systemd` его Recommends; на хосте служба active, `/etc/resolv.conf` указывает на stub. [exec]
  - **Arch:** входит в `systemd`, по умолчанию disabled. [exec]
- Per-link настройки теряются при рестарте resolved, поэтому daemon должен применять их заново. [inf]

---

## Утверждения спеки, которые оказались неверными или неполными

1. **B2** верно только для 26.3.27. Начиная с Xray ≥26.6.27/26.7.11, Xray на Linux сам ставит маршруты
   (`autoSystemRoutingTable`) и адреса (`gateway`); с 26.7.28 имя по умолчанию — случайное `utunNN`.
   Ключ `mtu` в нижнем регистре тоже работает (регистр не важен). Генерируемый `interfaceName` игнорируется, и получается `xray0`.
2. **D4, «`-test` запускается в daemon'е»:** `-test` создаёт реальное устройство и падает с `EBUSY`, если с тем же
   именем уже работает экземпляр. Валидировать нужно конфиг без tun inbound: для этого не нужны ни root, ни daemon.
3. **D4, «Xray только создаёт устройство» и «схема `name`/`MTU`»:** для pinned 26.3.27 это верно. При обновлении pin на
   ≥26.7.x поведение меняется. Решение: pin версии и явное `name`; `gateway`/`autoSystemRoutingTable` не
   использовать, чтобы маршрутами управлял daemon.
4. **D2, «`sockopt.mark` на всех outbound'ах, кроме `freedom`/`blackhole`»:** неверно, `freedom` тоже нужно
   помечать, иначе direct-трафик уйдёт в петлю через TUN. Метка не нужна только `blackhole`. Кроме того, `SO_MARK` требует
   `CAP_NET_ADMIN`/`CAP_NET_RAW` у процесса xray.
5. **D5/B5 (xray от root):** есть альтернатива. С Xray ≥26.6.22 daemon создаёт TUN и передаёт fd через `XRAY_TUN_FD`,
   а xray работает от непривилегированного пользователя. Loop prevention тогда строится на `sockopt.interface`
   или `autoOutboundsInterface`, а не на mark.
6. **D5, OpenVPN «принудительно `--script-security 1`»** недостаточно:
   - флаг действует, только если стоит после `--config`;
   - `plugin` уровнем не регулируется;
   - на 2.7 встроенный `dns-updown` работает при уровне 1 и сам меняет DNS;
   - `log`/`status`/`writepid`/вложенный `config` пишут и читают произвольные пути от root;
   - `up` при уровне 1 даёт fatal.
   Вырезать нужно весь список из §5, а не только `up/down/route-up/ipchange/plugin`.
7. **C1:** правильная форма — `--dev ovpn-<id> --dev-type tun` (не `--dev tun`). Без `--dev-type` произвольное имя не работает.
8. **C1 vs C4:** `--route-nopull` отбрасывает и pushed DNS (`dhcp-option`). Pushed routes и DNS нужно брать из
   строки `PUSH_REPLY` в management log.
9. **C3:** management socket создаётся с правами 0777. Нужен `--management-client-user` (или каталог 0700).
10. **§5 «OpenVPN 2.6»:** в Ubuntu 26.04 стоит 2.7.0, в Arch 2.7.7, в Debian 13 2.6.14. Опции 2.7 (`--dns-updown`)
    передавать через `--ignore-unknown-option`.
11. **D1 (VLESS `allowInsecure`, hy2 `insecure`):** в 26.3.27 после 2026-06-01 это hard error, в 26.9.9 поле удалено.
    Добавить поддержку нельзя, можно только отклонять ссылку или требовать `pcs`/`vcn`. Hysteria в Xray называется `hysteria`,
    `network:"hysteria"`, `security:"tls"` обязателен. `obfs=gecko` не поддерживается в 26.3.27.
12. **G1 `Depends: systemd-resolved`** противоречит D3. На Debian такой Depends принудительно поставит resolved
    и перепишет `/etc/resolv.conf`. Правильно указать его в `Recommends`.
13. **G1 `/usr/libexec/network-orchestrator/daemon` + G2 «те же пути»** противоречат правилу Arch
    (не использовать `/usr/libexec`). Правильный путь для обоих пакетов — `/usr/lib/network-orchestrator/network-orchestrator-daemon`.
14. **G2, `.install` с `systemctl enable --now`** противоречит конвенции Arch (preset `disable *`, пользователь
    включает службу сам). Достаточно печатать подсказку.
15. **G1, postinst/prerm:** у Tauri нет debhelper-сниппетов, поэтому `daemon-reload`/`enable`/`stop` и обработку аргументов
    maintainer-скриптов нужно писать вручную.
16. **G3, «обновления через apt/pacman»:** APT-репозитория нет, а updater поддерживает .deb (`pkexec dpkg -i`).
    Если выключить его на Linux, deb-пользователи останутся без обновлений. Для бинарника без бандлера (Arch)
    updater выключать обязательно: он попадёт в ветку AppImage.
17. **D3:** команды подтверждены, root вызывает resolved без polkit. Нужно дописать повторное применение настроек после
    рестарта resolved.

## Не проверено

- E2E полного туннеля (правила `fwmark`, таблица T) с реальными backend'ами. Проверены только части по отдельности.
- Hysteria port hopping и brutal против реального сервера. `obfs=gecko`.
- `--management-query-passwords` в работе. Поведение pushed `--dns` в 2.7 при `--route-nopull` [inf: отбрасывается].
- Полная сборка .deb с `files` и сборка `makepkg -si`.

## Артефакты (scratchpad/research/)

`tun/*.json`, `tun/passfd.py` (опыты с TUN); `cfg/*.json` (образцы hysteria/vless для `-test`);
`hy/` (interop с hysteria v2.12.3); `ovpn/` (скрипты OpenVPN, man-разделы 2.6.14 и 2.7.0);
`arch/pkg/` (PKGBUILD); `sd/` (исходники systemd v259); `xray-26.3.27/`, `xray-latest/`,
`docs-next/` (исходники и документация Xray); `d716.txt` (стандарт share-link).
