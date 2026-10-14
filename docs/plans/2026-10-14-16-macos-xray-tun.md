# macOS: Xray TUN — системный туннель через helper + XRAY_TUN_FD (2026-10-14)

**Статус:** реализовано (кроме подписи клиента, см. «Отклонения»); проверено
юнит-тестами с фейковыми платформой и runner'ами. Живой прогон с реальным
`utun` на macOS-машине ещё не делался. Прокси-режим (SOCKS + системный
прокси) работал и раньше; этот план добавил TUN-режим Xray как туннель для
всей системы macOS. NetworkExtension не используется — см. решение ниже.

## Задача

Xray-профиль в режиме TUN должен захватывать весь IP-трафик macOS
(браузеры, CLI, игноры системного прокси) с сохранением доменных/IP-правил
(прямой/прокси/блок) и split-DNS профиля.

## Решение: helper создаёт utun и запускает Xray от пользователя через fd

Проверено в исходниках Xray v26.7.28 (pinned для macOS arm64):

- `proxy/tun/tun_darwin.go`: env `XRAY_TUN_FD` — Xray берёт готовый fd и не
  трогает MTU/адрес/маршруты (`ownsFd=false`). Открыть utun может только
  root (socket `com.apple.net.utun_control`), поэтому fd передаёт helper.
- `proxy/tun/handler.go` + `sockopt_darwin.go`: `autoOutboundsInterface:
  "<физический интерфейс>"` в настройках tun inbound регистрирует глобальный
  dialer-controller, который привязывает **все** исходящие dial'ы Xray
  (VLESS, freedom, DNS) к интерфейсу через `IP_BOUND_IF` (macOS-нативный
  эквивалент SO_BINDTODEVICE). Это loop prevention: outbound-трафик Xray не
  попадает обратно в utun, и `direct`-правила не зацикливаются. Работает и в
  fd-режиме (регистрация в `Handler.Start`, не в `tunInterface.Start`).
  `"auto"` выбирать нельзя — с default route через utun он найдёт сам utun
  (и в fd-режиме монитора маршрутов нет).
- Darwin-путь Xray требует у utun point-to-point адреса для маршрутизации:
  `169.254.10.1/30` (gateway `.1`, local `.2`) — тот же default
  (`defaultDarwinGateway`), что Xray сам назначает в ownsFd-режиме.
- «Защищённый default»: вместо одного `0.0.0.0/0` через gateway Darwin-путь
  Xray ставит 8 префиксов `128.0.0.0/1 … 1.0.0.0/8` (покрывают весь unicast,
  кроме `0.0.0.0/8` с loopback) — повторяем их, плюс v6 default через
  интерфейс (без gateway).
- `dns` в tun inbound на macOS игнорируется — DNS настраивает helper
  (networksetup), а сам Xray отвечает на порту 53 через gVisor-стек +
  routing-правила (split-DNS профиля работает как есть).

Почему helper запускает Xray, а не передаёт fd приложению:

- fd через SCM_RIGHTS потребовал бы изменения кадрирования протокола
  (NDJSON без out-of-band) на обеих сторонах — неоправданный риск.
- Словарь методов совпадает с Linux daemon'ом: `xray.connect/disconnect/
  status` с общим `XrayConnectParams` (конфиг в теле запроса, как на Linux).
- Жизненный цикл (смерть процесса, recovery после перезагрузки, journal)
  целиком в helper — как в Linux daemon; bridge остаётся тонким.
- Xray работает **от uid консоли** (helper делает setuid до exec), а не от
  root: user-writable бинарник из per-user install'а исполняется только с
  правами владельца — escalation-пути нет (в отличие от Linux daemon, где
  xray от root). Бинарник при этом повторно проверяется по pinned SHA-256
  (`verify_managed_macos_executable`) перед запуском.

Открытый вопрос плана 14 (NE для full tunnel) закрыт: NE не нужен —
loop prevention решён `IP_BOUND_IF` в самом Xray, а не в ядре.

## Архитектура

```
Swift UI → bridge (C ABI, непривил.) → helper_client → daemon_protocol (NDJSON, Unix socket)
                                                        → macos-helper (root, launchd)
                                                            ├─ tun:  utun (AF_SYSTEM/utun_control), MTU, addr 169.254.10.1/30
                                                            ├─ routes: PF_ROUTE — 8 protected /1../8 via gw + v6 ::/0 via if
                                                            │          + bypass-маршруты via физ. интерфейс
                                                            ├─ dns:  networksetup -setdnsservices <svc> 169.254.10.1
                                                            └─ xray: setuid(console) + exec xray, fd 3, XRAY_TUN_FD=3,
                                                                     конфиг по stdin (как в bridge)
```

Соединение (bridge → helper `xray.connect`):

1. bridge: `hello` → capabilities содержит `xray.connect` (иначе ошибка
   «нужен helper»);
2. bridge готовит конфиг базово (политики профиля, без tun inbound) и
   валидирует `xray run -test` как пользователь (tun inbound не создаёт
   устройство и не требует прав);
3. bridge добавляет macOS-tun inbound (`mtu`, `autoOutboundsInterface`) и
   шлёт готовый конфиг + `dns_bypass` (резолверы, которые должны остаться на
   физ. линке, `dns_bypass_hosts`) в `xray.connect`;
4. helper: резолвит uplink (default route), свободный `utunN` (N≥10),
   создаёт utun (MTU 1500, адрес), проверяет хеш бинарника Xray в per-user
   install'е консоли, открывает лог-файл в user data dir, ставит
   bypass-маршруты → capture-маршруты → DNS → setuid+exec xray (fd 3);
5. helper пишет journal (owner `xray:<profile_id>`, utun, маршруты, DNS,
   pid) и отвечает `XrayConnectResult` (state, interface, dns_applied).

Отключение: kill xray → убрать DNS (восстановить сохранённые) → удалить
маршруты → закрыть utun → обновить journal. Смерть xray ловится waitpid-
потоком, cleanup автоматический. Recovery при старте helper'а: journal →
убить сирот xray (по pid), удалить маршруты/DNS сирот.

## Изменения по слоям

### core

- `xray.rs`: `apply_macos_tun_inbound(base, mtu, uplink)` (схема v26.7.28:
  `mtu` + `autoOutboundsInterface`, sniffing как в `apply_tun_inbound`),
  `strip_tun_inbound` (для `-test`), `prepare_xray_config_base` (конфиг с
  политиками, без tun inbound — для macOS TUN потока).
- `system_proxy.rs::macos`: `NetworksetupRunner` уже инжектируемый — DNS
  модуль helper'а переиспользует тот же паттерн (адаптер `networksetup`).

### macos-helper

- `tun.rs`: создание/закрытие utun, MTU, p2p-адрес, выбор свободного N (≥10,
  как у Xray 10..1024, чтобы не сталкиваться с NE-utun 0..9).
- `routes.rs`: PF_ROUTE RTM_ADD/RTM_DELETE (protected-префиксы, v6 default,
  bypass via uplink: connected-субнеты uplink + /32 gateway + dns_bypass).
- `dns.rs`: snapshot/apply/restore DNS основного сервиса через
  `/usr/sbin/networksetup` (инжектируемый runner для тестов).
- `signing.rs` + `peer.rs`: SecRequirement `identifier "com.netmanager.app.
  macos"` (ad-hoc-подпись бандла вносит identifier; `SecCodeCopyGuestWith
  Process(pid)` + `SecCodeCheckRequirements`). Мутающие методы (`xray.*`)
  отклоняются, если пир не прошёл проверку (uid + путь + подпись).
- `xray.rs`: executor — запуск/остановка/статус xray от uid консоли
  (setuid/setgid + HOME/USER/LOGNAME), лог-файл через dup'нутый fd,
  waitpid-поток, journal в `/var/run/network-orchestrator/` (0600, root).
- `service.rs`: `xray.connect/disconnect/status` в capabilities и dispatch.
  `openvpn.*`/`wireguard.*` остаются unsupported (стедиап 2 плана 14).

### macos-bridge

- `runtime.rs`: TUN-ветки `connect`/`disconnect`/`status` через
  `helper_client`; TUN-профиль не поднимает локальный xray; системный прокси
  гасится при TUN-подключении, если профиль им владел; статус TUN-профилей
  в `snapshot` берётся из helper'а.
- `set_xray_mode` — переключение socks/tun у Xray-профилей (минимальный
  write-метод для нативного клиента, где нет полной формы профиля).

### Swift

- карточка/детали Xray-профиля: переключатель режима SOCKS/TUN, статус
  TUN (интерфейс `utunN`), старт доступен при `helperStatus.reachable &&
  capabilities ∋ xray.connect`;
- `systemProxyOverridden`: наш собственный TUN-интерфейс (из runtime статуса)
  больше не считается «чужим packet-tunnel VPN» — вместо warning бейдж
  активного туннеля;
- `native.backendsNote`/`native.helperRequired` — обновить формулировки.

### docs

- `platform-matrix.md`: Xray TUN macOS — ✅ (helper, XRAY_TUN_FD).
- `AGENTS.md`: в исключения safety-rule добавить helper-supervised Xray TUN
  child, работающий от uid пользователя.

## Отклонения от первоначального замысла

Выяснились при реализации; код — источник истины.

- **`route(8)` вместо PF_ROUTE.** `routes.rs` запускает `/sbin/route` через
  инжектируемый runner (`sysexec.rs`): та же семантика, проверяемые в тестах
  командные строки, без ручной сборки rtmsg, которую нельзя проверить без
  root. Удаление идёт по адресату (без шлюза), отсутствующий маршрут = ок.
- **tun inbound добавляет helper, а не bridge.** Bridge шлёт конфиг с
  политиками и **без** tun inbound (и уже прошедший `xray run -test`); helper
  сам определяет uplink (`route -n get default`), вырезает любой tun inbound и
  вставляет свой через `apply_macos_tun_inbound`. Так ни один клиент не может
  задать чужой `autoOutboundsInterface`, а uplink определяется один раз.
- **DNS: Xray не отвечает на порт 53 сам** (исходное допущение плана было
  неверным). Пакеты на `169.254.10.1:53` приходят в `tun-in` как обычный
  трафик и без `dns`-outbound уходят `direct` в никуда — ни одно имя не
  резолвится, domain-правила не срабатывают. `apply_macos_dns_capture`
  (core) всегда добавляет: `dns`-outbound + правило `tun-in`/порт 53 → он;
  `dns.servers` — локальные резолверы только для доменов, идущих `direct`
  (явные с сервиса, иначе DHCP через `ipconfig getoption`; читаются до смены
  DNS), затем `https://1.1.1.1/dns-query` через прокси; правила, привязывающие
  адреса резолверов к своей стороне туннеля; `domainStrategy: UseIP` у
  freedom, чтобы прямое соединение к имени тоже резолвилось через эти
  серверы, а не через ОС (она смотрит обратно в туннель). Профиль с
  собственным port-53 правилом не трогается. Конфиг проверен настоящим
  `xray run -test`.
- **Конфиги провайдеров приходят со своим DNS.** Типичный профиль уже содержит
  `dns`-outbound с `rules` (новый Xray): `return` для AAAA/HTTPS, `hijack` лишь
  для нескольких RU-доменов и catch-all `direct` — «переслать остальное на
  фиксированный резолвер как есть». Такие ответы настоящие, мимо fake-DNS, и
  имена пользователя (`ds-mind-lab.ru`) туда не попадали. Поэтому имена из
  правил `direct`/`block` добавляются в `hijack`-правило перед первым `direct`
  (`hijack_routed_domains`). Правило перехвата порта 53 в этом случае у профиля
  уже есть, наше не добавляется; но наше ограничено адресом туннеля
  `169.254.10.1` (`tun-in`), чтобы запросы приложений к другим резолверам
  (корпоративный DNS, 8.8.8.8) не подменялись.
- **Корпоративные имена.** Search-домены сети (`networksetup
  -getsearchdomains`, DHCP `search_domain`/`domain_name`) и явные + DHCP
  резолверы читаются до смены DNS; имена под search-доменами получают
  правило `direct`, `dns.servers`-записи с локальными резолверами и попадают в
  hijack — иначе они уходили на публичные резолверы профиля (`rcode: 3`).
- **Fake-DNS для маршрутизируемых имён.** Domain-правила видят имя только из
  sniffing (TLS SNI / HTTP Host / QUIC); SSH, БД и прочее приходят голым IP и
  уходили бы в прокси по умолчанию (так `git fetch` по SSH к домену из
  `direct` шёл через прокси). Поэтому имена из правил `direct`/`block` получают
  fake-ответы (`fakedns` в `dns.servers` только для этих доменов, пул
  `198.18.0.0/16`), а sniffing `fakedns` на `tun-in` возвращает имя. `freedom`
  получает `domainStrategy: UseIP` — Xray сам резолвит имя реальным
  сервером (fake-сервер он при этом пропускает, проверено на живом Xray).
  Включается и поверх собственного DNS-перехвата профиля. Пул `198.18/16`
  пересекается с адресами других VPN (incy), с ними одновременно не работать.
- **Если default route уже у `utunN`** (чужой VPN), `xray.connect` отвечает
  `conflict`: иначе loop-prevention привязал бы Xray к чужому туннелю.
- **Порядок подъёма:** utun → запуск Xray → пауза 0.7 с и проверка, что он
  жив → bypass → capture-маршруты → DNS. Любой сбой откатывает уже сделанное;
  DNS восстанавливается только если его успели менять.
- **v6:** вместо одного `::/0` — две половины `::/1` и `8000::/1` через
  интерфейс (default уже занят физическим линком).
- **Bypass:** хосты из `dns_bypass` (IPv4; имена helper резолвит сам) идут
  через шлюз uplink; connected-подсети и `/32` шлюза не нужны — они уже
  длиннее `/1../8`.
- **Путь к Xray** helper не принимает «как есть»: клиент передаёт только
  `macos_data_root` (новое необязательное поле `XrayConnectParams`, Linux его
  не использует); helper требует владельца = консольный пользователь,
  отсутствие симлинков и пины SHA-256 (`verify_managed_macos_executable`).
- **Сброс привилегий** целиком в `pre_exec`: `setgroups([gid])`, `setgid`,
  `setuid`, проверка необратимости (`setuid(0)` обязан не пройти), `dup2` fd на 3.
  `Command::uid` не используется — он оставил бы supplementary-группы root.
- **Лог Xray:** `/var/run/network-orchestrator/xray-tun.log`
  (`O_NOFOLLOW`, 0600, владелец — пользователь), вместо файла в каталоге
  пользователя (root не должен открывать пути, которыми управляет юзер).
  Bridge читает хвост оттуда.
- **Журнал:** одна запись `xray-tun.json` (0600, атомарная замена) в
  `/var/db/network-orchestrator`; write-ahead до любых изменений. Recovery при
  старте helper'а и по `recovery.cleanup`; при остановке helper'а (SIGTERM)
  туннель снимается.
- **Слежение за смертью Xray:** опрос раз в 2 с (`reap`), а не waitpid-поток.
- **Один туннель одновременно**; второй `xray.connect` → `conflict`.
- **Не сделано — проверка подписи клиента (`signing.rs`, SecRequirement).**
  Мутирующие методы защищены прежней проверкой пира (uid консольного
  пользователя + путь исполняемого файла приложения). Подпись усилит это
  против подмены процесса, но требует подписанных сборок для проверки;
  остаётся отдельной задачей.

## Ограничения (принятые)

- `autoOutboundsInterface` — имя uplink'а фиксируется на момент connect'а
  (в fd-режиме у Xray нет route-монитора); смена Wi-Fi↔Ethernet требует
  переподключения.
- DNS ставится на сервис, несущий default route; другие сервисы (второй
  Wi-Fi, Thunderbolt Bridge) не трогаются.
- Multicast/DNS-проверки за пределами профиля — как на других платформах.
- E2E с реальным utun — только на живой macOS-машине (не в CI): в тестах —
  фейковый helper-сокет, synthetic-архив Xray, инжектируемые runners.
