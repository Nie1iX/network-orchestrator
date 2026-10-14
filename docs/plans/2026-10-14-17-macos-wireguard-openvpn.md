# macOS: WireGuard и OpenVPN через привилегированный помощник (2026-10-14)

**Статус:** реализовано и проверено юнит-тестами (фейковые платформы/runner'ы,
настоящее рукопожатие WireGuard между двумя движками по loopback, фейковый
management-сервер OpenVPN). Живой прогон с настоящим `utun`, VPN-сервером и
root на машине ещё не делался. Продолжает
`2026-09-30-14-macos-privileged-helper.md` (этап 2) и
`2026-10-14-16-macos-xray-tun.md`.

## Решения

- **WireGuard — без внешних бинарников.** Движок данных (`wg_engine.rs`) —
  один поток внутри helper'а на `boringtun::noise::Tunn`: `poll` по `utun` и
  UDP-сокетам, рукопожатия/сессии/таймеры по пирам, выбор пира по самому
  длинному совпадению `AllowedIPs`, роуминг эндпоинта. UDP-сокеты привязаны к
  физическому интерфейсу (`IP_BOUND_IF`/`IPV6_BOUND_IF`), поэтому туннельный
  трафик не возвращается в собственные маршруты и host-маршрут до эндпоинта не
  нужен. Выбрано вместо `wireguard-go` (нет Go в сборке, второй бинарник и
  UAPI-сокет) и вместо NetworkExtension (см. план 14).
- **OpenVPN — закреплённый самодостаточный бинарник в бандле.**
  `scripts/build-macos-openvpn.sh` собирает 2.6.17 из архива с проверкой
  SHA-256 (тот же, что в формуле Homebrew), статически линкуя OpenSSL, LZO и
  LZ4; в итоге зависимость только от системных библиотек (скрипт это
  проверяет). `build-macos-native.sh` кладёт его в `Contents/Helpers/openvpn` и
  до сборки helper'а записывает SHA-256 в `crates/macos-helper/backends.json`
  (вшивается в подписанный helper). Helper читает файл бандла без симлинков,
  сверяет хэш и запускает только root-владельческую копию
  (`trusted_exec::stage_backend`).
- **OpenVPN не управляет сетью.** Фиксированные флаги: `--route-nopull
  --route-noexec --script-security 1 --dns-updown disable`,
  `--management … unix --management-client-user root --management-hold`.
  Конфиг проходит `sanitize_openvpn_config` из core (тот же, что на Linux:
  никаких `up`/`plugin`/`script-security`, лимиты строк и ассетов) и
  раскладывается в root-каталог `/var/run/network-orchestrator/openvpn/<uid>/<имя>`
  (0700; файлы 0600; удаляется при любом завершении). Парольные запросы
  отвечаются из запроса клиента через management; маршруты и DNS по push ставит
  helper, как для Xray.
- **Один туннель за раз.** Xray TUN, WireGuard и OpenVPN делят default route и
  системный DNS; второй вид отвечает `conflict`.

## Как это работает

```
Swift → bridge (vpn_backends.rs: читает управляемый конфиг из хранилища)
      → helper_client → daemon_protocol (wireguard.* / openvpn.*)
      → macos-helper: wireguard.rs / openvpn.rs
```

`wireguard.connect`: разбор конфига (`wireguard_config.rs`, хуки `PreUp/PostUp`
не исполняются — только предупреждение) → утверждение uplink → `utun` (MTU
конфига или 1420) → адреса через `ifconfig … alias` → движок → маршруты
`AllowedIPs` (`0.0.0.0/0` и `::/0` как две половины `/1`, остальные
best-effort; `Table = off` — без маршрутов) → DNS сервиса uplink на `DNS =` из
конфига. Предупреждения: `ipv6NotCovered` (захвачен только v4), `dnsNotApplied`,
`ignoredHook`.

`openvpn.connect`: запрос приходит с конфигом, ассетами (base64) и, если нужно,
логином/паролем/фразой ключа → санитайзер → бинарник → процесс от root →
management (`state on`, `log on all`, `hold release`) → поток-монитор разбирает
события. По `CONNECTED` + `PUSH_REPLY` helper ставит: bypass-маршруты до IP
сервера (`remote` резолвятся заранее, реальный IP берётся из `>STATE`),
захват/маршруты через `utunN`, DNS. При `RECONNECTING` маршруты остаются
(трафик не утекает), при выходе процесса/ошибке всё откатывается, а причина
(`authenticationFailure`, `credentialsRequired`, …) остаётся в статусе.

Откат везде один: процесс/движок → DNS → маршруты → устройство → журнал. Журнал
пишется до изменений (`wireguard.json`, `openvpn.json`, `xray-tun.json`), при
старте helper'а сирот убирают `recover()`.

## Клиент

- Переключатель подключения у WireGuard/OpenVPN доступен всегда; без helper'а
  нажатие предлагает его установить (как для Xray TUN).
- OpenVPN: мост отдаёт `credential_requirements` (по тем же правилам, что
  Linux-клиент), приложение спрашивает логин/пароль/фразу и по желанию хранит их
  в Связке ключей (`CredentialStore`); отказ сервера стирает сохранённое.
- Статусы и причины (`connecting`, `authentication failed`, предупреждения)
  показываются в строке подключения; лог OpenVPN — в меню подключения.

## Ограничения

- Живой E2E (настоящий `utun`, маршруты, DNS, сервер) — только на машине с
  root; в тестах всё через фейки.
- IPv6-адрес сервера OpenVPN не получает bypass-маршрута (шлюз v6 не
  определяется); сервер по v4 — получает.
- OpenVPN: `probe`/`plan` из протокола не реализованы; DCO не используется.
- Сборка OpenVPN требует Homebrew (`openssl@3 lzo lz4`, только статические
  библиотеки) и сети при первой сборке; результат кэшируется в
  `target/macos-backends/`.
- Хэш в `backends.json` меняется только при новой сборке бинарника.
