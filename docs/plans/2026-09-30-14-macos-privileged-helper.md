# macOS: привилегированные мутации через launchd-хелпер, а не через bridge (2026-09-30)

**Статус:** решение принято, реализация не начата. Сейчас на macOS нет
ни одной сетевой мутации (`capabilities.networkMutations = false`).

## Контекст

`crates/macos-bridge` — in-process C ABI для SwiftUI-клиента: ограниченный
JSON-кадр → `method` → `args` → `{ok, data | error}`. По форме это второй
JSON-dispatch API рядом с `daemon_protocol` (ограниченный кадр → `method` →
`params` → `ResponseFrame`). Пока bridge обслуживает только
непривилегированные локальные операции (профили, импорт, инспекция, снимок
интерфейсов, lookup), и по смыслу он аналог Tauri-команд, а не демона.

Проблема появится вместе с туннелями: если добавлять `connect` /
`routes.apply` / DNS прямо в bridge, получится третья реализация
привилегированного словаря (Windows in-process, Linux daemon, macOS bridge)
с собственной авторизацией и журналом владения.

## Решение

1. **Bridge остаётся непривилегированным.** Никаких методов из
   `daemon_protocol::method` в `dispatch`: это закреплено тестом
   `daemon_protocol_methods_are_never_served_by_the_bridge`.
2. **Мутации на macOS идут в launchd-демон** (`SMAppService.daemon`),
   собранный из `crates/daemon` с macOS-исполнителями. Он говорит тем же
   `daemon_protocol` (NDJSON, `hello`/capabilities, `RequestFrame`/
   `ResponseFrame`/`EventFrame`, `MAX_FRAME_BYTES`) поверх Unix domain socket.
   Транспорт и исполнители платформенные, словарь общий.
3. **Клиент протокола один.** `src-tauri/src/daemon_client.rs` переносится в
   core (или отдельный крейт) и используется и Tauri, и bridge. Bridge
   получает не по методу на каждую мутацию, а максимум один сквозной вызов
   к хелперу. Сборка параметров connect из профиля (сейчас Linux-ветки в
   `src-tauri/src/commands/tunnels.rs`) переезжает в core, чтобы Swift-клиент
   не дублировал её.

## Что платформенное (Linux → macOS)

| Слой | Linux | macOS |
|---|---|---|
| Запуск | systemd unit | `SMAppService.daemon` + launchd plist |
| Сокет | `/run/network-orchestrator/daemon.sock` | `/var/run/network-orchestrator/daemon.sock` |
| Личность пира | `SO_PEERCRED` + pidfd (`peer.rs`) | `getpeereid` / `LOCAL_PEERCRED` + audit token, проверка code-signing requirement клиента |
| Авторизация | polkit actions (`auth.rs`) | Authorization Services с теми же `Action`-уровнями (`VpnAuthMode`) |
| Маршруты/линки | netlink (`netlink.rs`) | `PF_ROUTE` routing socket, `utun` |
| DNS | systemd-resolved (`dns.rs`) | SCDynamicStore / `/etc/resolver` |
| Журнал владения, recovery | `journal.rs` | тот же код, другой путь |

## Предпосылки, уже выполненные

- Платформенно-нейтральные модули `crates/daemon` (`openvpn`, `xray`,
  `wireguard`, `validate`, `journal`, `auth`, `settings`, `tailscale`)
  компилируются и тестируются на macOS: чистые помощники имён линков
  вынесены в `link_names.rs`, `stage_dir` — в `openvpn.rs`, без зависимости
  от Linux-only `core`/`openvpn_process`.

## Открытые вопросы

- `capabilities.systemVPN = "providerSetupRequired"` в bridge намекает на
  NetworkExtension. Для полнотуннельного системного VPN NE может оказаться
  обязательным (App Store, sandbox); тогда хелпер отвечает только за
  маршруты/DNS, а туннель поднимает provider. Решить до первой мутации.
