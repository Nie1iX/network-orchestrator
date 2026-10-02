# macOS: привилегированные мутации через launchd-хелпер, а не через bridge (2026-09-30)

**Статус:** этап 1 реализован (каркас helper'а, установка, проверка клиента).
Сетевых мутаций на macOS по-прежнему нет (`capabilities.networkMutations =
false`): исполнители WireGuard/OpenVPN/TUN ещё не написаны.

## Этап 1 — сделано (0.7.0)

- `crates/macos-helper` (`network-orchestrator-helper`): launchd-демон с общим
  `daemon_protocol` по Unix-сокету `/var/run/network-orchestrator/helper.sock`
  (0666, доступ решает политика пира). Обязательный `hello`, ограниченные
  кадры, лимит соединений. Исполняет только `owned.list` и
  `recovery.cleanup` (пустые), остальное — `unsupportedMethod`; список
  `capabilities` в `hello` честный.
- Политика пира: uid владельца `/dev/console` **и** путь процесса
  (`proc_pidpath`) равен исполняемому файлу приложения в том же бандле.
  Проверка подписи кода (SecRequirement) — следующий шаг; путь не защищает от
  подмены самого бандла, поэтому до неё helper не получает мутаций.
- Установка: бандл содержит `Contents/MacOS/network-orchestrator-helper` и
  `Contents/Library/LaunchDaemons/com.netmanager.app.helper.plist`; приложение
  регистрирует его через `SMAppService.daemon` (подтверждение в Настройки →
  Объекты входа). Пароль администратора приложение не запрашивает и не хранит.
- `core::helper_client` — блокирующий клиент протокола; мост даёт
  `helper_status` (достижим ли сокет, версия, capabilities). Мост по-прежнему
  не обслуживает методы `daemon_protocol`.
- Настройки → «Привилегированный помощник»: состояние, установка, удаление.

## Этап 2 — не начат, нужно решение по дистрибуции бинарников

Root-демон нельзя заставлять запускать пользовательски-записываемый файл или
файл с пользовательски-записываемыми dylib. Homebrew `openvpn`
(`/opt/homebrew/sbin`, линкуется с `/opt/homebrew/opt/openssl`) именно такой, как
и `wg-quick` (bash + `wireguard-go`). Допустимые варианты:

1. **Бинарники в подписанном бандле.** `openvpn` и `wireguard-go`, собранные из
   закреплённых тегов (хеш исходников в репозитории), статически или с
   dylib внутри бандла; helper запускает только их и проверяет путь/владельца.
2. **NetworkExtension** (packet tunnel provider, как WireGuard.app): нужны
   entitlement и подпись Developer ID; helper отвечает только за маршруты/DNS.

После выбора: исполнители маршрутов (`/sbin/route`/`ifconfig` или PF_ROUTE),
DNS (SCDynamicStore), журнал владения, очистка при смерти клиента и
восстановление после перезагрузки, затем подключение Swift-UI к connect.


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
