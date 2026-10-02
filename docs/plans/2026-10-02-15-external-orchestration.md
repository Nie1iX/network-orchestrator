# Оркестрация внешних VPN-клиентов (2026-10-02)

**Статус:** реализовано и проверено — полный `e2e/linux/run.sh` зелёный
(85 core + WG/OVPN/Xray-сьюты, включая attach-сценарий и Xray TUN datapath).
Реализация по стадиям ниже; ключевые отличия от первоначального наброска:

- `routes.apply` получил поле `attach: AttachSpecParams` — intent
  журналируется как `OwnedResource::AttachSpec` рядом с realized `Route`;
  reconcile-loop (`reconcile_network`, 10с + netlink wake) пересчитывает
  желаемое состояние по текущему ifindex каждый проход.
- Bypass: `/32` через физический uplink (метрика 50, как у NM),
  перенацеливается при смене uplink; DNS-имена резолвятся при reconcile
  с bounded 3с на helper-потоке. Endpoint, лежащий в connected-подсети
  uplink'а, пинится `dev`-маршрутом, а не `via` шлюз — hairpin через
  промежуточный хост видит поток только в одну сторону и падает на строгих
  conntrack/firewall (поймано e2e на Fedora: firewalld
  `ct state invalid drop`).
- NM up/down идёт через демона (`nm.list`, `nm.setActive`), не напрямую —
  активация NM требует root/polkit, которыми владеет именно демон.
- Deferred-статус в UI: бейдж «armed» на профиле + сообщение статуса
  «routes are armed and will install when interface X appears».

## Контекст и доказательство

Мотивирующий кейс воспроизведён на этом ноутбуке (Fedora 44, Happ 4.3.0 +
NM-managed OpenVPN `pfSense-Contractor-*`):

- Happ держит `default dev happ-xray metric 1` в main-таблице. `ip rule` и
  nft-mark/tproxy у него нет — клиент играет по правилам таблицы маршрутов.
- Endpoint OpenVPN (`91.245.41.31`) при активном Happ резолвится в `happ-xray`
  → UDP-handshake умирает по 60-секундному TLS timeout (A/B-эксперимент:
  без bypass — fail, с `/32` через физический gateway — connect за ~2 с).
- NM сам добавляет host-route до сервера (`proto static metric 50`), но
  **после** handshake — bootstrap себя обеспечить не может.
- Сосуществование уже доказано: `wg-kzn2` (NM wireguard) держит свои /24 + /16
  параллельно с Happ; более конкретные маршруты побеждают `default`.

Вывод: приложение может разруливать конфликты «личный VPN vs корп. VPN»
как **оркестратор маршрутной плоскости поверх внешних клиентов**, не владея
их процессами.

## Граница продукта (контракт на клиента)

Оркестрируются только клиенты, живущие в main-таблице маршрутизации:

| Клиент | Статус |
|---|---|
| Happ 4.x (Linux), NM OpenVPN/WireGuard, wg-quick | ✅ проверено/ожидаемо |
| Xray TUN как attach-таргет | ✅ проксирует любой dst |
| WireGuard как attach-таргет | ⚠️ только сети внутри peer `AllowedIPs` |
| Клиенты с `ip rule` / fwmark / tproxy / killswitch | ❌ честно помечаем «не оркестрируется» |
| macOS NetworkExtension (`enforceRoutes`) | ❌ вне scope до helper'а |

Детекция нарушения контракта — отдельная стадия (capability probe): читаем
`ip rule` и nft marks и помечаем чужой туннель, если его трафик выбирается
не из main. Не прячем от пользователя — это explainer-фича.

## Модель

Ключевой сдвиг: **маршруты — наш intent в сторе, а не состояние ядра**.
Профиль привязан к имени интерфейса; iface отсутствует → intent «armed/
awaiting interface», появление iface → демон применяет.

`Profile` (serde camelCase, additive):

- `endpointBypasses: Vec<String>` — хосты (IP или DNS-имена) VPN-серверов,
  которые демон маршрутизирует через текущий физический uplink-gateway.
  Резолв при apply + re-resolve при reconcile (DNS-дрейф подписок).
- `waitForInterface: bool` (default false → прежнее strict-поведение
  `interface not found`); true → connect «arm»-ит intent, маршруты
  применяются когда iface появляется.

`interface_name` остаётся точкой привязки: `tun0`, `happ-xray`, `wg-quick-*` —
по имени, не if_index (внешние TUN пересоздаются при реконнекте).

Настройка приложения `appMode: orchestrator | manager | combined`
(default `combined` — обратная совместимость): UI-фильтр возможностей,
ничего не удаляет. `orchestrator` скрывает создание/подключение managed
backend'ов; `manager` — прежний UX.

## Демон (`crates/daemon`)

- **Armed attach:** owned-маршруты, привязанные к имени отсутствующего iface,
  живут в журнале как `deferred`; на RTM_NEWLINK/ADDR с именем-таргетом —
  re-resolve if_index и применить (цикл reconcile уже существует:
  `reconcile_network` + `reconcile_static_routes` вызываются из
  netlink-monitor в server.rs).
- **Re-assert («принудительно»):** удаление owned-маршрута из ядра чужой
  стороной → ближайший reconcile восстанавливает. Уже работает для owned;
  расширить на external-bound и bypass-записи.
- **Endpoint bypass:** host-route `/32`/`/128` через `GatewayRoutes`
  (shared_gateways — тот же паттерн, что у managed-Xray bypass: смена
  uplink-gateway на roam/DHCP-renew → retarget). DNS-имена резолвятся на
  apply и пере-резолвятся при смене uplink.
- **NM inventory (опц.):** чтение списка NM-конфигураций `vpn`/`wireguard`
  через D-Bus для показа в UI как launchable-внешних профилей
  (zbus уже в deps демона; up/down — user-privileged, может делать и
  app-процесс напрямую).

## Приложение (`src-tauri` + `src`)

- Команды: `list_nm_connections` (name/uuid/type/state), `nm_connection_up`,
  `nm_connection_down` — жизненный цикл остаётся NM, мы только триггерим.
- Форма профиля: выбор attach-таргета (внешние tunnel-iface + NM-коннекшны +
  свободное имя), поле «Endpoint bypass» (chips: hostname/IP), тоггл
  «ждать интерфейс».
- Route map / карточка: третье состояние маршрута «declared — awaiting
  interface» рядом с predicted/effective.
- Diagnostics: сигнатура `TLS handshake failed` у OpenVPN +
  `route get endpoint → foreign tun` → подсказка-кнопка «добавить bypass».
- Settings → режим приложения (orchestrator/manager/combined).
- External-tunnel панель: attach-таргет, не только «stop».

## Стадии

1. **core:** поля `endpointBypasses`/`waitForInterface`; planner отдаёт
   deferred-план при отсутствии iface; unit-тесты (RED→GREEN).
2. **daemon:** armed-apply по имени, bypass-ресурс через shared_gateways,
   reconcile re-assert; тесты в существующем fake-harness.
3. **app:** NM-инвентарь + up/down, поля формы, deferred-отображение.
4. **mode toggle + capability probe** (`ip rule`/nft) + explainer-хинты.
5. **e2e/linux:** фейковый внешний TUN (default dev X metric 1) + профиль
   с bypass и attach → connect external → маршруты применились,
   down → откат только наших.

## Acceptance (соответствует проверенному кейсу)

> Happ поднят → OpenVPN-коннекшн в NM выключен → профиль оркестратора
> (bypass до endpoint + corp-CIDR → tun0, waitForInterface) активен →
> `nmcli up` → handshake проходит → corp-ресурс доступен → интернет идёт
> через happ-xray → `nmcli down` → наши маршруты убраны, intent armed.

## Non-goals

- Не трогаем managed-запуск backend'ов (заморожен, не удалён).
- Не управляем клиентами вне main-таблицы — только детектим и объясняем.
- Не трогаем macOS до появления privileged helper (план 14).
- Не перехватываем DNS внешних туннелей; свои профили DNS как прежде.
