# Network Orchestrator

A cross-platform network management tool that provides a unified view of all
network interfaces, routes, and DNS configuration. Currently in early
development (MVP-0: Network Explorer).

## Why

If you have multiple VPNs — WireGuard for work, OpenVPN for another network,
Xray/VLESS for geo-bypass — you end up juggling several clients with no
coherent picture of what goes where. Network Orchestrator solves this by
providing a single model over all interfaces and routes.

The first milestone (Network Explorer) is read-only: it inventories all
network interfaces, shows the full route table, and answers "which interface
will the OS use to reach this IP?" — without managing any VPN.

## Current features

- **Interface inventory** — all network interfaces (Wi-Fi, Ethernet,
  WireGuard, OpenVPN, TUN, loopback, Tailscale, Docker, WSL, etc.) with
  addresses, DNS, MTU, and state
- **Route table** — full IPv4 routing table with destination, prefix, gateway,
  interface, and metric
- **Route lookup** — longest-prefix-match lookup: "where will this IP go?"
- **Auto-refresh** — UI updates automatically when the routing table changes

## Roadmap

- **MVP-1:** WireGuard backend (start/stop tunnels, manage configs)
- **MVP-2:** Profiles + IP/CIDR policy routing (apply routes via OS API)
- **MVP-3:** OpenVPN backend
- **MVP-4:** Xray/VLESS backend + domain routing via Xray config generation

### Out of scope (for now)

- VPN chaining
- Process-based routing
- macOS support (open to PRs)

## Tech stack

- **Backend:** Rust, `net-route` (cross-platform routing table),
  `windows` crate (IP Helper API on Windows), `libc` (getifaddrs on Linux)
- **Desktop:** Tauri 2
- **Frontend:** React + TypeScript + Vite

## Architecture

```
                    GUI (Tauri + React)
                           |
                    Network Core (Rust)
                           |
            +--------------+--------------+
            |              |              |
      Network Explorer   Profiles      Policy Engine
      (read-only)        (future)       (future)
            |
            +----------+-------------------+
                       |
                Platform Adapter
                       |
            +----------+----------+
            |                     |
         Windows                 Linux
         IP Helper API           getifaddrs + netlink
         GetAdaptersAddresses    /sys/class/net
```

Core logic lives in `crates/core/` — a pure Rust library with no Tauri
dependency. The Tauri app in `src-tauri/` is a thin wrapper that exposes
core functions as Tauri commands.

## Project structure

```
network-orchestrator/
├── crates/core/          # Pure Rust library (models, explorer)
│   └── src/
│       ├── models.rs     # NetworkInterface, RouteEntry, RouteLookupResult
│       └── explorer.rs    # list_interfaces, list_routes, lookup_route
├── src-tauri/            # Tauri 2 desktop app
│   └── src/
│       └── lib.rs        # Tauri commands + route change watcher
├── src/                  # React frontend
│   ├── App.tsx           # Layout + tab navigation
│   ├── components/
│   │   ├── InterfaceList.tsx
│   │   ├── RouteTable.tsx
│   │   └── RouteLookup.tsx
│   └── types.ts          # TypeScript types matching Rust models
└── Cargo.toml            # Workspace root
```

## Development

### Prerequisites

**Linux (WSL or native):**
```bash
sudo apt install -y \
  libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev \
  libayatana-appindicator3-dev libdbus-1-dev \
  libsoup-3.0-dev libjavascriptcoregtk-4.1-dev
```

**Windows:** Install [Rust](https://rustup.rs/) and
[Node.js](https://nodejs.org/). No extra system libraries needed.

### Run

```bash
npm install
npm run tauri dev
```

### Build

```bash
npm run tauri build
```

### Tests

```bash
cargo test -p net-manager-core
```

## License

[MIT](LICENSE)
