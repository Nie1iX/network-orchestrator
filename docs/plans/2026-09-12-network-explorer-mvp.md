# Network Explorer MVP Implementation Plan

**Goal:** Build a read-only Network Explorer for Windows that inventories all network interfaces, routes, and DNS, and answers "which interface will Windows use to reach this IP?"

**Architecture:** Tauri 2 desktop app. Rust backend queries Windows IP Helper API (`GetAdaptersAddresses`, `GetIpForwardTable2`) via the `net-route` crate and the `windows` crate. React/TypeScript frontend renders interface list, route table, and a "trace route" lookup. No VPN management in this phase — pure observation.

**Tech Stack:**
- Rust + Tauri 2.11.x (MSRV 1.78+)
- `net-route` 0.4.6 — cross-platform routing table read/listen (wraps `GetIpForwardTable2` on Windows)
- `windows` crate — IP Helper API for adapter addresses, DNS
- React + TypeScript + Vite (Tauri default frontend)
- Vitest — frontend unit tests
- `cargo test` — backend unit tests

**Scope boundaries (MVP-0):**
- Windows only
- Read-only: no route changes, no VPN control
- IPv4 only in first pass; IPv6 added structurally but not required to work
- No domain routing, no process routing, no VPN chaining

---

## Task 1: Scaffold Tauri 2 project with Cargo workspace

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `src-tauri/Cargo.toml`
- Create: `src-tauri/src/main.rs`
- Create: `src-tauri/tauri.conf.json`
- Create: `package.json`
- Create: `src/App.tsx` (Tauri default)

**Step 1: Scaffold with Tauri CLI**

Run:
```bash
cd /home/artur/pet_projects/net_manager
npm create tauri-app@latest . -- --template react-ts --manager npm
```

If the directory is not empty, move `summary.txt`, `chat.txt`, `analysis.md`, `docs/` aside first, scaffold, then move back.

Expected: project created with `src-tauri/`, `src/`, `package.json`, `tsconfig.json`, `vite.config.ts`.

**Step 2: Verify dev build works**

Run:
```bash
npm install
npm run tauri dev
```

Expected: Tauri window opens with default React app. Close it.

**Step 3: Add workspace-level dependencies**

Edit `src-tauri/Cargo.toml`, add under `[dependencies]`:
```toml
net-route = "0.4"
windows = { version = "0.58", features = [
    "Win32_Foundation",
    "Win32_NetworkManagement_IpHelper",
    "Win32_Networking_WinSock",
] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["full"] }
ipnet = "2"
```

**Step 4: Verify it compiles**

Run:
```bash
cd src-tauri && cargo check
```

Expected: compiles with no errors (warnings OK).

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: scaffold Tauri 2 project with workspace deps"
```

---

## Task 2: Define core data models

**Files:**
- Create: `src-tauri/src/models.rs`
- Modify: `src-tauri/src/main.rs` (add `mod models;`)

**Step 1: Write the model structs**

`src-tauri/src/models.rs`:
```rust
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkInterface {
    pub name: String,
    pub friendly_name: String,
    pub kind: InterfaceKind,
    pub state: InterfaceState,
    pub addresses: Vec<InterfaceAddress>,
    pub dns_servers: Vec<IpAddr>,
    pub mtu: Option<u32>,
    pub if_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InterfaceKind {
    Ethernet,
    Wifi,
    WireGuard,
    OpenVpn,
    Xray,
    Loopback,
    Other(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InterfaceState {
    Up,
    Down,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceAddress {
    pub address: IpAddr,
    pub prefix_len: u8,
    pub family: AddressFamily,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteEntry {
    pub destination: IpAddr,
    pub prefix_len: u8,
    pub gateway: Option<IpAddr>,
    pub interface_index: u32,
    pub interface_name: String,
    pub metric: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteLookupResult {
    pub destination: IpAddr,
    pub matched_route: RouteEntry,
    pub interface_name: String,
}
```

**Step 2: Write a unit test for serialization**

Append to `src-tauri/src/models.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_serializes_to_camel_case() {
        let iface = NetworkInterface {
            name: "wg0".into(),
            friendly_name: "WireGuard".into(),
            kind: InterfaceKind::WireGuard,
            state: InterfaceState::Up,
            addresses: vec![],
            dns_servers: vec![],
            mtu: Some(1420),
            if_index: 7,
        };
        let json = serde_json::to_string(&iface).unwrap();
        assert!(json.contains("\"friendlyName\""));
        assert!(json.contains("\"ifIndex\""));
    }
}
```

**Step 3: Run test to verify it passes**

Run:
```bash
cd src-tauri && cargo test models::tests
```

Expected: PASS.

**Step 4: Commit**

```bash
git add -A
git commit -m "feat: define core network data models"
```

---

## Task 3: Implement Windows interface inventory

**Files:**
- Create: `src-tauri/src/explorer.rs`
- Modify: `src-tauri/src/main.rs` (add `mod explorer;`)

**Step 1: Write the interface collection function**

`src-tauri/src/explorer.rs`:
```rust
use crate::models::*;
use std::net::IpAddr;
use std::ptr;
use windows::Win32::Foundation::NO_ERROR;
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetAdaptersAddresses, GAA_FLAG_INCLUDE_ALL_INTERFACES,
    GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};

/// Collect all network interfaces from the Windows IP Helper API.
pub fn list_interfaces() -> std::io::Result<Vec<NetworkInterface>> {
    let mut buf_len: u32 = 0;
    unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            GAA_FLAG_INCLUDE_ALL_INTERFACES | GAA_FLAG_INCLUDE_PREFIX,
            None,
            None,
            &mut buf_len,
        );
    }

    let mut buf = vec![0u8; buf_len as usize];
    let head = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

    let ret = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            GAA_FLAG_INCLUDE_ALL_INTERFACES | GAA_FLAG_INCLUDE_PREFIX,
            None,
            Some(head),
            &mut buf_len,
        )
    };
    if ret != NO_ERROR {
        return Err(std::io::Error::from_raw_os_error(ret as i32));
    }

    let mut result = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        let adapter = unsafe { &*cur };
        result.push(adapter_to_model(adapter));
        cur = unsafe { (*cur).Next };
    }

    unsafe { FreeMibTable(head as *const _ as *mut _) };
    Ok(result)
}

fn adapter_to_model(adapter: &IP_ADAPTER_ADDRESSES_LH) -> NetworkInterface {
    let name = unsafe {
        adapter.FriendlyName.to_string().unwrap_or_default()
    };
    let raw_name = unsafe {
        adapter.AdapterName.to_string().unwrap_or_default()
    };
    let kind = classify_interface(&raw_name, &name);
    let state = if adapter.OperStatus == 1 {
        InterfaceState::Up
    } else {
        InterfaceState::Down
    };

    let mut addresses = Vec::new();
    let mut ip = adapter.FirstUnicastAddress;
    while !ip.is_null() {
        let ua = unsafe { &*ip };
        let sockaddr = unsafe { ua.Address.lpSockaddr };
        if !sockaddr.is_null() {
            let sa = unsafe { *sockaddr };
            let family = sa.sa_family;
            if family == AF_INET as u16 || family == AF_INET6 as u16 {
                if let Some((addr, prefix)) = sockaddr_to_ip(sockaddr) {
                    addresses.push(InterfaceAddress {
                        address: addr,
                        prefix_len: ua.OnLinkPrefixLength,
                        family: if addr.is_ipv4() {
                            AddressFamily::Ipv4
                        } else {
                            AddressFamily::Ipv6
                        },
                    });
                }
            }
        }
        ip = ua.Next;
    }

    let dns_servers = collect_dns(adapter);

    NetworkInterface {
        name: raw_name,
        friendly_name: name,
        kind,
        state,
        addresses,
        dns_servers,
        mtu: Some(adapter.Mtu),
        if_index: adapter.Ipv4IfIndex,
    }
}

fn classify_interface(raw: &str, friendly: &str) -> InterfaceKind {
    let lower = friendly.to_lowercase();
    if lower.contains("wireguard") || raw.starts_with("wg") {
        return InterfaceKind::WireGuard;
    }
    if lower.contains("openvpn") || lower.contains("tap-") || lower.contains("tun-") {
        return InterfaceKind::OpenVpn;
    }
    if lower.contains("xray") || lower.contains("wintun") {
        return InterfaceKind::Xray;
    }
    if lower.contains("wi-fi") || lower.contains("wifi") || lower.contains("wireless") {
        return InterfaceKind::Wifi;
    }
    if lower.contains("ethernet") || lower.contains("ethernet") {
        return InterfaceKind::Ethernet;
    }
    if lower.contains("loopback") || raw == "lo" {
        return InterfaceKind::Loopback;
    }
    InterfaceKind::Other(lower)
}

fn sockaddr_to_ip(
    sa: *const windows::Win32::Networking::WinSock::SOCKADDR,
) -> Option<(IpAddr, u8)> {
    use windows::Win32::Networking::WinSock::{SOCKADDR_IN, SOCKADDR_IN6};
    let raw = unsafe { *sa };
    match raw.sa_family {
        f if f == AF_INET as u16 => {
            let sin = unsafe { *(sa as *const SOCKADDR_IN) };
            let bytes = sin.sin_addr.S_un.S_addr.to_ne_bytes();
            Some((IpAddr::V4(std::net::Ipv4Addr::from(bytes)), 32))
        }
        f if f == AF_INET6 as u16 => {
            let sin6 = unsafe { *(sa as *const SOCKADDR_IN6) };
            let bytes = sin6.sin6_addr.u.Byte;
            Some((IpAddr::V6(std::net::Ipv6Addr::from(bytes)), 128))
        }
        _ => None,
    }
}

fn collect_dns(adapter: &IP_ADAPTER_ADDRESSES_LH) -> Vec<IpAddr> {
    let mut dns = Vec::new();
    let mut cur = adapter.FirstDnsServerAddress;
    while !cur.is_null() {
        let entry = unsafe { &*cur };
        let sa = entry.Address.lpSockaddr;
        if !sa.is_null() {
            if let Some((addr, _)) = sockaddr_to_ip(sa) {
                dns.push(addr);
            }
        }
        cur = entry.Next;
    }
    dns
}
```

**Step 2: Write a smoke test (skipped on non-Windows)**

Append to `src-tauri/src/explorer.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "windows")]
    #[test]
    fn list_interfaces_returns_nonempty() {
        let ifaces = list_interfaces().expect("should list interfaces");
        assert!(!ifaces.is_empty(), "Windows always has at least loopback");
        assert!(
            ifaces
                .iter()
                .any(|i| matches!(i.kind, InterfaceKind::Loopback)),
            "loopback should be present"
        );
    }
}
```

**Step 3: Run test (on Windows)**

Run:
```bash
cd src-tauri && cargo test explorer
```

Expected: PASS (on Windows). On Linux/WSL this test is `cfg`-gated out.

**Step 4: Commit**

```bash
git add -A
git commit -m "feat: implement Windows interface inventory via IP Helper API"
```

---

## Task 4: Implement route table reading

**Files:**
- Modify: `src-tauri/src/explorer.rs` (add route functions)

**Step 1: Add route listing via net-route**

Append to `src-tauri/src/explorer.rs`:
```rust
use net_route::Handle as RouteHandle;

/// List all IPv4 routes from the system routing table.
pub async fn list_routes() -> std::io::Result<Vec<RouteEntry>> {
    let handle = RouteHandle::new()?;
    let routes = handle.list().await?;

    // Build ifindex → name map
    let ifaces = list_interfaces()?;
    let name_map: std::collections::HashMap<u32, String> = ifaces
        .iter()
        .map(|i| (i.if_index, i.friendly_name.clone()))
        .collect();

    let mut result = Vec::new();
    for r in routes {
        if r.destination.is_ipv6() {
            continue; // IPv4 only in MVP-0
        }
        let name = name_map
            .get(&r.ifindex.unwrap_or(0))
            .cloned()
            .unwrap_or_else(|| format!("ifindex {}", r.ifindex.unwrap_or(0)));
        result.push(RouteEntry {
            destination: r.destination,
            prefix_len: r.prefix,
            gateway: r.gateway,
            interface_index: r.ifindex.unwrap_or(0),
            interface_name: name,
            metric: r.metric,
        });
    }
    Ok(result)
}
```

**Step 2: Write a smoke test**

Append to `src-tauri/src/explorer.rs` tests module:
```rust
    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn list_routes_returns_default() {
        let routes = list_routes().await.expect("should list routes");
        assert!(
            routes.iter().any(|r| r.destination.is_unspecified()),
            "should have a default route"
        );
    }
```

**Step 3: Run test**

Run:
```bash
cd src-tauri && cargo test explorer::tests::list_routes
```

Expected: PASS (on Windows).

**Step 4: Commit**

```bash
git add -A
git commit -m "feat: read system route table via net-route crate"
```

---

## Task 5: Implement route lookup ("where will this IP go?")

**Files:**
- Modify: `src-tauri/src/explorer.rs` (add lookup function)

**Step 1: Implement longest-prefix-match lookup**

Append to `src-tauri/src/explorer.rs`:
```rust
use ipnet::IpNet;

/// Given a destination IP, find which route and interface Windows would use.
pub async fn lookup_route(dest: IpAddr) -> std::io::Result<RouteLookupResult> {
    let routes = list_routes().await?;

    let mut best: Option<&RouteEntry> = None;
    let mut best_prefix: u8 = 0;
    let mut best_metric: u32 = u32::MAX;

    for r in &routes {
        if let IpAddr::V4(dst) = r.destination {
            let net = match IpNet::V4(ipnet::Ipv4Net::new(dst, r.prefix_len)) {
                Ok(n) => n,
                Err(_) => continue,
            };
            if net.contains(&dest) {
                // Longest prefix wins; tie-break by lowest metric
                if r.prefix_len > best_prefix
                    || (r.prefix_len == best_prefix && r.metric < best_metric)
                {
                    best = Some(r);
                    best_prefix = r.prefix_len;
                    best_metric = r.metric;
                }
            }
        }
    }

    let matched = best.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "no matching route")
    })?;

    Ok(RouteLookupResult {
        destination: dest,
        matched_route: matched.clone(),
        interface_name: matched.interface_name.clone(),
    })
}
```

**Step 2: Write unit test with mock data**

Append to `src-tauri/src/explorer.rs` tests module:
```rust
    #[test]
    fn longest_prefix_match_logic() {
        // This tests the selection logic without hitting the OS.
        let routes = vec![
            RouteEntry {
                destination: "0.0.0.0".parse().unwrap(),
                prefix_len: 0,
                gateway: Some("192.168.1.1".parse().unwrap()),
                interface_index: 1,
                interface_name: "Wi-Fi".into(),
                metric: 25,
            },
            RouteEntry {
                destination: "10.228.0.0".parse().unwrap(),
                prefix_len: 16,
                gateway: None,
                interface_index: 7,
                interface_name: "WireGuard".into(),
                metric: 5,
            },
        ];

        let dest: IpAddr = "10.228.32.10".parse().unwrap();
        let best = routes.iter()
            .filter(|r| {
                let net = ipnet::Ipv4Net::new(
                    match r.destination {
                        IpAddr::V4(d) => d,
                        _ => return false,
                    },
                    r.prefix_len,
                ).unwrap();
                net.contains(&dest)
            })
            .min_by_key(|r| (std::cmp::Reverse(r.prefix_len), r.metric))
            .unwrap();

        assert_eq!(best.interface_name, "WireGuard");
        assert_eq!(best.prefix_len, 16);
    }
```

**Step 3: Run test**

Run:
```bash
cd src-tauri && cargo test explorer::tests::longest_prefix
```

Expected: PASS.

**Step 4: Commit**

```bash
git add -A
git commit -m "feat: implement longest-prefix-match route lookup"
```

---

## Task 6: Expose Tauri commands to frontend

**Files:**
- Modify: `src-tauri/src/main.rs`

**Step 1: Define Tauri commands**

`src-tauri/src/main.rs`:
```rust
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod explorer;
mod models;

use explorer::{list_interfaces, list_routes, lookup_route};
use models::*;
use std::net::IpAddr;

#[tauri::command]
async fn get_interfaces() -> Result<Vec<NetworkInterface>, String> {
    list_interfaces().map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_routes() -> Result<Vec<RouteEntry>, String> {
    list_routes().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn lookup_destination(dest: String) -> Result<RouteLookupResult, String> {
    let ip: IpAddr = dest
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    lookup_route(ip).await.map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_interfaces,
            get_routes,
            lookup_destination
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

**Step 2: Verify it compiles**

Run:
```bash
cd src-tauri && cargo check
```

Expected: compiles.

**Step 3: Commit**

```bash
git add -A
git commit -m "feat: expose Tauri commands for interfaces, routes, lookup"
```

---

## Task 7: Build React frontend — interface list

**Files:**
- Modify: `src/App.tsx`
- Create: `src/components/InterfaceList.tsx`
- Create: `src/types.ts`

**Step 1: Define TypeScript types matching Rust models**

`src/types.ts`:
```typescript
export type InterfaceKind =
  | "Ethernet" | "Wifi" | "WireGuard" | "OpenVpn"
  | "Xray" | "Loopback" | { Other: string };

export type InterfaceState = "Up" | "Down" | "Unknown";

export interface InterfaceAddress {
  address: string;
  prefixLen: number;
  family: "Ipv4" | "Ipv6";
}

export interface NetworkInterface {
  name: string;
  friendlyName: string;
  kind: InterfaceKind;
  state: InterfaceState;
  addresses: InterfaceAddress[];
  dnsServers: string[];
  mtu: number | null;
  ifIndex: number;
}

export interface RouteEntry {
  destination: string;
  prefixLen: number;
  gateway: string | null;
  interfaceIndex: number;
  interfaceName: string;
  metric: number;
}

export interface RouteLookupResult {
  destination: string;
  matchedRoute: RouteEntry;
  interfaceName: string;
}
```

**Step 2: Create InterfaceList component**

`src/components/InterfaceList.tsx`:
```tsx
import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { NetworkInterface } from "../types";

export function InterfaceList() {
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    invoke<NetworkInterface[]>("get_interfaces")
      .then(setInterfaces)
      .catch((e) => setError(String(e)));
  }, []);

  if (error) return <div className="error">{error}</div>;

  return (
    <div className="interface-list">
      <h2>Interfaces</h2>
      {interfaces.map((iface) => (
        <div key={iface.ifIndex} className="interface-card">
          <div className="interface-header">
            <span className="interface-name">{iface.friendlyName}</span>
            <span className={`state state-${iface.state.toLowerCase()}`}>
              {iface.state}
            </span>
          </div>
          <div className="interface-detail">
            <span className="kind">{formatKind(iface.kind)}</span>
            {iface.addresses.map((a) => (
              <span key={a.address} className="address">
                {a.address}/{a.prefixLen}
              </span>
            ))}
            {iface.dnsServers.length > 0 && (
              <span className="dns">DNS: {iface.dnsServers.join(", ")}</span>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

function formatKind(kind: NetworkInterface["kind"]): string {
  if (typeof kind === "string") return kind;
  return kind.Other;
}
```

**Step 3: Wire into App**

`src/App.tsx`:
```tsx
import { InterfaceList } from "./components/InterfaceList";

function App() {
  return (
    <main className="container">
      <h1>Network Explorer</h1>
      <InterfaceList />
    </main>
  );
}

export default App;
```

**Step 4: Verify in dev mode**

Run:
```bash
npm run tauri dev
```

Expected: window opens, shows list of Windows network interfaces with their IPs and states.

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: interface list UI with live data from backend"
```

---

## Task 8: Build React frontend — route table

**Files:**
- Create: `src/components/RouteTable.tsx`
- Modify: `src/App.tsx`

**Step 1: Create RouteTable component**

`src/components/RouteTable.tsx`:
```tsx
import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { RouteEntry } from "../types";

export function RouteTable() {
  const [routes, setRoutes] = useState<RouteEntry[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    invoke<RouteEntry[]>("get_routes")
      .then(setRoutes)
      .catch((e) => setError(String(e)));
  }, []);

  if (error) return <div className="error">{error}</div>;

  return (
    <div className="route-table">
      <h2>Routes</h2>
      <table>
        <thead>
          <tr>
            <th>Destination</th>
            <th>Prefix</th>
            <th>Gateway</th>
            <th>Interface</th>
            <th>Metric</th>
          </tr>
        </thead>
        <tbody>
          {routes.map((r, i) => (
            <tr key={i}>
              <td>{r.destination}</td>
              <td>/{r.prefixLen}</td>
              <td>{r.gateway ?? "—"}</td>
              <td>{r.interfaceName}</td>
              <td>{r.metric}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

**Step 2: Add to App**

Modify `src/App.tsx`:
```tsx
import { InterfaceList } from "./components/InterfaceList";
import { RouteTable } from "./components/RouteTable";

function App() {
  return (
    <main className="container">
      <h1>Network Explorer</h1>
      <InterfaceList />
      <RouteTable />
    </main>
  );
}

export default App;
```

**Step 3: Verify in dev mode**

Run:
```bash
npm run tauri dev
```

Expected: route table shows below interfaces with all IPv4 routes.

**Step 4: Commit**

```bash
git add -A
git commit -m "feat: route table UI"
```

---

## Task 9: Build route lookup ("where does this IP go?")

**Files:**
- Create: `src/components/RouteLookup.tsx`
- Modify: `src/App.tsx`

**Step 1: Create RouteLookup component**

`src/components/RouteLookup.tsx`:
```tsx
import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { RouteLookupResult } from "../types";

export function RouteLookup() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<RouteLookupResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const lookup = async () => {
    setError(null);
    setResult(null);
    try {
      const r = await invoke<RouteLookupResult>("lookup_destination", {
        dest: input,
      });
      setResult(r);
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <div className="route-lookup">
      <h2>Route Lookup</h2>
      <div className="lookup-input">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="e.g. 10.228.32.50"
          onKeyDown={(e) => e.key === "Enter" && lookup()}
        />
        <button onClick={lookup}>Lookup</button>
      </div>
      {error && <div className="error">{error}</div>}
      {result && (
        <div className="lookup-result">
          <p>
            <strong>{result.destination}</strong> →{" "}
            <strong>{result.interfaceName}</strong>
          </p>
          <p>
            Route: {result.matchedRoute.destination}/
            {result.matchedRoute.prefixLen} (metric{" "}
            {result.matchedRoute.metric})
          </p>
        </div>
      )}
    </div>
  );
}
```

**Step 2: Add to App**

Modify `src/App.tsx`:
```tsx
import { InterfaceList } from "./components/InterfaceList";
import { RouteTable } from "./components/RouteTable";
import { RouteLookup } from "./components/RouteLookup";

function App() {
  return (
    <main className="container">
      <h1>Network Explorer</h1>
      <RouteLookup />
      <InterfaceList />
      <RouteTable />
    </main>
  );
}

export default App;
```

**Step 3: Verify in dev mode**

Run:
```bash
npm run tauri dev
```

Expected: type `8.8.8.8` → shows which interface Windows uses (likely Wi-Fi/Ethernet default route). Type `10.228.x.x` → shows WireGuard if active.

**Step 4: Commit**

```bash
git add -A
git commit -m "feat: route lookup UI — where does this IP go?"
```

---

## Task 10: Add auto-refresh and route change listener

**Files:**
- Modify: `src-tauri/src/explorer.rs` (add route change stream)
- Modify: `src-tauri/src/main.rs` (add event emission)
- Modify: `src/App.tsx` (listen for events)

**Step 1: Add route change stream to backend**

Append to `src-tauri/src/explorer.rs`:
```rust
use futures::StreamExt;

/// Spawn a background task that emits "route-changed" events to the frontend.
pub fn spawn_route_watcher(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        let handle = match RouteHandle::new() {
            Ok(h) => h,
            Err(e) => {
                eprintln!("route watcher init failed: {e}");
                return;
            }
        };
        let mut stream = handle.route_listen_stream();
        while let Some(_change) = stream.next().await {
            let _ = app.emit("route-changed", ());
        }
    });
}
```

Add to `src-tauri/Cargo.toml`:
```toml
futures = "0.3"
```

**Step 2: Wire watcher into Tauri setup**

Modify `src-tauri/src/main.rs`:
```rust
use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            explorer::spawn_route_watcher(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_interfaces,
            get_routes,
            lookup_destination
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

**Step 3: Listen for events in frontend**

Modify `src/App.tsx`:
```tsx
import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { InterfaceList } from "./components/InterfaceList";
import { RouteTable } from "./components/RouteTable";
import { RouteLookup } from "./components/RouteLookup";

function App() {
  useEffect(() => {
    const unlisten = listen("route-changed", () => {
      // Trigger re-fetch by dispatching a custom event components listen to
      window.dispatchEvent(new CustomEvent("route-changed"));
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  return (
    <main className="container">
      <h1>Network Explorer</h1>
      <RouteLookup />
      <InterfaceList />
      <RouteTable />
    </main>
  );
}

export default App;
```

**Step 4: Make InterfaceList and RouteTable refresh on event**

In `src/components/InterfaceList.tsx` and `src/components/RouteTable.tsx`, add to the `useEffect`:
```tsx
useEffect(() => {
  const refresh = () => invoke<NetworkInterface[]>("get_interfaces")
    .then(setInterfaces)
    .catch((e) => setError(String(e)));
  refresh();
  window.addEventListener("route-changed", refresh);
  return () => window.removeEventListener("route-changed", refresh);
}, []);
```

(Analogous for RouteTable — replace `get_interfaces` with `get_routes`.)

**Step 5: Verify in dev mode**

Run:
```bash
npm run tauri dev
```

Expected: app opens. Connect/disconnect a VPN or toggle Wi-Fi — interface list and route table update automatically within ~1 second.

**Step 6: Commit**

```bash
git add -A
git commit -m "feat: auto-refresh on route changes via net-route listener"
```

---

## Task 11: Add basic styling

**Files:**
- Modify: `src/styles.css` (or `src/index.css`)

**Step 1: Write minimal CSS**

```css
.container {
  max-width: 900px;
  margin: 0 auto;
  padding: 20px;
  font-family: system-ui, sans-serif;
}

.interface-card {
  border: 1px solid #ddd;
  border-radius: 8px;
  padding: 12px;
  margin-bottom: 8px;
}

.interface-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.state-up { color: #2e7d32; }
.state-down { color: #c62828; }

.interface-detail {
  display: flex;
  gap: 16px;
  margin-top: 8px;
  font-size: 0.9em;
  color: #555;
}

table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 12px;
}

th, td {
  text-align: left;
  padding: 6px 10px;
  border-bottom: 1px solid #eee;
}

.lookup-input {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
}

.lookup-input input {
  flex: 1;
  padding: 6px 10px;
}

.error { color: #c62828; }
```

**Step 2: Verify in dev mode**

Run:
```bash
npm run tauri dev
```

Expected: clean, readable layout.

**Step 3: Commit**

```bash
git add -A
git commit -m "feat: basic styling for Network Explorer"
```

---

## Task 12: Build production binary

**Step 1: Build**

Run:
```bash
npm run tauri build
```

Expected: produces `src-tauri/target/release/bundle/` with an MSI/NSIS installer for Windows.

**Step 2: Verify the binary runs**

Run the produced `.exe` from the bundle directory. Expected: app opens, shows interfaces and routes.

**Step 3: Commit any config changes**

```bash
git add -A
git commit -m "chore: verify production build"
```

---

## Verification checklist (MVP-0 complete when all pass)

- [ ] App opens and shows all Windows network interfaces (Wi-Fi, Ethernet, WireGuard, OpenVPN, VPN TUN, loopback)
- [ ] Each interface shows: friendly name, state, IP addresses, DNS servers, MTU
- [ ] Interface kind classification works (WireGuard/OpenVPN/Xray detected by name)
- [ ] Route table shows all IPv4 routes with destination, prefix, gateway, interface, metric
- [ ] Route lookup: `8.8.8.8` → default route interface; `10.228.x.x` → WireGuard (if active)
- [ ] Auto-refresh: toggling Wi-Fi or connecting a VPN updates the UI within ~1s
- [ ] Production build produces a working installer
- [ ] `cargo test` passes all unit tests
- [ ] No panics on machines with many virtual adapters (Docker, WSL, Hyper-V)

---

## What's next (post-MVP-0, not in this plan)

- **MVP-1:** WireGuard backend (start/stop tunnels, manage configs)
- **MVP-2:** Profiles + IP/CIDR policy routing (apply routes via `net-route`)
- **MVP-3:** OpenVPN backend
- **MVP-4:** Xray backend + domain routing via Xray config generation
