import type {
  AlwaysOnListResult, BackendAvailability, ConditionalRuleEntry, ConditionalRouteRule,
  ConfigAnalysis, NetworkInterface, Profile, ProfileInspection, RouteEntry, RouteMap,
  TunnelStatus, VpnAuthMode,
} from "../types.ts";

// This module intentionally has no I/O imports, fetch, or process calls.
// It models UI transitions only; Rust tests verify actual backend behavior.
function profile(id: string, name: string, backend: Profile["backend"], cidr?: string): Profile {
  return {
    id, name, backend, configPath: backend === "none" ? "" : `/sandbox/${id}.${backend === "xray" ? "json" : backend === "openVpn" ? "ovpn" : "conf"}`,
    interfaceName: backend === "none" ? "qa-ethernet" : `qa-${id}`,
    routes: cidr ? [{ destination: cidr, metric: 5, via: null }] : [],
    autoConnect: false, domainPolicies: [], privateLanDirect: false,
    xraySocksPort: backend === "xray" ? 10808 : null,
    xrayHttpPort: backend === "xray" ? 10809 : null,
    useSystemProxy: false, proxyBypass: [], subscription: null,
    xrayMode: "socks", xrayTunInterface: null, xrayTunIp: null,
  };
}

function iface(name: string, index: number, physical: boolean, state: NetworkInterface["state"], kind: NetworkInterface["kind"] = "ethernet"): NetworkInterface {
  return {
    name, friendlyName: name, ifIndex: index, physical, state,
    kind, category: physical ? "physical" : "vpn",
    addresses: [{ address: physical ? "192.0.2.2" : kind === "openVpn" ? "10.88.0.2" : "10.77.0.2", prefixLen: 24, family: "Ipv4" }],
    dnsServers: ["192.0.2.53"], dnsSuffix: null, mtu: 1500, mac: null,
    gateway: physical ? "192.0.2.1" : null, ipv6Gateway: null,
    rxBytes: 1048576, txBytes: 524288, linkSpeedMbps: 1000,
    description: "Synthetic interface; no OS adapter", ifType: 6, tunnelType: null,
  };
}

export class SandboxBackend {
  private profiles: Profile[] = [
    profile("wg", "QA WireGuard", "wireGuard", "10.77.0.0/24"),
    profile("ovpn", "QA OpenVPN", "openVpn", "10.88.0.0/24"),
    profile("xray", "AcmeVPN - ⚡ Нидерланды", "xray"),
    profile("static", "QA Static routes", "none", "203.0.113.0/24"),
  ];
  private running = new Set<string>();
  // Foreign tunnels raised outside the app (wg-quick, another VPN app).
  private externalIfaces = [
    iface("wg-home", 90, false, "up", "wireGuard"),
    iface("tun-happ", 91, false, "up", "xray"),
  ];
  private enrollment: AlwaysOnListResult = { profiles: [], paused: false, supportedKinds: ["wireGuard", "staticRoutes"] };
  private loginAutostart = false;
  private authMode: VpnAuthMode = "fullTunnelOnly";
  private recovered = false;
  private endpoints = [
    "AcmeVPN - ⚡ Нидерланды",
    "AcmeVPN - 🇩🇪 Германия",
    "AcmeVPN - 🇫🇮 Финляндия",
    "AcmeVPN - 🇯🇵 Япония",
    "AcmeVPN - 🇺🇸 США",
    "AcmeVPN - 🇧🇷 Бразилия",
    "AcmeVPN - 🇸🇬 Сингапур",
    "AcmeVPN - 🇵🇱 Польша",
  ];
  private backendPaths = new Map<string, string>();
  private xrayManaged = false;
  private condRules: ConditionalRuleEntry[] = [
    {
      rule: {
        id: "cond-lan",
        name: "QA LAN bypass",
        enabled: true,
        condition: { kind: "interfaceAddressIn", prefix: "192.168.0.0/16" },
        routes: [{ destination: "10.228.32.0/21", metric: 5, via: null }],
      },
      status: { state: "active", matchedInterface: "qa-ethernet", appliedRoutes: 1, detail: null },
    },
  ];

  constructor() {
    // QA WireGuard wants the same interface the external wg-home tunnel holds:
    // demonstrates the "interface occupied" conflict until it is connected.
    this.profiles[0].interfaceName = "wg-home";
    this.profiles[2].subscription = {
      url: "", hwid: "", endpointCount: this.endpoints.length, activeIndex: 0,
      refreshIntervalMinutes: null, lastRefreshAtUnix: null, lastRefreshError: null,
      providerTitle: "AcmeVPN",
      announce: "Maintenance window on Saturday 03:00–05:00 UTC.\nNL endpoints may flap briefly.",
      supportUrl: "https://support.example.invalid/chat",
      webPageUrl: "https://cabinet.example.invalid/dashboard",
      updateIntervalHours: 12,
      skippedProtocols: ["trojan", "ss"],
      userInfo: { uploadBytes: 1048576, downloadBytes: 2097152, totalBytes: 1073741824, expiresAtUnix: Math.floor(Date.now() / 1000) + 5 * 86400 },
    };
  }

  private find(id: unknown): Profile {
    const found = this.profiles.find((p) => p.id === id);
    if (!found) throw new Error("Sandbox profile not found");
    return found;
  }

  private stopped(p: Profile) {
    if (this.running.has(p.id)) throw new Error("Disconnect the profile before editing or deleting");
  }

  private allocateProxyPorts(p: Profile) {
    const used = new Set(this.profiles.filter((other) => other.id !== p.id).flatMap((other) => [other.xraySocksPort, other.xrayHttpPort]));
    let port = 10808;
    while (used.has(port) || used.has(port + 1)) port += 2;
    p.xraySocksPort = port;
    p.xrayHttpPort = port + 1;
  }

  private statuses(): TunnelStatus[] {
    return this.profiles.map((p) => ({ profileId: p.id, state: this.running.has(p.id) ? "running" : "stopped", message: null }));
  }

  private interfaces(): NetworkInterface[] {
    // Managed tunnel interfaces exist only while the tunnel runs — same as on
    // a real system. A foreign device holding the same name stays listed and
    // surfaces as the external-tunnel conflict in Profiles.
    const managed = this.profiles.filter((p) => p.backend !== "none" && !(p.backend === "xray" && p.xrayMode === "socks") && this.running.has(p.id)).map((p, i) => iface(p.interfaceName, i + 2, false, "up", p.backend === "none" ? "ethernet" : p.backend));
    const runningNames = new Set(this.profiles.filter((p) => this.running.has(p.id)).map((p) => p.interfaceName));
    return [iface("qa-ethernet", 1, true, "up"), ...managed, ...this.externalIfaces.filter((e) => !runningNames.has(e.name))];
  }

  private routes(): RouteEntry[] {
    // Foreign tunnels contribute real-looking overlapping routes while up —
    // /30 containing /32s and an IPv6 link-local, like a live kernel table.
    const external = this.externalIfaces.filter((e) => e.state === "up").flatMap((e) => {
      if (e.name === "tun-happ") return [
        { destination: "0.0.0.0", prefixLen: 0, gateway: null, interfaceIndex: e.ifIndex, interfaceName: e.name, metric: 1 },
        { destination: "172.19.0.0", prefixLen: 30, gateway: null, interfaceIndex: e.ifIndex, interfaceName: e.name, metric: 0 },
        { destination: "172.19.0.1", prefixLen: 32, gateway: null, interfaceIndex: e.ifIndex, interfaceName: e.name, metric: 0 },
        { destination: "172.19.0.3", prefixLen: 32, gateway: null, interfaceIndex: e.ifIndex, interfaceName: e.name, metric: 0 },
        { destination: "fe80::", prefixLen: 64, gateway: null, interfaceIndex: e.ifIndex, interfaceName: e.name, metric: 256 },
      ];
      if (e.name === "wg-home") return [
        { destination: "0.0.0.0", prefixLen: 0, gateway: null, interfaceIndex: e.ifIndex, interfaceName: e.name, metric: 5 },
      ];
      return [];
    });
    return [
      { destination: "0.0.0.0", prefixLen: 0, gateway: "192.0.2.1", interfaceIndex: 1, interfaceName: "qa-ethernet", metric: 100 },
      ...external,
      ...this.profiles.filter((p) => this.running.has(p.id)).flatMap((p) => p.routes.map((r) => {
        const [destination, prefix] = r.destination.split("/");
        return { destination, prefixLen: Number(prefix), gateway: r.via ?? null, interfaceIndex: this.interfaces().find((i) => i.name === p.interfaceName)?.ifIndex ?? 1, interfaceName: p.interfaceName, metric: r.metric };
      })),
    ];
  }

  private inspect(p: Profile): ProfileInspection {
    const analysis: ConfigAnalysis = {
      profileId: p.id, osRoutes: p.routes.map((r) => ({ destination: r.destination, source: "profile" })),
      internalRoutes: [], listeners: p.backend === "xray" ? [{ address: "127.0.0.1", port: p.xraySocksPort ?? 10808, protocol: "socks" }] : [],
      endpoints: p.backend === "none" ? [] : [{ address: "vpn.example.invalid", port: 443, protocol: p.backend }],
      domainPatterns: p.domainPolicies.flatMap((d) => d.domains), warnings: ["Synthetic configuration: no network traffic is sent."], routeKnowledgeComplete: true,
      peers: p.backend === "wireGuard" ? [{
        endpoint: { address: "vpn.example.invalid", port: 51820, protocol: "wireGuard" },
        routes: p.routes.map((r) => ({ destination: r.destination, source: "WireGuard AllowedIPs" })),
      }] : [],
      interfaceDetails: p.backend === "wireGuard" ? [{ field: "address", value: "10.203.0.2/32" }] : [],
    };
    return { analysis, conflicts: [], managedConfig: true };
  }

  private routeMap(includeInactive: unknown): RouteMap {
    return {
      predicted: this.profiles.filter((p) => includeInactive || this.running.has(p.id)).flatMap((p) => p.routes.map((r) => ({ destination: r.destination, ownerProfileId: p.id, ownerName: p.name, source: "profile", interfaceName: p.interfaceName, metric: r.metric, active: this.running.has(p.id) }))),
      effective: this.routes(), diffs: [], warnings: ["Sandbox route table; the host routing table is unchanged."], pushedRoutes: [],
    };
  }

  invoke(command: string, args: Record<string, unknown> = {}): unknown {
    // Clone responses to prevent UI edits from mutating backend state by reference.
    const result = this.dispatch(command, args);
    // Slow synthetic commands (delay probes) resolve later; clone on arrival.
    if (result instanceof Promise) return result.then((value) => structuredClone(value));
    return structuredClone(result);
  }

  private dispatch(command: string, args: Record<string, unknown>): unknown {
    switch (command) {
      case "get_platform_capabilities": return { os: "linux", systemProxy: false, wireguardStandardImport: false, managedXrayInstall: true, elevationRelaunch: false, appUpdates: false, executableExtensions: [] };
      case "get_profiles": return this.profiles;
      case "get_interfaces": return this.interfaces();
      case "get_routes": return this.routes();
      case "get_tunnel_statuses": return this.statuses();
      case "daemon_status": return { state: "ready", message: "Simulated daemon: host network is never modified." };
      case "is_elevated": return false;
      case "get_auto_connect_result": return null;
      case "get_always_on_profiles": return this.enrollment;
      case "set_always_on_profile": {
        const p = this.find(args.id);
        if (!["wireGuard", "none"].includes(p.backend)) throw new Error("This backend does not support always-on");
        this.enrollment.profiles = this.enrollment.profiles.filter((e) => e.profileId !== p.id);
        this.enrollment.profiles.push({ kind: p.backend === "none" ? "staticRoutes" : "wireGuard", profileId: p.id, enabled: true });
        return { stored: true, active: this.running.has(p.id) };
      }
      case "remove_always_on_profile": this.enrollment.profiles = this.enrollment.profiles.filter((e) => e.profileId !== args.profileId || e.kind !== args.kind); return { removed: true };
      case "resume_always_on": this.enrollment.paused = false; return { resumed: true };
      case "get_login_autostart": return this.loginAutostart;
      case "set_login_autostart": this.loginAutostart = Boolean(args.enabled); return this.loginAutostart;
      case "get_vpn_auth_mode": return this.authMode;
      case "set_vpn_auth_mode": this.authMode = args.mode as VpnAuthMode; return this.authMode;
      case "get_recovery_report": return { issues: this.recovered ? [] : [{ kind: "ownedRoutes", profileId: "static", message: "Synthetic stale route from a previous sandbox session." }], requiresElevation: false };
      case "cleanup_recovery": this.recovered = true; return { issues: [], requiresElevation: false };
      case "connect_profile":
      case "connect_openvpn_with_credentials": {
        const p = this.find(args.id);
        if (this.running.has(p.id)) throw new Error("Profile is already running");
        if (p.backend === "none" && !p.routes.length) throw new Error("Static-routes profile has no routes");
        if (p.backend === "openVpn" && command === "connect_profile") throw "OpenVPN credentials required";
        this.running.add(p.id);
        return this.statuses().find((s) => s.profileId === p.id);
      }
      case "disconnect_profile": this.running.delete(this.find(args.id).id); return this.statuses().find((s) => s.profileId === args.id);
      case "save_profile":
      case "save_vless_profile":
      case "save_wireguard_profile": {
        const p = structuredClone(args.profile) as Profile;
        if (!p.id || !p.name?.trim()) throw new Error("Profile name is required");
        const existing = this.profiles.find((e) => e.id === p.id);
        if (existing) this.stopped(existing);
        if (command === "save_vless_profile") { p.configPath = `/sandbox/${p.id}.json`; this.allocateProxyPorts(p); }
        if (command === "save_wireguard_profile") p.configPath = `/sandbox/${p.id}.conf`;
        this.profiles = [...this.profiles.filter((e) => e.id !== p.id), p];
        return this.profiles;
      }
      case "delete_profile": this.stopped(this.find(args.id)); this.profiles = this.profiles.filter((p) => p.id !== args.id); return this.profiles;
      case "inspect_profiles": return this.profiles.map((p) => this.inspect(p));
      case "inspect_profile_by_id": return this.inspect(this.find(args.id));
      case "diagnose_profile": {
        const p = this.find(args.id);
        return { profileId: p.id, status: this.statuses().find((s) => s.profileId === p.id), inspection: this.inspect(p), checks: [{ name: "Sandbox isolation", level: "healthy", message: "All actions run in memory. No VPN process is started." }] };
      }
      case "get_route_map": return this.routeMap(args.includeInactive);
      case "lookup_destination": {
        const dest = String(args.dest);
        const ip = dest.split(".").map(Number);
        if (ip.length !== 4 || ip.some((b) => !Number.isInteger(b) || b < 0 || b > 255)) throw new Error("Sandbox lookup supports IPv4 literals only");
        const bits = ip.reduce((n, b) => (n << 8) | b, 0) >>> 0;
        const matched = this.routes().filter((r) => {
          const network = r.destination.split(".").map(Number).reduce((n, b) => (n << 8) | b, 0) >>> 0;
          const mask = r.prefixLen === 0 ? 0 : (0xffffffff << (32 - r.prefixLen)) >>> 0;
          return ((network & mask) >>> 0) === ((bits & mask) >>> 0);
        }).sort((a, b) => b.prefixLen - a.prefixLen || a.metric - b.metric)[0];
        return { destination: dest, matchedRoute: matched, interfaceName: matched.interfaceName, table: "sandbox" };
      }
      case "set_interface_state": {
        // External fixtures may be flipped to demo the bring-down flow; all
        // other interface mutations stay read-only.
        const ext = this.externalIfaces.find((i) => i.name === args.name);
        if (!ext || typeof args.up !== "boolean") throw new Error("Interface mutations are disabled in sandbox");
        ext.state = args.up ? "up" : "down";
        return null;
      }
      case "stop_external_tunnel": {
        // Mirrors the daemon: a foreign WireGuard netdev is deleted, a
        // foreign TUN is only admin-downed (its owner still holds it).
        const ext = this.externalIfaces.find((i) => i.name === args.name);
        if (!ext) throw new Error("Sandbox interface not found");
        if (ext.kind === "wireGuard") {
          this.externalIfaces = this.externalIfaces.filter((i) => i.name !== args.name);
        } else {
          ext.state = "down";
        }
        return null;
      }
      case "get_subscription_endpoints": {
        const p = this.find(args.profileId);
        return this.endpoints.map((name, i) => ({
          name,
          active: p.subscription?.activeIndex === i,
          protocol: i === 0 ? "VLESS · Reality" : i === 1 ? "VLESS · TLS" : "Hysteria2",
        }));
      }
      case "switch_subscription_endpoint": {
        const p = this.find(args.profileId); this.stopped(p);
        if (!p.subscription || !Number.isInteger(args.endpointIndex) || Number(args.endpointIndex) < 0 || Number(args.endpointIndex) >= this.endpoints.length) throw new Error("Invalid endpoint index");
        p.subscription.activeIndex = Number(args.endpointIndex); return this.profiles;
      }
      case "set_subscription_refresh_interval": {
        const p = this.find(args.profileId);
        if (!p.subscription) throw new Error("Not a subscription profile");
        p.subscription.refreshIntervalMinutes = args.refreshIntervalMinutes as number | null; return this.profiles;
      }
      case "refresh_subscription": {
        const p = this.find(args.id); this.stopped(p);
        if (!p.subscription) throw new Error("Not a subscription profile");
        p.subscription.lastRefreshAtUnix = Math.floor(Date.now() / 1000);
        return { endpointCount: this.endpoints.length, activeIndex: p.subscription.activeIndex, skippedCount: 0, fallbackUsed: false, cleanupFailed: false };
      }
      case "measure_subscription_endpoint_delay": {
        // Deterministic synthetic latency with a real wait, so the browser
        // preview shows probes landing one by one; every fourth one times out.
        const index = Number(args.endpointIndex);
        const delayMs = 60 + ((index * 263) % 900);
        const unreachable = index % 4 === 3;
        return new Promise((resolve) =>
          setTimeout(
            () => resolve(unreachable ? { delayMs: null, error: "delay probe timed out" } : { delayMs, error: null }),
            unreachable ? 2500 : delayMs * 2,
          ));
      }
      case "import_share_link": {
        const link = String(args.link ?? "").trim();
        const invalid = () => new Error("Invalid or unsupported share link. Use vless://, hysteria2:// or hy2://.");
        let url: URL;
        try { url = new URL(link); } catch { throw invalid(); }
        if (link.length > 65536 || /[\r\n]/.test(link) || !["vless:", "hysteria2:", "hy2:"].includes(url.protocol) || !url.username || !url.hostname || url.port === "0") throw invalid();
        let name = String(args.name ?? "").trim();
        if (!name) {
          try { name = decodeURIComponent(url.hash.slice(1)).trim(); } catch { name = ""; }
        }
        const p = profile(`link-${this.profiles.length}`, name || "Imported connection", "xray");
        this.allocateProxyPorts(p);
        p.configPath = `/sandbox/${p.id}.json`;
        this.profiles.push(p);
        return { profiles: this.profiles, errors: [] };
      }
      case "import_subscription": {
        const p = profile(`subscription-${this.profiles.length}`, "QA Imported subscription", "xray");
        this.allocateProxyPorts(p);
        p.subscription = structuredClone(this.profiles.find((p) => p.subscription)?.subscription ?? null);
        this.profiles.push(p); return { profiles: [p], errors: [] };
      }
      case "import_configs_batch": {
        const imported = [profile(`import-${this.profiles.length}`, "QA Imported WireGuard", "wireGuard", "10.99.0.0/24")];
        this.profiles.push(...imported); return { profiles: imported, errors: [] };
      }
      case "get_backend_availability": return (["wireGuard", "openVpn", "xray"] as const).map((backend): BackendAvailability => {
        if (backend === "xray" && this.xrayManaged) {
          return { backend, available: true, path: "/usr/lib/network-orchestrator/xray/v26.3.27/xray", source: "managed", version: "v26.3.27", message: "Simulated managed package; nothing is launched." };
        }
        if (backend === "xray") {
          return { backend, available: false, path: this.backendPaths.get(backend) ?? null, source: this.backendPaths.has(backend) ? "configured" : null, version: null, message: "Xray unavailable; TUN requires verified package Xray and network daemon." };
        }
        return { backend, available: true, path: this.backendPaths.get(backend) ?? `/sandbox/bin/${backend}`, source: this.backendPaths.has(backend) ? "configured" : "autoDetected", version: null, message: "Simulated executable; nothing is launched." };
      });
      case "get_managed_xray_offer": return { version: "v26.3.27", sourceUrl: "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip", sha256: "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae", maxDownloadBytes: 64 * 1024 * 1024 };
      case "install_managed_xray": this.xrayManaged = true; return "/usr/lib/network-orchestrator/xray/v26.3.27/xray";
      case "remove_managed_xray": this.xrayManaged = false; this.backendPaths.delete("xray"); return null;
      case "cancel_managed_xray_install": return null;
      case "set_backend_executable": this.backendPaths.set(String(args.backend), String(args.path)); return null;
      case "reset_backend_executable": this.backendPaths.delete(String(args.backend)); return null;
      case "plugin:app|version": return "Sandbox";
      case "plugin:dialog|open": return (args.options as { multiple?: boolean })?.multiple ? ["/sandbox/sample.conf"] : "/sandbox/sample.conf";
      case "plugin:dialog|message": {
        const buttons = args.buttons as string | { OkCancelCustom?: string[]; OkCustom?: string; YesNoCancelCustom?: string[] } | undefined;
        return buttons === "YesNo" ? "Yes" : typeof buttons === "object"
          ? buttons.OkCancelCustom?.[0] ?? buttons.OkCustom ?? buttons.YesNoCancelCustom?.[0] ?? "Ok"
          : "Ok";
      }
      case "list_conditional_rules": return { rules: this.condRules };
      case "put_conditional_rule": {
        const rule = args.rule as ConditionalRouteRule;
        const idx = this.condRules.findIndex((e) => e.rule.id === rule.id);
        const entry: ConditionalRuleEntry = {
          rule,
          status: rule.enabled
            ? { state: "active", matchedInterface: "qa-ethernet", appliedRoutes: rule.routes.length, detail: null }
            : { state: "disabled", matchedInterface: null, appliedRoutes: 0, detail: null },
        };
        if (idx >= 0) this.condRules[idx] = entry; else this.condRules.push(entry);
        return { stored: true, status: entry.status };
      }
      case "remove_conditional_rule": {
        const idx = this.condRules.findIndex((e) => e.rule.id === args.ruleId);
        if (idx >= 0) this.condRules.splice(idx, 1);
        return { removed: idx >= 0 };
      }
      case "plugin:dialog|ask":
      case "plugin:dialog|confirm": return true;
      default: throw new Error(`Command is disabled in sandbox: ${command}`);
    }
  }
}
