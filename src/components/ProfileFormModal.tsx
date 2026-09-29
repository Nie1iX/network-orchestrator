import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import Modal from "./Modal";
import {
  AnalyzedRoute,
  DomainPolicy,
  DomainRouteTarget,
  NetworkInterface,
  PolicyRoute,
  Profile,
  ProfileInspection,
  TunnelBackend,
  WireGuardFields,
  XrayMode,
} from "../types";
import { usePlatformCapabilities } from "../platform";
import { ChevronIcon } from "../icons";

const BACKEND_LABELS: Record<TunnelBackend, string> = {
  none: "Static routes",
  wireGuard: "WireGuard",
  openVpn: "OpenVPN",
  xray: "Xray",
};

const BACKEND_EXTENSIONS: Record<TunnelBackend, string[]> = {
  none: [],
  wireGuard: ["conf", "dpapi"],
  openVpn: ["ovpn", "conf"],
  xray: ["json"],
};

const PROXY_BYPASS_PLACEHOLDER = "10.*, *.corp.local";

const EMPTY_WG_FIELDS: WireGuardFields = {
  privateKey: "",
  address: "",
  dns: "",
  peerPublicKey: "",
  peerEndpoint: "",
  allowedIps: "0.0.0.0/0",
  presharedKey: "",
  persistentKeepalive: 25,
};

function newProfileId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function clampMetric(value: number): number {
  if (Number.isNaN(value)) return 0;
  return Math.max(0, Math.min(9999, Math.trunc(value)));
}

function parseBypass(text: string): string[] {
  return text
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

export interface ProfileFormState {
  id: string;
  name: string;
  backend: TunnelBackend;
  configPath: string;
  interfaceName: string;
  routes: PolicyRoute[];
  autoConnect: boolean;
  xraySource: "json" | "vless";
  vlessUrl: string;
  wgSource: "file" | "fields";
  wgFields: WireGuardFields;
  xraySocksPort: number | null;
  xrayHttpPort: number | null;
  /** One selector per line per target; `#` lines are comments. */
  rulesProxy: string;
  rulesDirect: string;
  rulesBlock: string;
  privateLanDirect: boolean;
  useSystemProxy: boolean;
  proxyBypass: string;
  isNew: boolean;
  subscription: import("../types").SubscriptionMeta | null;
  xrayMode: XrayMode;
  xrayTunInterface: string;
  xrayTunIp: string;
  xrayGeoipUrl: string;
  xrayGeositeUrl: string;
}

/** Group a profile's policies into per-target text (comments preserved). */
function policiesToText(policies: DomainPolicy[], target: DomainRouteTarget): string {
  return policies
    .filter((p) => p.target === target)
    .flatMap((p) => p.domains)
    .join("\n");
}

/** Build policies from textarea content; ordering matches Happ's
 * block → proxy → direct precedence (first match wins in xray). */
function textToPolicies(
  rulesBlock: string,
  rulesProxy: string,
  rulesDirect: string,
): DomainPolicy[] {
  const parse = (text: string) =>
    text
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
  const policies: DomainPolicy[] = [];
  for (const [text, target] of [
    [rulesBlock, "block"],
    [rulesProxy, "proxy"],
    [rulesDirect, "direct"],
  ] as const) {
    const domains = parse(text);
    if (domains.length > 0) policies.push({ domains, target });
  }
  return policies;
}

export function newFormState(
  backend: TunnelBackend = "wireGuard",
  os?: string,
): ProfileFormState {
  return {
    id: newProfileId(),
    name: "",
    backend,
    configPath: "",
    interfaceName: "",
    routes: [],
    autoConnect: false,
    xraySource: "json",
    vlessUrl: "",
    wgSource: "fields",
    wgFields: { ...EMPTY_WG_FIELDS },
    xraySocksPort: null,
    xrayHttpPort: null,
    rulesProxy: "",
    rulesDirect: "",
    rulesBlock: "",
    privateLanDirect: false,
    useSystemProxy: false,
    proxyBypass: "",
    isNew: true,
    subscription: null,
    // On Linux a SOCKS listener captures no system traffic, so TUN is the
    // mode that actually tunnels; the backend import defaults match this.
    xrayMode: os === "linux" ? "tun" : "socks",
    xrayTunInterface: "xray-tun",
    xrayTunIp: "172.19.0.1/30",
    xrayGeoipUrl: "",
    xrayGeositeUrl: "",
  };
}

export function editFormState(profile: Profile): ProfileFormState {
  return {
    id: profile.id,
    name: profile.name,
    backend: profile.backend,
    configPath: profile.configPath,
    interfaceName: profile.interfaceName,
    routes: profile.routes.map((r) => ({ ...r })),
    autoConnect: profile.autoConnect,
    xraySource: "json",
    vlessUrl: "",
    wgSource: "file",
    wgFields: { ...EMPTY_WG_FIELDS },
    xraySocksPort: profile.xraySocksPort,
    xrayHttpPort: profile.xrayHttpPort,
    rulesProxy: policiesToText(profile.domainPolicies, "proxy"),
    rulesDirect: policiesToText(profile.domainPolicies, "direct"),
    rulesBlock: policiesToText(profile.domainPolicies, "block"),
    privateLanDirect: profile.privateLanDirect,
    useSystemProxy: profile.useSystemProxy,
    proxyBypass: profile.proxyBypass.join(", "),
    isNew: false,
    subscription: profile.subscription,
    xrayMode: profile.xrayMode ?? "socks",
    xrayTunInterface: profile.xrayTunInterface ?? "xray-tun",
    xrayTunIp: profile.xrayTunIp ?? "172.19.0.1/30",
    xrayGeoipUrl: profile.xrayGeoipUrl ?? "",
    xrayGeositeUrl: profile.xrayGeositeUrl ?? "",
  };
}

interface ProfileFormModalProps {
  open: boolean;
  editing: ProfileFormState | null;
  interfaces: NetworkInterface[];
  onClose: () => void;
  onSaved: (profiles: Profile[], inspection: ProfileInspection | null) => void;
  onError: (message: string) => void;
}

type FormTab = "general" | "connection" | "routing";

export default function ProfileFormModal({
  open,
  editing,
  interfaces,
  onClose,
  onSaved,
  onError,
}: ProfileFormModalProps) {
  const [form, setForm] = useState<ProfileFormState | null>(editing);
  const [formError, setFormError] = useState<string | null>(null);
  const caps = usePlatformCapabilities();
  const [saving, setSaving] = useState(false);
  const [probing, setProbing] = useState(false);
  const [probeResults, setProbeResults] = useState<AnalyzedRoute[] | null>(null);
  const [probeNotice, setProbeNotice] = useState<string | null>(null);
  const [bulkCidrs, setBulkCidrs] = useState("");
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkOpen, setBulkOpen] = useState(false);
  const [tab, setTab] = useState<FormTab>("general");

  useEffect(() => {
    if (open) {
      setForm(editing);
      setFormError(null);
      setBulkCidrs("");
      setBulkOpen(false);
      setTab("general");
      setProbeResults(null);
      setProbeNotice(null);
    }
  }, [open, editing?.id]);

  const current = form ?? editing;
  if (!current) return null;

  const targetable = interfaces.filter((i) => i.category !== "filter");
  const systemProxyAvailable =
    current.xrayMode === "socks" &&
    (current.xraySocksPort !== null ||
      (current.isNew && current.xraySource === "vless"));
  const daemonManagedInterface = caps?.os === "linux" && (
    current.backend === "wireGuard" ||
    current.backend === "openVpn" ||
    (current.backend === "xray" && current.xrayMode === "tun")
  );

  const update = (patch: Partial<ProfileFormState>) =>
    setForm({ ...current, ...patch });

  /** Show a validation error and jump to the tab that contains the field. */
  const fail = (message: string, targetTab: FormTab) => {
    setFormError(message);
    setTab(targetTab);
  };

  const policyRuleCount =
    textToPolicies(current.rulesBlock, current.rulesProxy, current.rulesDirect)
      .reduce((n, p) => n + p.domains.length, 0);
  const routingCount = current.routes.length + policyRuleCount;

  const browseConfig = async () => {
    try {
      const selected = await openDialog({
        multiple: false,
        directory: false,
        filters: [
          {
            name: `${BACKEND_LABELS[current.backend]} config`,
            extensions: BACKEND_EXTENSIONS[current.backend],
          },
        ],
      });
      if (typeof selected === "string") {
        update({ configPath: selected });
      }
    } catch (err) {
      setFormError(String(err));
    }
  };

  const probeRoutes = async () => {
    if (!current.configPath.trim()) {
      setProbeNotice("Set a config file first.");
      return;
    }
    setProbing(true);
    setProbeNotice(null);
    setProbeResults(null);
    try {
      const routes = await invoke<AnalyzedRoute[]>("probe_openvpn_routes", {
        id: current.id,
      });
      setProbeResults(routes);
      setProbeNotice(
        routes.length === 0
          ? "Probe completed, but no pushed routes were found."
          : `Found ${routes.length} route(s). Add them to policy routes below.`,
      );
    } catch (err) {
      setProbeNotice(String(err));
    } finally {
      setProbing(false);
    }
  };

  const addProbedRoutes = () => {
    if (!probeResults) return;
    const existing = new Set(current.routes.map((r) => r.destination));
    const toAdd = probeResults
      .filter((r) => !existing.has(r.destination))
      .map((r) => ({
        destination: r.destination,
        metric: 5,
      }));
    if (toAdd.length === 0) {
      setProbeNotice("All probed routes are already in the policy routes list.");
      return;
    }
    update({ routes: [...current.routes, ...toAdd] });
    setProbeNotice(`Added ${toAdd.length} route(s) to policy routes.`);
  };

  const updateRoute = (index: number, patch: Partial<PolicyRoute>) =>
    update({
      routes: current.routes.map((r, i) =>
        i === index ? { ...r, ...patch } : r,
      ),
    });

  const addBulkCidrs = async () => {
    if (!bulkCidrs.trim()) return;
    setBulkBusy(true);
    setFormError(null);
    try {
      const cidrs = await invoke<string[]>("parse_bulk_cidrs", { input: bulkCidrs });
      if (cidrs.length === 0) {
        setFormError("No CIDRs found in the pasted list.");
        return;
      }
      const existing = new Set(current.routes.map((route) => route.destination.trim()));
      update({
        routes: [
          ...current.routes,
          ...cidrs.filter((cidr) => !existing.has(cidr)).map((destination) => ({ destination, metric: 5 })),
        ],
      });
      setBulkCidrs("");
    } catch (err) {
      setFormError(String(err));
    } finally {
      setBulkBusy(false);
    }
  };

  const save = async () => {
    for (const route of current.routes) {
      if (!route.destination.trim()) {
        fail("Route destination cannot be blank.", "routing");
        return;
      }
    }
    if (current.routes.length > 0 && !current.interfaceName.trim()
      && !daemonManagedInterface) {
      fail("Target interface is required when policy routes are set.", "routing");
      return;
    }
    if (current.backend === "none" && current.routes.length === 0) {
      fail("Static-routes profile requires at least one policy route.", "routing");
      return;
    }
    const isXray = current.backend === "xray";
    const isVlessImport =
      isXray && current.isNew && current.xraySource === "vless";
    const isWgFields =
      current.backend === "wireGuard" &&
      current.isNew &&
      current.wgSource === "fields";
    const proxyBypass = parseBypass(current.proxyBypass);
    if (isXray && current.useSystemProxy) {
      for (const entry of proxyBypass) {
        if (entry.includes(";")) {
          fail("Proxy bypass entries must not contain ';'.", "connection");
          return;
        }
      }
    }
    const domainPolicies = textToPolicies(
      current.rulesBlock,
      current.rulesProxy,
      current.rulesDirect,
    );
    if (isVlessImport) {
      if (!current.vlessUrl.trim()) {
        fail("Share link is required.", "connection");
        return;
      }
      if (
        current.xraySocksPort !== null &&
        (!Number.isInteger(current.xraySocksPort) ||
          current.xraySocksPort < 1 ||
          current.xraySocksPort > 65535)
      ) {
        fail("SOCKS port must be an integer between 1 and 65535.", "connection");
        return;
      }
    }
    if (isWgFields) {
      const f = current.wgFields;
      if (!f.privateKey.trim()) {
        fail("WireGuard private key is required.", "connection");
        return;
      }
      if (!f.address.trim()) {
        fail("WireGuard interface address is required.", "connection");
        return;
      }
      if (!f.peerPublicKey.trim()) {
        fail("WireGuard peer public key is required.", "connection");
        return;
      }
      if (!f.peerEndpoint.trim()) {
        fail("WireGuard peer endpoint is required.", "connection");
        return;
      }
      if (!f.allowedIps.trim()) {
        fail("WireGuard allowed IPs are required.", "connection");
        return;
      }
    }
    const payload: Profile = {
      id: current.id,
      name: current.name.trim(),
      backend: current.backend,
      configPath: current.configPath.trim(),
      interfaceName: current.interfaceName.trim(),
      routes: current.routes.map((r) => ({
        destination: r.destination.trim(),
        metric: clampMetric(r.metric),
        via: r.via?.trim() || null,
      })),
      autoConnect: current.autoConnect,
      domainPolicies: isXray ? domainPolicies : [],
      privateLanDirect: isXray && current.privateLanDirect,
      xraySocksPort: !isXray
        ? null
        : isVlessImport
          ? current.xraySocksPort
          : current.isNew
            ? null
            : current.xraySocksPort,
      xrayHttpPort: isXray && !current.isNew ? current.xrayHttpPort : null,
      useSystemProxy: isXray && current.useSystemProxy && current.xrayMode === "socks",
      proxyBypass: isXray ? proxyBypass : [],
      subscription: current.isNew ? null : current.subscription ?? null,
      xrayMode: isXray ? current.xrayMode : "socks",
      xrayTunInterface: isXray && current.xrayMode === "tun" && caps?.os === "windows" ? current.xrayTunInterface.trim() : null,
      xrayTunIp: isXray && current.xrayMode === "tun" && caps?.os === "windows" ? current.xrayTunIp.trim() : null,
      xrayGeoipUrl: isXray && current.xrayMode === "tun" ? current.xrayGeoipUrl.trim() || null : null,
      xrayGeositeUrl: isXray && current.xrayMode === "tun" ? current.xrayGeositeUrl.trim() || null : null,
    };
    setSaving(true);
    try {
      let updated: Profile[];
      if (isVlessImport) {
        updated = await invoke<Profile[]>("save_vless_profile", {
          profile: payload,
          vlessUrl: current.vlessUrl.trim(),
        });
      } else if (isWgFields) {
        updated = await invoke<Profile[]>("save_wireguard_profile", {
          profile: payload,
          fields: current.wgFields,
        });
      } else {
        updated = await invoke<Profile[]>("save_profile", { profile: payload });
      }
      let inspection: ProfileInspection | null = null;
      try {
        inspection = await invoke<ProfileInspection>(
          "inspect_profile_by_id",
          { id: current.id },
        );
      } catch (err) {
        onError(`Profile was saved, but static analysis failed: ${String(err)}`);
      }
      onSaved(updated, inspection);
      setForm(null);
      setFormError(null);
    } catch (err) {
      setFormError(String(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open={open}
      title={current.isNew ? "New profile" : "Edit profile"}
      onClose={onClose}
      footer={
        <>
          <button type="button" onClick={onClose} disabled={saving}>
            Cancel
          </button>
          <button
            type="button"
            className="btn-primary"
            onClick={save}
            disabled={saving}
          >
            {saving ? "Saving…" : "Save"}
          </button>
        </>
      }
    >
      <div className="modal-tabs" role="tablist" aria-label="Profile sections">
        <button
          type="button"
          role="tab"
          aria-selected={tab === "general"}
          className={`modal-tab ${tab === "general" ? "active" : ""}`}
          onClick={() => setTab("general")}
        >
          General
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === "connection"}
          className={`modal-tab ${tab === "connection" ? "active" : ""}`}
          onClick={() => setTab("connection")}
        >
          Connection
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === "routing"}
          className={`modal-tab ${tab === "routing" ? "active" : ""}`}
          onClick={() => setTab("routing")}
        >
          Routing
          {routingCount > 0 && (
            <span className="modal-tab-count">{routingCount}</span>
          )}
        </button>
      </div>

      {formError && <p className="error">{formError}</p>}

      {tab === "general" && (
      <div className="modal-tab-body" role="tabpanel">
      <label>
        Name
        <input
          type="text"
          value={current.name}
          onChange={(e) => update({ name: e.target.value })}
          placeholder="Work VPN"
          autoFocus
        />
      </label>
      <label>
        Backend
        <select
          className="filter-select"
          value={current.backend}
          onChange={(e) => {
            const backend = e.target.value as TunnelBackend;
            update({
              backend,
              configPath: "",
              rulesProxy: backend === "xray" ? current.rulesProxy : "",
              rulesDirect: backend === "xray" ? current.rulesDirect : "",
              rulesBlock: backend === "xray" ? current.rulesBlock : "",
              privateLanDirect: backend === "xray" && current.privateLanDirect,
              xraySource: "json",
              xraySocksPort:
                backend === "xray"
                  ? current.isNew
                    ? null
                    : (current.xraySocksPort ?? 10808)
                  : null,
              xrayHttpPort: backend === "xray" ? current.xrayHttpPort : null,
            });
          }}
        >
          <option value="none">Static routes (no tunnel)</option>
          <option value="wireGuard">WireGuard</option>
          <option value="openVpn">OpenVPN</option>
          <option value="xray">Xray</option>
        </select>
      </label>
      {caps?.os === "linux" && (
        <label className="profile-proxy-toggle">
          <input
            type="checkbox"
            checked={current.autoConnect}
            onChange={(e) => update({ autoConnect: e.target.checked })}
          />
          Connect when the app starts
        </label>
      )}
      </div>
      )}

      {tab === "connection" && (
      <div className="modal-tab-body" role="tabpanel">
      {current.backend !== "none" && current.backend === "xray" && current.isNew && (
        <label>
          Config source
          <select
            className="filter-select"
            value={current.xraySource}
            onChange={(e) =>
              update({ xraySource: e.target.value as "json" | "vless" })
            }
          >
            <option value="json">Existing Xray JSON</option>
            <option value="vless">Import share link</option>
          </select>
        </label>
      )}
      {current.backend === "wireGuard" && current.isNew && (
        <label>
          Config source
          <select
            className="filter-select"
            value={current.wgSource}
            onChange={(e) =>
              update({ wgSource: e.target.value as "file" | "fields" })
            }
          >
            <option value="fields">Enter tunnel fields</option>
            <option value="file">Existing .conf file</option>
          </select>
        </label>
      )}
      {current.backend === "xray" &&
      current.isNew &&
      current.xraySource === "vless" ? (
        <>
          <label>
            Share link
            <input
              type="password"
              value={current.vlessUrl}
              onChange={(e) => update({ vlessUrl: e.target.value })}
              placeholder="vless:// or hysteria2://…"
              autoComplete="off"
            />
          </label>
          <span className="profile-help">
            SOCKS5 port will be assigned automatically when the profile is
            saved.
          </span>
        </>
      ) : current.backend === "wireGuard" &&
        current.isNew &&
        current.wgSource === "fields" ? (
        <div className="profile-wg-fields">
          <label>
            Private key
            <input
              type="password"
              value={current.wgFields.privateKey}
              onChange={(e) =>
                update({
                  wgFields: { ...current.wgFields, privateKey: e.target.value },
                })
              }
              placeholder="base64 private key"
              autoComplete="off"
            />
          </label>
          <label>
            Interface address
            <input
              type="text"
              value={current.wgFields.address}
              onChange={(e) =>
                update({
                  wgFields: { ...current.wgFields, address: e.target.value },
                })
              }
              placeholder="10.0.0.2/24"
            />
          </label>
          <label>
            DNS (optional)
            <input
              type="text"
              value={current.wgFields.dns}
              onChange={(e) =>
                update({
                  wgFields: { ...current.wgFields, dns: e.target.value },
                })
              }
              placeholder="1.1.1.1"
            />
          </label>
          <label>
            Peer public key
            <input
              type="text"
              value={current.wgFields.peerPublicKey}
              onChange={(e) =>
                update({
                  wgFields: {
                    ...current.wgFields,
                    peerPublicKey: e.target.value,
                  },
                })
              }
              placeholder="base64 public key"
            />
          </label>
          <label>
            Peer endpoint
            <input
              type="text"
              value={current.wgFields.peerEndpoint}
              onChange={(e) =>
                update({
                  wgFields: {
                    ...current.wgFields,
                    peerEndpoint: e.target.value,
                  },
                })
              }
              placeholder="vpn.example.com:51820"
            />
          </label>
          <label>
            Allowed IPs
            <input
              type="text"
              value={current.wgFields.allowedIps}
              onChange={(e) =>
                update({
                  wgFields: { ...current.wgFields, allowedIps: e.target.value },
                })
              }
              placeholder="0.0.0.0/0"
            />
          </label>
          <label>
            Preshared key (optional)
            <input
              type="password"
              value={current.wgFields.presharedKey}
              onChange={(e) =>
                update({
                  wgFields: {
                    ...current.wgFields,
                    presharedKey: e.target.value,
                  },
                })
              }
              placeholder="base64 preshared key"
              autoComplete="off"
            />
          </label>
          <label>
            Persistent keepalive (seconds, optional)
            <input
              type="number"
              min={0}
              max={65535}
              value={current.wgFields.persistentKeepalive ?? ""}
              onChange={(e) =>
                update({
                  wgFields: {
                    ...current.wgFields,
                    persistentKeepalive:
                      e.target.value === "" ? null : e.target.valueAsNumber,
                  },
                })
              }
              placeholder="25"
            />
          </label>
        </div>
      ) : current.backend !== "none" ? (
        <label>
          Config file
          <div className="profile-config-row">
            <input
              type="text"
              value={current.configPath}
              onChange={(e) => update({ configPath: e.target.value })}
              placeholder={
                current.backend === "wireGuard"
                  ? "C:\\path\\tunnel.conf"
                  : current.backend === "openVpn"
                    ? "C:\\path\\client.ovpn"
                    : "C:\\path\\config.json"
              }
            />
            <button type="button" onClick={browseConfig}>
              Browse…
            </button>
          </div>
        </label>
      ) : (
        <span className="profile-help">
          Static-routes profiles apply policy routes through an existing
          interface (e.g. Ethernet) without starting a tunnel.
        </span>
      )}
      {current.backend === "openVpn" && caps?.os !== "linux" && !current.isNew && current.configPath.trim() && (
        <div className="profile-probe">
          <button
            type="button"
            className="profile-probe-btn"
            onClick={probeRoutes}
            disabled={probing}
          >
            {probing ? "Probing…" : "Probe routes"}
          </button>
          <span className="profile-help">
            Connects briefly with <code>--route-nopull</code> to discover
            server-pushed routes without installing them.
          </span>
          {probeNotice && (
            <p className={`probe-notice ${probeResults && probeResults.length > 0 ? "ok" : ""}`}>
              {probeNotice}
            </p>
          )}
          {probeResults && probeResults.length > 0 && (
            <div className="probe-results">
              <div className="probe-results-head">
                <span>Discovered routes ({probeResults.length})</span>
                <button type="button" className="profile-probe-add" onClick={addProbedRoutes}>
                  Add all to policy routes
                </button>
              </div>
              <ul className="probe-route-list">
                {probeResults.map((r, i) => (
                  <li key={i}>
                    <span className="mono">{r.destination}</span>
                    <span className="probe-route-source">{r.source}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
      {current.backend === "xray" && (
        <label>
          Xray mode
          <select
            className="filter-select"
            value={current.xrayMode}
            onChange={(e) =>
              update({ xrayMode: e.target.value as XrayMode })
            }
          >
            <option value="socks">SOCKS5 (system proxy)</option>
            <option value="tun" disabled={caps?.os === "linux" && current.xraySource !== "vless" && current.xraySocksPort === null}>
              {caps?.os === "linux" ? "TUN (network daemon, generated links)" : "TUN (full tunnel, requires admin)"}
            </option>
          </select>
        </label>
      )}
      {current.backend === "xray" &&
        current.xrayMode === "tun" && (
          <div className="profile-tun-fields">
            {caps?.os === "linux" ? (
              <span className="profile-help">
                The network daemon assigns the TUN interface and IP. With no
                policy routes, IPv4 uses a default route and 1.1.1.1 DNS;
                explicit split routes do not set DNS automatically.
              </span>
            ) : (
            <>
            <label>
              TUN interface name
              <input
                type="text"
                value={current.xrayTunInterface}
                onChange={(e) =>
                  update({ xrayTunInterface: e.target.value })
                }
                placeholder="xray-tun"
              />
            </label>
            <label>
              TUN interface IP
              <input
                type="text"
                value={current.xrayTunIp}
                onChange={(e) => update({ xrayTunIp: e.target.value })}
                placeholder="172.19.0.1/30"
              />
            </label>
            <span className="profile-help">
              TUN mode captures all IP traffic via a TUN interface. Domain
              policies still apply inside Xray. System proxy is not used.
            </span>
            </>
            )}
          </div>
        )}
      {current.backend === "xray" &&
        !current.isNew &&
        current.xrayMode === "socks" &&
        current.xraySocksPort !== null && (
          <div className="interface-row">
            <span className="row-label">SOCKS5</span>
            <span className="row-value mono">
              127.0.0.1:{current.xraySocksPort}
            </span>
          </div>
        )}
      {current.backend === "xray" &&
        !current.isNew &&
        current.xrayMode === "socks" &&
        current.xrayHttpPort !== null && (
          <div className="interface-row">
            <span className="row-label">HTTP CONNECT</span>
            <span className="row-value mono">
              127.0.0.1:{current.xrayHttpPort}
            </span>
          </div>
        )}
      {current.backend === "xray" &&
        current.xrayMode === "socks" &&
        caps?.systemProxy && (
        <div className="profile-proxy">
          <label className="profile-proxy-toggle">
            <input
              type="checkbox"
              checked={current.useSystemProxy}
              disabled={!systemProxyAvailable}
              onChange={(e) =>
                update({ useSystemProxy: e.target.checked })
              }
            />
            Use Windows system proxy
          </label>
          {!systemProxyAvailable ? (
            <span className="profile-help">
              System proxy requires a generated Xray profile with a SOCKS5
              listener — this existing JSON config has none.
            </span>
          ) : (
            <span className="profile-help">
              Applies only to apps that honor Windows proxy settings. LAN and
              localhost are always bypassed; add extra entries below.
            </span>
          )}
          {current.useSystemProxy && systemProxyAvailable && (
            <label>
              Extra proxy bypass (comma-separated)
              <input
                type="text"
                value={current.proxyBypass}
                onChange={(e) => update({ proxyBypass: e.target.value })}
                placeholder={PROXY_BYPASS_PLACEHOLDER}
              />
            </label>
          )}
        </div>
      )}
      </div>
      )}

      {tab === "routing" && (
      <div className="modal-tab-body" role="tabpanel">
      {!daemonManagedInterface && <label>
        Target interface (required for policy routes)
        <input
          type="text"
          list="profile-target-interfaces"
          value={current.interfaceName}
          onChange={(e) => update({ interfaceName: e.target.value })}
          placeholder="Interface friendly name"
        />
        <datalist id="profile-target-interfaces">
          {targetable.map((i) => (
            <option
              key={i.ifIndex}
              value={i.friendlyName}
              label={i.description || i.name}
            />
          ))}
        </datalist>
      </label>}
      <div className="profile-routes">
        <div className="profile-routes-head">
          <span>Policy routes</span>
          <button
            type="button"
            onClick={() =>
              update({
                routes: [
                  ...current.routes,
                  { destination: "10.0.0.0/24", metric: 5 },
                ],
              })
            }
          >
            Add route
          </button>
        </div>
        <button
          type="button"
          className="connection-detail-toggle"
          onClick={() => setBulkOpen((v) => !v)}
          aria-expanded={bulkOpen}
        >
          <ChevronIcon size={13} collapsed={!bulkOpen} />
          Paste a CIDR list or load from file
        </button>
        {bulkOpen && (
          <div className="profile-bulk-cidrs">
            <label>
              Paste CIDRs (one per line or comma-separated)
              <textarea
                value={bulkCidrs}
                onChange={(event) => setBulkCidrs(event.target.value)}
                rows={3}
                placeholder={"10.0.0.0/24\n2001:db8::/32"}
              />
            </label>
            <div className="profile-bulk-actions">
              <input
                type="file"
                accept=".txt,.csv,text/plain,text/csv"
                aria-label="Load CIDRs from file"
                onChange={async (event) => {
                  const file = event.target.files?.[0];
                  event.target.value = "";
                  if (!file) return;
                  if (file.size > 1024 * 1024) {
                    setFormError("CIDR file exceeds 1 MiB.");
                    return;
                  }
                  try {
                    setBulkCidrs(await file.text());
                  } catch {
                    setFormError("Could not read CIDR file.");
                  }
                }}
              />
              <button type="button" onClick={addBulkCidrs} disabled={bulkBusy || !bulkCidrs.trim()}>
                {bulkBusy ? "Adding…" : "Add CIDRs"}
              </button>
            </div>
          </div>
        )}
        {current.routes.length === 0 && (
          <span className="profile-routes-empty">
            No routes — tunnel uses its own routing.
          </span>
        )}
        {current.routes.map((route, index) => (
          <div className="profile-route-row" key={index}>
            <input
              type="text"
              value={route.destination}
              onChange={(e) =>
                updateRoute(index, { destination: e.target.value })
              }
              placeholder="10.0.0.0/24"
            />
            <input
              type="text"
              value={route.via ?? ""}
              onChange={(e) => updateRoute(index, { via: e.target.value })}
              placeholder="Gateway (optional)"
              aria-label="Gateway (optional)"
            />
            <input
              type="number"
              min={0}
              max={9999}
              value={route.metric}
              onChange={(e) =>
                updateRoute(index, {
                  metric: clampMetric(e.target.valueAsNumber),
                })
              }
            />
            <button
              type="button"
              onClick={() =>
                update({
                  routes: current.routes.filter((_, i) => i !== index),
                })
              }
            >
              Remove
            </button>
          </div>
        ))}
      </div>
      {current.backend === "xray" && (
        <div className="profile-routes">
          <div className="profile-routes-head">
            <span>Domain/IP routing</span>
          </div>
          <span className="profile-routes-hint">
            One selector per line: domain:example.com, geosite:category, geoip:cc,
            or a bare IP/CIDR. Lines starting with # are comments. Rules are
            evaluated block → proxy → direct; unmatched traffic uses the proxy.
          </span>
          <div className="rules-grid">
            <label className="rules-pane">
              <span className="rules-pane-title rules-pane-proxy">Proxy</span>
              <textarea
                className="rules-textarea"
                value={current.rulesProxy}
                onChange={(e) => update({ rulesProxy: e.target.value })}
                placeholder={"geosite:youtube\ndomain:example.com"}
                spellCheck={false}
              />
            </label>
            <label className="rules-pane">
              <span className="rules-pane-title rules-pane-direct">Direct</span>
              <textarea
                className="rules-textarea"
                value={current.rulesDirect}
                onChange={(e) => update({ rulesDirect: e.target.value })}
                placeholder={"geosite:private\n# my services\n10.0.0.0/8"}
                spellCheck={false}
              />
            </label>
            <label className="rules-pane">
              <span className="rules-pane-title rules-pane-block">Block</span>
              <textarea
                className="rules-textarea"
                value={current.rulesBlock}
                onChange={(e) => update({ rulesBlock: e.target.value })}
                placeholder={"geosite:category-ads\ndomain:tracker.io"}
                spellCheck={false}
              />
            </label>
          </div>
          <label className="profile-proxy-toggle">
            <input
              type="checkbox"
              checked={current.privateLanDirect}
              onChange={(e) => update({ privateLanDirect: e.target.checked })}
            />
            Direct for private/LAN IPs (after custom rules)
          </label>
          {current.xrayMode === "tun" && (
            <div className="geo-override">
              <span className="profile-routes-hint">
                Custom geo data (optional) — HTTPS URLs to geoip.dat / geosite.dat
                replacing the bundled files. Downloaded on connect, cached 24h.
              </span>
              <div className="geo-override-fields">
                <input
                  type="text"
                  value={current.xrayGeoipUrl}
                  onChange={(e) => update({ xrayGeoipUrl: e.target.value })}
                  placeholder="https://…/geoip.dat"
                  spellCheck={false}
                />
                <input
                  type="text"
                  value={current.xrayGeositeUrl}
                  onChange={(e) => update({ xrayGeositeUrl: e.target.value })}
                  placeholder="https://…/geosite.dat"
                  spellCheck={false}
                />
              </div>
            </div>
          )}
        </div>
      )}
      </div>
      )}
    </Modal>
  );
}
