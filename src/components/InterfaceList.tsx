import { useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  NetworkInterface,
  InterfaceCategory,
  formatKind,
  ifTypeName,
  CATEGORY_ORDER,
  CATEGORY_LABELS,
  CATEGORY_DESCRIPTIONS,
} from "../types";
import { kindIcon, categoryIcon, ChevronIcon } from "../icons";
import InterfaceDetail from "./InterfaceDetail";

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatRate(bytesPerSec: number): string {
  if (bytesPerSec < 1024) return `${bytesPerSec.toFixed(0)} B/s`;
  if (bytesPerSec < 1024 * 1024) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
  return `${(bytesPerSec / (1024 * 1024)).toFixed(1)} MB/s`;
}

interface Throughput {
  rxRate: number;
  txRate: number;
}

type StateFilter = "all" | "up" | "down";
type TypePreset = "main" | "all" | "osinternal";

const MAIN_CATS: InterfaceCategory[] = ["physical", "vpn", "virtual", "system"];
const OSINTERNAL_CATS: InterfaceCategory[] = ["tunnel", "filter"];

export default function InterfaceList() {
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [throughput, setThroughput] = useState<Record<number, Throughput>>({});
  const [selected, setSelected] = useState<NetworkInterface | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [stateFilter, setStateFilter] = useState<StateFilter>("all");
  const [typePreset, setTypePreset] = useState<TypePreset>("main");
  const [enabledCats, setEnabledCats] = useState<Set<InterfaceCategory>>(
    () => new Set(MAIN_CATS)
  );
  const [collapsed, setCollapsed] = useState<Set<InterfaceCategory>>(new Set());
  const prevStats = useRef<Record<number, { rx: number; tx: number; time: number }>>({});

  const fetchInterfaces = async () => {
    try {
      setError(null);
      const data = await invoke<NetworkInterface[]>("get_interfaces");
      setInterfaces(data);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  // Poll for throughput every 1 second
  useEffect(() => {
    const poll = async () => {
      try {
        const data = await invoke<NetworkInterface[]>("get_interfaces");
        const now = Date.now();
        const newThroughput: Record<number, Throughput> = {};
        for (const iface of data) {
          if (iface.rxBytes === null || iface.txBytes === null) continue;
          const prev = prevStats.current[iface.ifIndex];
          if (prev) {
            const dt = (now - prev.time) / 1000;
            if (dt > 0) {
              newThroughput[iface.ifIndex] = {
                rxRate: Math.max(0, (iface.rxBytes - prev.rx) / dt),
                txRate: Math.max(0, (iface.txBytes - prev.tx) / dt),
              };
            }
          }
          prevStats.current[iface.ifIndex] = {
            rx: iface.rxBytes,
            tx: iface.txBytes,
            time: now,
          };
        }
        setThroughput(newThroughput);
      } catch {
        // ignore polling errors
      }
    };

    const interval = setInterval(poll, 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    fetchInterfaces();
  }, []);

  useEffect(() => {
    const handler = () => fetchInterfaces();
    window.addEventListener("route-changed", handler);
    return () => window.removeEventListener("route-changed", handler);
  }, []);

  // Count per category (before filtering, for chip badges)
  const categoryCounts = useMemo(() => {
    const counts = new Map<InterfaceCategory, number>();
    for (const iface of interfaces) {
      counts.set(iface.category, (counts.get(iface.category) ?? 0) + 1);
    }
    return counts;
  }, [interfaces]);

  // Filtered + grouped
  const grouped = useMemo(() => {
    const lower = search.toLowerCase();
    const filtered = interfaces.filter((iface) => {
      if (!enabledCats.has(iface.category)) return false;
      if (stateFilter === "up" && iface.state !== "Up") return false;
      if (stateFilter === "down" && iface.state === "Up") return false;
      if (lower) {
        const haystack = [
          iface.friendlyName,
          iface.name,
          iface.mac ?? "",
          ...iface.addresses.map((a) => a.address),
        ].join(" ").toLowerCase();
        if (!haystack.includes(lower)) return false;
      }
      return true;
    });

    const groups = new Map<InterfaceCategory, NetworkInterface[]>();
    for (const iface of filtered) {
      let list = groups.get(iface.category);
      if (!list) {
        list = [];
        groups.set(iface.category, list);
      }
      list.push(iface);
    }
    // Sort within group: physical first, then by name
    for (const list of groups.values()) {
      list.sort((a, b) => Number(b.physical) - Number(a.physical));
    }
    return groups;
  }, [interfaces, enabledCats, stateFilter, search]);

  const toggleCategory = (cat: InterfaceCategory) => {
    setEnabledCats((prev) => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  };

  const applyTypePreset = (preset: TypePreset) => {
    setTypePreset(preset);
    if (preset === "main") {
      setEnabledCats(new Set(MAIN_CATS));
    } else if (preset === "osinternal") {
      setEnabledCats(new Set(OSINTERNAL_CATS));
    } else {
      setEnabledCats(new Set(CATEGORY_ORDER));
    }
  };

  const toggleCollapse = (cat: InterfaceCategory) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  };

  if (loading) return <p>Loading interfaces...</p>;
  if (error) return <p className="error">Error loading interfaces: {error}</p>;

  return (
    <section>
      <div className="filter-bar">
        <input
          className="filter-search"
          type="text"
          placeholder="Search by name, MAC, address..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select
          className="filter-select"
          value={typePreset}
          onChange={(e) => applyTypePreset(e.target.value as TypePreset)}
        >
          <option value="main">Main</option>
          <option value="all">All interfaces</option>
          <option value="osinternal">OS-internal</option>
        </select>
        <div className="filter-state">
          <button
            className={`filter-btn ${stateFilter === "all" ? "active" : ""}`}
            onClick={() => setStateFilter("all")}
          >
            All
          </button>
          <button
            className={`filter-btn ${stateFilter === "up" ? "active" : ""}`}
            onClick={() => setStateFilter("up")}
          >
            Up
          </button>
          <button
            className={`filter-btn ${stateFilter === "down" ? "active" : ""}`}
            onClick={() => setStateFilter("down")}
          >
            Down
          </button>
        </div>
      </div>
      <div className="filter-categories">
        {CATEGORY_ORDER.map((cat) => {
          const count = categoryCounts.get(cat) ?? 0;
          if (count === 0) return null;
          const active = enabledCats.has(cat);
          return (
            <button
              key={cat}
              className={`cat-chip ${active ? "active" : ""} cat-${cat.toLowerCase()}`}
              onClick={() => toggleCategory(cat)}
              title={CATEGORY_DESCRIPTIONS[cat]}
            >
              {categoryIcon(cat, 14)}
              <span>{CATEGORY_LABELS[cat]}</span>
              <span className="cat-count">{count}</span>
            </button>
          );
        })}
      </div>

      {grouped.size === 0 ? (
        <p className="empty-state">No interfaces match the current filters.</p>
      ) : (
        <div className="interface-groups">
          {CATEGORY_ORDER.map((cat) => {
            const list = grouped.get(cat);
            if (!list || list.length === 0) return null;
            const isCollapsed = collapsed.has(cat);
            return (
              <div key={cat} className="interface-group">
                <div
                  className="group-header"
                  onClick={() => toggleCollapse(cat)}
                >
                  <ChevronIcon size={16} collapsed={isCollapsed} />
                  {categoryIcon(cat, 16)}
                  <span className="group-title">{CATEGORY_LABELS[cat]}</span>
                  <span className="group-count">{list.length}</span>
                  <span className="group-desc">{CATEGORY_DESCRIPTIONS[cat]}</span>
                </div>
                {!isCollapsed && (
                  <div className="interface-grid">
                    {list.map((iface) => {
                      const tp = throughput[iface.ifIndex];
                      return (
                        <div
                          key={iface.ifIndex}
                          className="interface-card clickable"
                          onClick={() => setSelected(iface)}
                        >
                          <div className="interface-header">
                            <div className="interface-title">
                              {kindIcon(iface.kind, 18)}
                              <span className="interface-name">{iface.friendlyName}</span>
                            </div>
                            <div className="badge-group">
                              <span className={`badge ${iface.physical ? "badge-physical" : "badge-virtual"}`}>
                                {iface.physical ? "Physical" : "Virtual"}
                              </span>
                              <span className={`state-badge state-${iface.state.toLowerCase()}`}>
                                {iface.state}
                              </span>
                            </div>
                          </div>
                          <div className="interface-meta">
                            <span className="meta-label">{formatKind(iface.kind)}</span>
                            <span className="meta-label">{ifTypeName(iface.ifType)}</span>
                            {iface.tunnelType && (
                              <span className="meta-label">Tunnel: {iface.tunnelType}</span>
                            )}
                            {iface.mtu !== null && (
                              <span className="meta-label">MTU: {iface.mtu}</span>
                            )}
                            {iface.linkSpeedMbps !== null && (
                              <span className="meta-label">{iface.linkSpeedMbps} Mbps</span>
                            )}
                          </div>
                          {iface.description && (
                            <div className="interface-row">
                              <span className="row-label">Driver</span>
                              <span className="row-value mono">{iface.description}</span>
                            </div>
                          )}
                          {iface.mac && (
                            <div className="interface-row">
                              <span className="row-label">MAC</span>
                              <span className="row-value mono">{iface.mac}</span>
                            </div>
                          )}
                          {iface.gateway && (
                            <div className="interface-row">
                              <span className="row-label">Gateway</span>
                              <span className="row-value mono">{iface.gateway}</span>
                            </div>
                          )}
                          {iface.addresses.length > 0 && (
                            <div className="interface-section">
                              <span className="section-label">Addresses</span>
                              <ul className="address-list">
                                {iface.addresses.map((addr, i) => (
                                  <li key={i}>
                                    <span className="mono">{addr.address}/{addr.prefixLen}</span>
                                    <span className="family-tag">{addr.family}</span>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                          {iface.dnsServers.length > 0 && (
                            <div className="interface-section">
                              <span className="section-label">DNS</span>
                              <ul className="dns-list">
                                {iface.dnsServers.map((dns, i) => (
                                  <li key={i} className="mono">{dns}</li>
                                ))}
                              </ul>
                            </div>
                          )}
                          {iface.dnsSuffix && (
                            <div className="interface-row">
                              <span className="row-label">DNS suffix</span>
                              <span className="row-value mono">{iface.dnsSuffix}</span>
                            </div>
                          )}
                          {iface.rxBytes !== null && iface.txBytes !== null && (
                            <div className="traffic-row">
                              <div className="interface-row">
                                <span className="row-label">Total</span>
                                <span className="row-value">
                                  <span className="traffic">↓ {formatBytes(iface.rxBytes)}</span>
                                  <span className="traffic">↑ {formatBytes(iface.txBytes)}</span>
                                </span>
                              </div>
                              {tp && (
                                <div className="interface-row">
                                  <span className="row-label">Rate</span>
                                  <span className="row-value">
                                  <span className="traffic rate">↓ {formatRate(tp.rxRate)}</span>
                                  <span className="traffic rate">↑ {formatRate(tp.txRate)}</span>
                                </span>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
      {selected && (
        <InterfaceDetail iface={selected} onClose={() => setSelected(null)} />
      )}
    </section>
  );
}
