import { useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  NetworkInterface,
  InterfaceCategory,
  formatKind,
  ifTypeName,
  CATEGORY_ORDER,
} from "../types";
import { useT } from "../i18n";
import { CATEGORY_DESC_KEYS, CATEGORY_LABEL_KEYS } from "../i18n/labels";
import { kindIcon, categoryIcon, ChevronIcon } from "../icons";
import InterfaceDetail from "./InterfaceDetail";
import Page from "./Page";
import Skeleton from "./ui/Skeleton";
import RateText from "./ui/RateText";
import { formatBytes } from "../format";

interface Throughput {
  rxRate: number;
  txRate: number;
}

type StateFilter = "all" | "up" | "down";
type TypePreset = "main" | "all" | "osinternal";

const MAIN_CATS: InterfaceCategory[] = ["physical", "vpn", "virtual", "system"];
const OSINTERNAL_CATS: InterfaceCategory[] = ["tunnel", "filter"];

export default function InterfaceList() {
  const t = useT();
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

  if (loading) {
    return (
      <Page width="wide">
        <section>
          <h2>{t("net.title")}</h2>
          <div className="iface-list">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="iface-row">
                <Skeleton width="14px" height="14px" />
                <Skeleton width="160px" height="0.9rem" />
              </div>
            ))}
          </div>
        </section>
      </Page>
    );
  }
  if (error)
    return (
      <Page width="wide">
        <p className="error">{t("net.loadError", { err: error })}</p>
      </Page>
    );

  return (
    <Page width="wide">
    <section>
      <h2>{t("net.title")}</h2>
      <div className="filter-bar">
        <input
          className="filter-search"
          type="text"
          placeholder={t("net.searchPlaceholder")}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select
          className="filter-select"
          value={typePreset}
          onChange={(e) => applyTypePreset(e.target.value as TypePreset)}
        >
          <option value="main">{t("net.presetMain")}</option>
          <option value="all">{t("net.presetAll")}</option>
          <option value="osinternal">{t("net.presetOs")}</option>
        </select>
        <div className="filter-state">
          <button
            className={`filter-btn ${stateFilter === "all" ? "active" : ""}`}
            onClick={() => setStateFilter("all")}
          >
            {t("common.all")}
          </button>
          <button
            className={`filter-btn ${stateFilter === "up" ? "active" : ""}`}
            onClick={() => setStateFilter("up")}
          >
            {t("iface.stateUp")}
          </button>
          <button
            className={`filter-btn ${stateFilter === "down" ? "active" : ""}`}
            onClick={() => setStateFilter("down")}
          >
            {t("iface.stateDown")}
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
              title={t(CATEGORY_DESC_KEYS[cat])}
            >
              {categoryIcon(cat, 14)}
              <span>{t(CATEGORY_LABEL_KEYS[cat])}</span>
              <span className="cat-count">{count}</span>
            </button>
          );
        })}
      </div>

      {grouped.size === 0 ? (
        <p className="empty-state">{t("net.noMatch")}</p>
      ) : (
        <div className="interface-groups">
          {CATEGORY_ORDER.map((cat) => {
            const list = grouped.get(cat);
            if (!list || list.length === 0) return null;
            const isCollapsed = collapsed.has(cat);
            return (
              <div key={cat} className="interface-group">
                <button
                  type="button"
                  className="group-header"
                  onClick={() => toggleCollapse(cat)}
                  aria-expanded={!isCollapsed}
                >
                  <ChevronIcon size={16} collapsed={isCollapsed} />
                  {categoryIcon(cat, 16)}
                  <span className="group-title">{t(CATEGORY_LABEL_KEYS[cat])}</span>
                  <span className="group-count">{list.length}</span>
                  <span className="group-desc">{t(CATEGORY_DESC_KEYS[cat])}</span>
                </button>
                {!isCollapsed && (
                  <div className="iface-list">
                    {list.map((iface) => {
                      const tp = throughput[iface.ifIndex];
                      const primary = iface.addresses[0];
                      const kindBits = [
                        formatKind(iface.kind),
                        ifTypeName(iface.ifType),
                        iface.tunnelType ? iface.tunnelType : null,
                        iface.mtu !== null ? `MTU ${iface.mtu}` : null,
                        iface.linkSpeedMbps !== null
                          ? `${iface.linkSpeedMbps} Mbps`
                          : null,
                      ].filter(Boolean);
                      return (
                        <button
                          key={iface.ifIndex}
                          type="button"
                          className="iface-row"
                          onClick={() => setSelected(iface)}
                        >
                          <span
                            className={`status-dot state-${
                              iface.state === "Up"
                                ? "running"
                                : iface.state === "Down"
                                  ? "stopped"
                                  : "unknown"
                            }`}
                          />
                          <span className="backend-avatar">
                            {kindIcon(iface.kind, 14)}
                          </span>
                          <span className="iface-row-name">
                            {iface.friendlyName}
                          </span>
                          <span className="iface-row-kind">
                            {kindBits.join(" · ")}
                          </span>
                          <span className="iface-row-addr mono">
                            {primary
                              ? `${primary.address}/${primary.prefixLen}${
                                  iface.addresses.length > 1
                                    ? ` +${iface.addresses.length - 1}`
                                    : ""
                                }`
                              : ""}
                          </span>
                          <span className="iface-row-rate">
                            {tp ? (
                              <RateText
                                rx={tp.rxRate}
                                tx={tp.txRate}
                                live
                              />
                            ) : iface.rxBytes !== null ? (
                              `↓${formatBytes(iface.rxBytes)} ↑${formatBytes(iface.txBytes ?? 0)}`
                            ) : null}
                          </span>
                          <span
                            className={`state-badge state-${iface.state.toLowerCase()}`}
                          >
                            {iface.state}
                          </span>
                        </button>
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
    </Page>
  );
}
