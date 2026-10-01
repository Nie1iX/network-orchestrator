import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import Page from "./Page";
import RouteFlow from "./RouteFlow";
import RouteMap from "./RouteMap";
import RouteTable from "./RouteTable";
import { RouteLookupResult, RouteMap as RouteMapData } from "../types";
import { TranslationKey, useT } from "../i18n";
import { setRoutesPrefs, useRoutesPrefs } from "../prefs";

type RouteTab = "flow" | "tree" | "table";

const TABS: { id: RouteTab; labelKey: TranslationKey }[] = [
  { id: "flow", labelKey: "routes.flow" },
  { id: "tree", labelKey: "routes.tree" },
  { id: "table", labelKey: "routes.table" },
];

export default function RouteView() {
  const t = useT();
  const prefs = useRoutesPrefs();
  const [tab, setTab] = useState<RouteTab>("flow");
  const [map, setMap] = useState<RouteMapData | null>(null);
  const [lookupDest, setLookupDest] = useState("");
  const [lookupResult, setLookupResult] = useState<RouteLookupResult | null>(
    null,
  );
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [lookupLoading, setLookupLoading] = useState(false);

  const loadSummary = useCallback(async () => {
    try {
      const data = await invoke<RouteMapData>("get_route_map", {
        includeInactive: true,
      });
      setMap(data);
    } catch {
      // summary chips are best-effort
    }
  }, []);

  useEffect(() => {
    void loadSummary();
    const handler = () => void loadSummary();
    window.addEventListener("route-changed", handler);
    return () => window.removeEventListener("route-changed", handler);
  }, [loadSummary]);

  const lookup = async () => {
    const target = lookupDest.trim();
    if (!target) return;
    setLookupLoading(true);
    setLookupError(null);
    try {
      const data = await invoke<RouteLookupResult>("lookup_destination", {
        dest: target,
      });
      setLookupResult(data);
    } catch (err) {
      setLookupResult(null);
      setLookupError(String(err));
    } finally {
      setLookupLoading(false);
    }
  };

  const activeCount = map ? map.predicted.filter((r) => r.active).length : null;
  const conflicts = map?.diffs.length ?? null;
  const warnings = map?.warnings.length ?? null;

  return (
    <Page width="full">
      <div className="routes-toolbar">
        <h2>{t("routes.title")}</h2>
        <nav className="route-tabs" aria-label={t("routes.viewsAria")}>
          {TABS.map((item) => (
            <button
              key={item.id}
              type="button"
              className={`route-tab ${tab === item.id ? "active" : ""}`}
              onClick={() => setTab(item.id)}
            >
              {t(item.labelKey)}
            </button>
          ))}
        </nav>
        {map && (
          <div className="routes-summary">
            <span className="route-stat">{t("routes.activeCount", { n: activeCount ?? 0 })}</span>
            <button
              type="button"
              className={`route-stat route-stat-btn ${conflicts ? "bad" : ""}`}
              onClick={() => setTab("tree")}
              title={t("routes.conflictsTitle")}
            >
              {t("routes.conflictCount", { count: conflicts ?? 0 })}
            </button>
            <button
              type="button"
              className={`route-stat route-stat-btn ${warnings ? "warn" : ""}`}
              onClick={() => setTab("tree")}
              title={t("routes.warningsTitle")}
            >
              {t("routes.warningCount", { count: warnings ?? 0 })}
            </button>
          </div>
        )}
        <div className="routes-options">
          <label className="route-map-toggle">
            <input
              type="checkbox"
              checked={prefs.hideIpv6}
              onChange={(e) => setRoutesPrefs({ hideIpv6: e.target.checked })}
            />
            {t("routes.hideIpv6")}
          </label>
          {tab === "tree" && (
            <label className="route-map-toggle">
              <input
                type="checkbox"
                checked={prefs.includeStopped}
                onChange={(e) =>
                  setRoutesPrefs({ includeStopped: e.target.checked })
                }
              />
              {t("routes.includeStopped")}
            </label>
          )}
        </div>
        <form
          className="lookup-input"
          title={t("routes.lookupHint")}
          onSubmit={(e) => {
            e.preventDefault();
            void lookup();
          }}
        >
          <span className="routes-lookup-label">{t("routes.lookupLabel")}</span>
          <input
            type="text"
            value={lookupDest}
            onChange={(e) => setLookupDest(e.currentTarget.value)}
            placeholder={t("routes.lookupPlaceholder")}
          />
          <button
            type="submit"
            className="btn-sm"
            disabled={lookupLoading || !lookupDest.trim()}
          >
            {lookupLoading ? "…" : t("routes.lookup")}
          </button>
        </form>
      </div>

      {lookupError && <p className="error">{lookupError}</p>}
      {lookupResult && (
        <div className="lookup-result routes-lookup-result">
          <div className="lookup-result-head">
            <span>
              {lookupResult.destination} →{" "}
              <span className="mono">
                {lookupResult.matchedRoute.destination}/
                {lookupResult.matchedRoute.prefixLen}
              </span>{" "}
              {t("routes.via")} {lookupResult.interfaceName}
              {lookupResult.table
                ? ` · ${t("routes.tableN", { n: lookupResult.table })}`
                : ""}
            </span>
            <button
              type="button"
              className="btn-ghost btn-sm"
              onClick={() => {
                setLookupResult(null);
                setLookupError(null);
              }}
            >
              {t("common.clear")}
            </button>
          </div>
          <div className="lookup-result-meta">
            {lookupResult.matchedRoute.gateway && (
              <span className="mono">
                gw {lookupResult.matchedRoute.gateway}
              </span>
            )}
            <span>
              {t("routes.metric", { n: lookupResult.matchedRoute.metric })}
            </span>
          </div>
        </div>
      )}

      <div className="route-tab-content">
        {tab === "flow" && <RouteFlow hideIpv6={prefs.hideIpv6} />}
        {tab === "tree" && (
          <RouteMap
            hideIpv6={prefs.hideIpv6}
            includeInactive={prefs.includeStopped}
          />
        )}
        {tab === "table" && <RouteTable hideIpv6={prefs.hideIpv6} />}
      </div>
    </Page>
  );
}
