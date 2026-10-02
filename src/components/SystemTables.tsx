import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { NetTablesResult, SystemRoute, SystemRule } from "../types";
import { useT } from "../i18n";

const TABLE_NAMES: Record<number, string> = {
  253: "default",
  254: "main",
  255: "local",
};

function tableLabel(table: number): string {
  const name = TABLE_NAMES[table];
  return name ? `${table} · ${name}` : `${table}`;
}

function routeDestination(route: SystemRoute): string {
  const slash = route.destination.lastIndexOf("/");
  const prefix = slash >= 0 ? Number(route.destination.slice(slash + 1)) : 0;
  const hostLen = route.family === "ipv4" ? 32 : 128;
  if (prefix === 0) return "default";
  if (prefix === hostLen) return route.destination.slice(0, slash);
  return route.destination;
}

function ruleSelector(rule: SystemRule): string {
  const parts: string[] = [];
  if (rule.invert) parts.push("not");
  parts.push("from", rule.from ?? "all");
  if (rule.to) parts.push("to", rule.to);
  if (rule.iifname) parts.push("iif", rule.iifname);
  if (rule.oifname) parts.push("oif", rule.oifname);
  if (rule.fwmark != null) {
    const mark = `0x${rule.fwmark.toString(16)}`;
    parts.push(
      rule.fwmask != null && rule.fwmask !== 0xffffffff
        ? `fwmark ${mark}/0x${rule.fwmask.toString(16)}`
        : `fwmark ${mark}`,
    );
  }
  if (rule.uidRange) parts.push("uidrange", rule.uidRange.join("-"));
  if (rule.ipProtocol) parts.push("ipproto", rule.ipProtocol);
  if (rule.sourcePortRange)
    parts.push("sport", rule.sourcePortRange.join("-"));
  if (rule.destinationPortRange)
    parts.push("dport", rule.destinationPortRange.join("-"));
  if (rule.tos !== 0) parts.push("tos", `0x${rule.tos.toString(16)}`);
  if (rule.tunId != null) parts.push("tun_id", `${rule.tunId}`);
  if (rule.suppressPrefixLength != null)
    parts.push("suppress_prefixlen", `${rule.suppressPrefixLength}`);
  if (rule.suppressIfGroup != null)
    parts.push("suppress_ifgroup", `${rule.suppressIfGroup}`);
  return parts.join(" ");
}

function ruleAction(rule: SystemRule): string {
  if (rule.action === "lookup") return `lookup ${tableLabel(rule.table)}`;
  if (rule.action === "goto") return `goto ${rule.goto ?? "?"}`;
  return rule.action;
}

function routeDetails(route: SystemRoute): string {
  const parts: string[] = [];
  if (route.kind !== "unicast") parts.push(route.kind);
  if (route.scope !== "universe") parts.push(`scope ${route.scope}`);
  if (route.protocol !== 0 && !route.managed)
    parts.push(`proto ${route.protocol}`);
  if (route.prefSource) parts.push(`src ${route.prefSource}`);
  return parts.join(" ");
}

export default function SystemTables({ hideIpv6 }: { hideIpv6: boolean }) {
  const t = useT();
  const [data, setData] = useState<NetTablesResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchTables = async () => {
    try {
      setError(null);
      setData(await invoke<NetTablesResult>("get_net_tables"));
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void fetchTables();
    const handler = () => void fetchTables();
    window.addEventListener("route-changed", handler);
    return () => window.removeEventListener("route-changed", handler);
  }, []);

  if (loading) return <p>{t("routes.systemLoading")}</p>;
  if (error) return <p className="error">{t("routes.systemError", { err: error })}</p>;
  if (!data || !data.available) return <p>{t("routes.systemUnavailable")}</p>;

  const rules = data.rules.filter(
    (rule) => !hideIpv6 || rule.family !== "ipv6",
  );
  const tables = new Map<number, SystemRoute[]>();
  for (const route of data.routes) {
    if (hideIpv6 && route.family === "ipv6") continue;
    const group = tables.get(route.table) ?? [];
    group.push(route);
    tables.set(route.table, group);
  }
  const groups = [...tables.entries()].sort(([a], [b]) => a - b);

  return (
    <section>
      <h3 className="system-tables-heading">{t("routes.systemRules")}</h3>
      {rules.length === 0 ? (
        <p>{t("routes.systemNone")}</p>
      ) : (
        <table className="route-table">
          <thead>
            <tr>
              <th className="num">{t("routes.systemPrio")}</th>
              <th>{t("routes.systemSelector")}</th>
              <th>{t("routes.systemAction")}</th>
              <th>{t("routes.owner")}</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((rule, i) => (
              <tr key={i}>
                <td className="num mono">
                  {rule.family === "ipv6" ? "IPv6 " : ""}
                  {rule.priority}
                </td>
                <td className="mono">{ruleSelector(rule)}</td>
                <td className="mono">{ruleAction(rule)}</td>
                <td>
                  {rule.managed && (
                    <span className="badge badge-managed">
                      {t("routes.systemManaged")}
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h3 className="system-tables-heading">{t("routes.systemRoutes")}</h3>
      {groups.length === 0 ? (
        <p>{t("routes.systemNone")}</p>
      ) : (
        groups.map(([table, routes]) => (
          <div key={table} className="system-table-group">
            <h4 className="system-tables-heading">
              {t("routes.tableN", { n: tableLabel(table) })}
            </h4>
            <table className="route-table">
              <thead>
                <tr>
                  <th>{t("routes.destination")}</th>
                  <th>{t("routes.gateway")}</th>
                  <th>{t("routes.interfaceCol")}</th>
                  <th className="num">{t("routes.metricCol")}</th>
                  <th>{t("routes.systemDetails")}</th>
                  <th>{t("routes.owner")}</th>
                </tr>
              </thead>
              <tbody>
                {routes.map((route, i) => (
                  <tr key={i}>
                    <td className="mono">
                      {route.family === "ipv6" ? "IPv6 " : ""}
                      {routeDestination(route)}
                    </td>
                    <td className="mono">
                      {route.nexthops.length > 0
                        ? route.nexthops.map((hop, j) => (
                            <div key={j}>
                              {hop.gateway ?? "—"} dev{" "}
                              {hop.interfaceName ?? `if${hop.interfaceIndex}`}
                              {hop.weight > 0 ? ` weight ${hop.weight}` : ""}
                            </div>
                          ))
                        : (route.gateway ?? "—")}
                    </td>
                    <td>
                      {route.interfaceName ??
                        (route.interfaceIndex != null
                          ? `if${route.interfaceIndex}`
                          : "—")}
                    </td>
                    <td className="num">{route.metric ?? "—"}</td>
                    <td className="mono system-route-details">
                      {routeDetails(route)}
                    </td>
                    <td>
                      {route.managed && (
                        <span className="badge badge-managed">
                          {t("routes.systemManaged")}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))
      )}
    </section>
  );
}
