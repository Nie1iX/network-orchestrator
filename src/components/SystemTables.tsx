import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { confirm } from "@tauri-apps/plugin-dialog";
import {
  ExplainEntry,
  ExplainStatus,
  NetDnsProbeResult,
  NetDnsStatusResult,
  NetEditResult,
  NetExplainResult,
  NetRouteAddParams,
  NetRuleAddParams,
  NetTablesResult,
  SystemRoute,
  SystemRule,
} from "../types";
import { useT } from "../i18n";
import { useToast } from "./ui/Toast";
import Modal from "./Modal";
import { PlusIcon, SpinnerIcon } from "../icons";

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
  if (rule.tos) parts.push("tos", `0x${rule.tos.toString(16)}`);
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
  if (route.routeType !== "unicast") parts.push(route.routeType);
  if (route.scope !== "universe") parts.push(`scope ${route.scope}`);
  if (route.protocol !== 0 && !route.managed)
    parts.push(`proto ${route.protocol}`);
  if (route.prefSource) parts.push(`src ${route.prefSource}`);
  return parts.join(" ");
}

function routeSubject(route: SystemRoute): string {
  return `${routeDestination(route)} ${route.gateway ? `via ${route.gateway} ` : ""}dev ${route.interfaceName ?? `if${route.interfaceIndex ?? "?"}`} table ${tableLabel(route.table)}`;
}

function ruleSubject(rule: SystemRule): string {
  return `pref ${rule.priority} ${ruleSelector(rule)} → ${ruleAction(rule)}`;
}

/// A route the user may delete: unicast in an editable table. The kernel
/// local table (255) and unspec (0) are off limits.
function routeEditable(route: SystemRoute): boolean {
  return (
    route.routeType === "unicast" && route.table !== 0 && route.table !== 255
  );
}

const EDITABLE_RULE_ACTIONS = new Set([
  "lookup",
  "goto",
  "nop",
  "blackhole",
  "unreachable",
  "prohibit",
]);

/// A rule the user may delete: not the kernel local rule, a known action.
function ruleEditable(rule: SystemRule): boolean {
  return rule.priority !== 0 && EDITABLE_RULE_ACTIONS.has(rule.action);
}

const STATUS_CLASS: Record<ExplainStatus, string> = {
  effective: "state-up",
  active: "state-up",
  deferred: "state-deferred",
  conflicted: "state-down",
  missing: "state-missing",
  disabled: "state-disabled",
};

function explainBadge(entry: ExplainEntry, t: ReturnType<typeof useT>) {
  const stale = entry.state !== "applied" ? ` · ${t(`routes.state.${entry.state}`)}` : "";
  return (
    <span className={`state-badge ${STATUS_CLASS[entry.status]}`}>
      {t(`routes.status.${entry.status}`)}
      {stale}
    </span>
  );
}

/** `net.explain` output: every journaled intent with its live status. */
function IntentPanel({
  explain,
  t,
}: {
  explain: NetExplainResult | null;
  t: ReturnType<typeof useT>;
}) {
  if (!explain) return null;
  return (
    <>
      <h3 className="system-tables-heading">{t("routes.intent")}</h3>
      {!explain.available ? (
        <p className="runtime-notice">{t("routes.intentUnavailable")}</p>
      ) : explain.entries.length === 0 ? (
        <p className="system-intent-empty">{t("routes.intentEmpty")}</p>
      ) : (
        <table className="route-table">
          <thead>
            <tr>
              <th>{t("routes.intentStatus")}</th>
              <th>{t("routes.owner")}</th>
              <th>{t("routes.intentObject")}</th>
              <th>{t("routes.intentDetail")}</th>
            </tr>
          </thead>
          <tbody>
            {explain.entries.map((entry, i) => (
              <tr key={i}>
                <td>{explainBadge(entry, t)}</td>
                <td className="mono">{entry.owner}</td>
                <td className="mono system-route-details">{entry.subject}</td>
                <td>{entry.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

/** Resolver inventory + a real DNS probe showing the egress path. */
function DnsPanel({
  status,
  hideIpv6,
  t,
}: {
  status: NetDnsStatusResult | null;
  hideIpv6: boolean;
  t: ReturnType<typeof useT>;
}) {
  const toast = useToast();
  const [hostname, setHostname] = useState("");
  const [server, setServer] = useState("");
  const [family, setFamily] = useState<"ipv4" | "ipv6">("ipv4");
  const [probing, setProbing] = useState(false);
  const [result, setResult] = useState<NetDnsProbeResult | null>(null);
  const [probeError, setProbeError] = useState<string | null>(null);

  if (!status) return null;
  const links = status.links.filter(
    (link) => !hideIpv6 || link.servers.some((s) => !s.includes(":")),
  );
  const serverOptions = [
    ...new Set(
      links.flatMap((link) => link.servers).concat(status.resolvConf),
    ),
  ];

  const probe = async () => {
    setProbing(true);
    setProbeError(null);
    setResult(null);
    try {
      setResult(
        await invoke<NetDnsProbeResult>("net_dns_probe", {
          hostname,
          server: server || null,
          family,
        }),
      );
    } catch (err) {
      setProbeError(String(err));
      toast("error", t("dns.probeError", { err: String(err) }));
    } finally {
      setProbing(false);
    }
  };

  return (
    <>
      <h3 className="system-tables-heading">{t("dns.title")}</h3>
      {!status.available && (
        <p className="runtime-notice">{t("dns.unavailable")}</p>
      )}
      {links.length > 0 && (
        <table className="route-table">
          <thead>
            <tr>
              <th>{t("dns.link")}</th>
              <th>{t("dns.servers")}</th>
              <th>{t("dns.current")}</th>
              <th>{t("dns.domains")}</th>
            </tr>
          </thead>
          <tbody>
            {links.map((link) => {
              // A link can carry ~70 zones (tailscale arpa domains): a
              // space-joined blob starves sibling columns down to their
              // min-content. Show the first few; the rest stay in the tooltip.
              const domains = link.domains.map((d) =>
                d.routeOnly ? `~${d.domain}` : d.domain,
              );
              const hidden = domains.length - 4;
              return (
                <tr key={link.interfaceIndex}>
                  <td>
                    {link.interfaceName}
                    {link.defaultRoute && (
                      <span className="badge badge-armed system-badge-gap">
                        {t("dns.defaultRoute")}
                      </span>
                    )}
                  </td>
                  <td className="mono">{link.servers.join(" ") || "—"}</td>
                  <td className="mono">{link.currentServer ?? "—"}</td>
                  <td
                    className="mono system-route-details"
                    title={hidden > 0 ? domains.join(" ") : undefined}
                  >
                    {domains.slice(0, 4).join(" ") || "—"}
                    {hidden > 0 && ` +${hidden}`}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {status.resolvConf.length > 0 && (
        <p className="system-route-details mono dns-resolv">
          resolv.conf: {status.resolvConf.join(" ")}
        </p>
      )}

      <div className="dns-probe">
        <input
          type="text"
          className="dns-probe-host"
          placeholder={t("dns.probeHostPh")}
          value={hostname}
          onChange={(e) => setHostname(e.target.value)}
        />
        <input
          type="text"
          list="dns-server-options"
          placeholder={t("dns.probeAuto")}
          value={server}
          onChange={(e) => setServer(e.target.value)}
        />
        <datalist id="dns-server-options">
          {serverOptions.map((s) => (
            <option key={s} value={s} />
          ))}
        </datalist>
        <select
          value={family}
          onChange={(e) => setFamily(e.target.value as "ipv4" | "ipv6")}
        >
          <option value="ipv4">A</option>
          <option value="ipv6">AAAA</option>
        </select>
        <button
          type="button"
          className="btn-sm btn-with-icon"
          disabled={probing || !hostname.trim()}
          onClick={probe}
        >
          {probing && <SpinnerIcon size={12} className="spin" />}
          {probing ? t("dns.probing") : t("dns.probe")}
        </button>
      </div>
      {probeError && <p className="error">{probeError}</p>}
      {result && (
        <div className="dns-result interface-card">
          <div className="interface-meta">
            <span className="meta-label mono">
              {t("dns.resultServer", { server: result.server })}
            </span>
            {result.interfaceName && (
              <span className="meta-label mono">
                {t("dns.resultPath", {
                  iface: result.interfaceName,
                  src: result.source ?? "?",
                })}
              </span>
            )}
            {result.gateway && (
              <span className="meta-label mono">
                {t("dns.resultGateway", { gw: result.gateway })}
              </span>
            )}
            <span
              className={`state-badge ${result.status === "NOERROR" ? "state-up" : "state-missing"}`}
            >
              {result.status}
            </span>
            <span className="meta-label">
              {t("dns.resultRtt", { ms: result.rttMs })}
            </span>
          </div>
          {result.answers.length > 0 ? (
            <ul className="cond-routes">
              {result.answers.map((answer, i) => (
                <li key={i} className="mono">
                  {answer}
                </li>
              ))}
            </ul>
          ) : (
            <p className="system-intent-empty">{t("dns.noAnswers")}</p>
          )}
          <p className="external-note">{t("dns.probeNote")}</p>
        </div>
      )}
    </>
  );
}

interface RouteDraft {
  destination: string;
  table: string;
  gateway: string;
  interfaceName: string;
  metric: string;
  prefSource: string;
}

const EMPTY_ROUTE: RouteDraft = {
  destination: "",
  table: "",
  gateway: "",
  interfaceName: "",
  metric: "",
  prefSource: "",
};

interface RuleDraft {
  family: "ipv4" | "ipv6";
  priority: string;
  table: string;
  from: string;
  to: string;
  fwmark: string;
  fwmask: string;
  iifname: string;
  oifname: string;
  invert: boolean;
}

const EMPTY_RULE: RuleDraft = {
  family: "ipv4",
  priority: "",
  table: "",
  from: "",
  to: "",
  fwmark: "",
  fwmask: "",
  iifname: "",
  oifname: "",
  invert: false,
};

function parseNum(text: string): number | undefined {
  const trimmed = text.trim();
  if (!trimmed) return undefined;
  const value = trimmed.startsWith("0x") || trimmed.startsWith("0X")
    ? parseInt(trimmed, 16)
    : Number(trimmed);
  if (!Number.isFinite(value) || value < 0 || !Number.isInteger(value)) {
    throw new Error(`invalid number: ${trimmed}`);
  }
  return value;
}

export default function SystemTables({ hideIpv6 }: { hideIpv6: boolean }) {
  const t = useT();
  const toast = useToast();
  const [data, setData] = useState<NetTablesResult | null>(null);
  const [explain, setExplain] = useState<NetExplainResult | null>(null);
  const [dnsStatus, setDnsStatus] = useState<NetDnsStatusResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [routeDraft, setRouteDraft] = useState<RouteDraft | null>(null);
  const [ruleDraft, setRuleDraft] = useState<RuleDraft | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setError(null);
      const [tables, explained, dns] = await Promise.all([
        invoke<NetTablesResult>("get_net_tables"),
        invoke<NetExplainResult>("net_explain").catch(() => null),
        invoke<NetDnsStatusResult>("net_dns_status").catch(() => null),
      ]);
      setData(tables);
      setExplain(explained);
      setDnsStatus(dns);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const handler = () => void refresh();
    window.addEventListener("route-changed", handler);
    return () => window.removeEventListener("route-changed", handler);
  }, [refresh]);

  const afterEdit = async (outcome: NetEditResult["outcome"], subject: string) => {
    toast(
      "info",
      outcome === "suppressed"
        ? t("routes.suppressedToast", { subject })
        : t("routes.deletedToast", { subject }),
    );
    await refresh();
  };

  const delRoute = async (route: SystemRoute) => {
    const subject = routeSubject(route);
    const ok = await confirm(
      route.managed
        ? t("routes.delManagedConfirm", { subject })
        : t("routes.delForeignRouteConfirm", { subject }),
      { title: t("routes.delTitle"), kind: "warning" },
    );
    if (!ok) return;
    const key = `r${route.table}:${route.destination}`;
    setBusy(key);
    try {
      const result = await invoke<NetEditResult>("net_route_del", { route });
      await afterEdit(result.outcome, subject);
    } catch (err) {
      toast("error", t("routes.editError", { err: String(err) }));
    } finally {
      setBusy(null);
    }
  };

  const delRule = async (rule: SystemRule) => {
    const subject = ruleSubject(rule);
    const ok = await confirm(
      rule.managed
        ? t("routes.delManagedConfirm", { subject })
        : t("routes.delForeignRuleConfirm", { subject }),
      { title: t("routes.delTitle"), kind: "warning" },
    );
    if (!ok) return;
    const key = `p${rule.priority}:${rule.family}`;
    setBusy(key);
    try {
      const result = await invoke<NetEditResult>("net_rule_del", { rule });
      await afterEdit(result.outcome, subject);
    } catch (err) {
      toast("error", t("routes.editError", { err: String(err) }));
    } finally {
      setBusy(null);
    }
  };

  const addRoute = async () => {
    if (!routeDraft) return;
    setSaving(true);
    setFormError(null);
    try {
      const params: NetRouteAddParams = {
        destination: routeDraft.destination.trim(),
        table: parseNum(routeDraft.table),
        gateway: routeDraft.gateway.trim() || undefined,
        interfaceName: routeDraft.interfaceName.trim() || undefined,
        metric: parseNum(routeDraft.metric),
        prefSource: routeDraft.prefSource.trim() || undefined,
      };
      await invoke("net_route_add", { params });
      setRouteDraft(null);
      toast("success", t("routes.addedToast"));
      await refresh();
    } catch (err) {
      setFormError(String(err));
    } finally {
      setSaving(false);
    }
  };

  const addRule = async () => {
    if (!ruleDraft) return;
    setSaving(true);
    setFormError(null);
    try {
      const params: NetRuleAddParams = {
        family: ruleDraft.family,
        priority: parseNum(ruleDraft.priority) ?? NaN,
        table: parseNum(ruleDraft.table) ?? NaN,
        from: ruleDraft.from.trim() || undefined,
        to: ruleDraft.to.trim() || undefined,
        fwmark: parseNum(ruleDraft.fwmark),
        fwmask: parseNum(ruleDraft.fwmask),
        iifname: ruleDraft.iifname.trim() || undefined,
        oifname: ruleDraft.oifname.trim() || undefined,
        invert: ruleDraft.invert,
      };
      if (!Number.isFinite(params.priority) || !Number.isFinite(params.table)) {
        throw new Error(t("routes.ruleRequired"));
      }
      await invoke("net_rule_add", { params });
      setRuleDraft(null);
      toast("success", t("routes.addedToast"));
      await refresh();
    } catch (err) {
      setFormError(String(err));
    } finally {
      setSaving(false);
    }
  };

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
  // Every interface name the dump knows — suggestions for the route form.
  const ifaceNames = [
    ...new Set(
      data.routes.flatMap((route) =>
        route.interfaceName ? [route.interfaceName] : [],
      ),
    ),
  ].sort();

  return (
    <section>
      <IntentPanel explain={explain} t={t} />
      <DnsPanel status={dnsStatus} hideIpv6={hideIpv6} t={t} />

      <div className="system-head-row">
        <h3 className="system-tables-heading">{t("routes.systemRules")}</h3>
        <button
          type="button"
          className="btn-sm btn-with-icon"
          onClick={() => {
            setFormError(null);
            setRuleDraft({ ...EMPTY_RULE });
          }}
        >
          <PlusIcon size={12} />
          {t("routes.addRule")}
        </button>
      </div>
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
              <th aria-label={t("routes.colActions")} />
            </tr>
          </thead>
          <tbody>
            {rules.map((rule, i) => {
              const key = `p${rule.priority}:${rule.family}`;
              return (
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
                  <td className="system-actions">
                    {ruleEditable(rule) && (
                      <button
                        type="button"
                        className="btn-sm btn-danger"
                        disabled={busy === key}
                        onClick={() => delRule(rule)}
                      >
                        {t("common.delete")}
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      <div className="system-head-row">
        <h3 className="system-tables-heading">{t("routes.systemRoutes")}</h3>
        <button
          type="button"
          className="btn-sm btn-with-icon"
          onClick={() => {
            setFormError(null);
            setRouteDraft({ ...EMPTY_ROUTE });
          }}
        >
          <PlusIcon size={12} />
          {t("routes.addRoute")}
        </button>
      </div>
      {groups.length === 0 ? (
        <p>{t("routes.systemNone")}</p>
      ) : (
        <table className="route-table">
          <thead>
            <tr>
              <th>{t("routes.field.table")}</th>
              <th>{t("routes.destination")}</th>
              <th>{t("routes.gateway")}</th>
              <th>{t("routes.interfaceCol")}</th>
              <th className="num">{t("routes.metricCol")}</th>
              <th>{t("routes.systemDetails")}</th>
              <th>{t("routes.owner")}</th>
              <th aria-label={t("routes.colActions")} />
            </tr>
          </thead>
          <tbody>
            {groups.map(([table, routes]) =>
              routes.map((route, i) => {
                const key = `r${route.table}:${route.destination}`;
                return (
                  <tr key={`${table}:${i}`}>
                    <td className="mono system-route-details">
                      {tableLabel(table)}
                    </td>
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
                    <td className="system-actions">
                      {routeEditable(route) && (
                        <button
                          type="button"
                          className="btn-sm btn-danger"
                          disabled={busy === key}
                          onClick={() => delRoute(route)}
                        >
                          {t("common.delete")}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              }),
            )}
          </tbody>
        </table>
      )}

      <Modal
        open={routeDraft !== null}
        title={t("routes.addRouteTitle")}
        onClose={() => setRouteDraft(null)}
        footer={
          <>
            <button
              type="button"
              onClick={() => setRouteDraft(null)}
              disabled={saving}
            >
              {t("common.cancel")}
            </button>
            <button
              type="button"
              className="btn-primary"
              onClick={addRoute}
              disabled={saving || !routeDraft?.destination.trim()}
            >
              {saving ? t("common.saving") : t("common.save")}
            </button>
          </>
        }
      >
        {routeDraft && (
          <div className="modal-tab-body">
            {formError && <p className="error">{formError}</p>}
            <label>
              {t("routes.field.destination")}
              <input
                type="text"
                value={routeDraft.destination}
                autoFocus
                placeholder="198.51.100.0/24"
                onChange={(e) =>
                  setRouteDraft({ ...routeDraft, destination: e.target.value })
                }
              />
            </label>
            <label>
              {t("routes.field.iface")}
              <input
                type="text"
                list="system-iface-options"
                value={routeDraft.interfaceName}
                placeholder="enp59s0u2"
                onChange={(e) =>
                  setRouteDraft({ ...routeDraft, interfaceName: e.target.value })
                }
              />
              <datalist id="system-iface-options">
                {ifaceNames.map((name) => (
                  <option key={name} value={name} />
                ))}
              </datalist>
            </label>
            <label>
              {t("routes.field.gateway")}
              <input
                type="text"
                value={routeDraft.gateway}
                placeholder="192.168.1.1"
                onChange={(e) =>
                  setRouteDraft({ ...routeDraft, gateway: e.target.value })
                }
              />
            </label>
            <label>
              {t("routes.field.table")}
              <input
                type="text"
                value={routeDraft.table}
                placeholder="254 · main"
                onChange={(e) =>
                  setRouteDraft({ ...routeDraft, table: e.target.value })
                }
              />
            </label>
            <label>
              {t("routes.field.metric")}
              <input
                type="text"
                value={routeDraft.metric}
                onChange={(e) =>
                  setRouteDraft({ ...routeDraft, metric: e.target.value })
                }
              />
            </label>
            <label>
              {t("routes.field.prefSource")}
              <input
                type="text"
                value={routeDraft.prefSource}
                onChange={(e) =>
                  setRouteDraft({ ...routeDraft, prefSource: e.target.value })
                }
              />
            </label>
          </div>
        )}
      </Modal>

      <Modal
        open={ruleDraft !== null}
        title={t("routes.addRuleTitle")}
        onClose={() => setRuleDraft(null)}
        footer={
          <>
            <button
              type="button"
              onClick={() => setRuleDraft(null)}
              disabled={saving}
            >
              {t("common.cancel")}
            </button>
            <button
              type="button"
              className="btn-primary"
              onClick={addRule}
              disabled={saving || !ruleDraft?.priority.trim()}
            >
              {saving ? t("common.saving") : t("common.save")}
            </button>
          </>
        }
      >
        {ruleDraft && (
          <div className="modal-tab-body">
            {formError && <p className="error">{formError}</p>}
            <div className="system-form-grid">
              <label>
                {t("routes.field.family")}
                <select
                  value={ruleDraft.family}
                  onChange={(e) =>
                    setRuleDraft({
                      ...ruleDraft,
                      family: e.target.value as "ipv4" | "ipv6",
                    })
                  }
                >
                  <option value="ipv4">IPv4</option>
                  <option value="ipv6">IPv6</option>
                </select>
              </label>
              <label>
                {t("routes.field.priority")}
                <input
                  type="text"
                  value={ruleDraft.priority}
                  autoFocus
                  placeholder="1000"
                  onChange={(e) =>
                    setRuleDraft({ ...ruleDraft, priority: e.target.value })
                  }
                />
              </label>
              <label>
                {t("routes.field.table")}
                <input
                  type="text"
                  value={ruleDraft.table}
                  placeholder="100"
                  onChange={(e) =>
                    setRuleDraft({ ...ruleDraft, table: e.target.value })
                  }
                />
              </label>
              <label>
                {t("routes.field.from")}
                <input
                  type="text"
                  value={ruleDraft.from}
                  onChange={(e) =>
                    setRuleDraft({ ...ruleDraft, from: e.target.value })
                  }
                />
              </label>
              <label>
                {t("routes.field.to")}
                <input
                  type="text"
                  value={ruleDraft.to}
                  onChange={(e) =>
                    setRuleDraft({ ...ruleDraft, to: e.target.value })
                  }
                />
              </label>
              <label>
                {t("routes.field.fwmark")}
                <input
                  type="text"
                  value={ruleDraft.fwmark}
                  placeholder="0x1"
                  onChange={(e) =>
                    setRuleDraft({ ...ruleDraft, fwmark: e.target.value })
                  }
                />
              </label>
              <label>
                {t("routes.field.fwmask")}
                <input
                  type="text"
                  value={ruleDraft.fwmask}
                  placeholder="0xffffffff"
                  onChange={(e) =>
                    setRuleDraft({ ...ruleDraft, fwmask: e.target.value })
                  }
                />
              </label>
              <label>
                {t("routes.field.iif")}
                <input
                  type="text"
                  list="system-iface-options"
                  value={ruleDraft.iifname}
                  onChange={(e) =>
                    setRuleDraft({ ...ruleDraft, iifname: e.target.value })
                  }
                />
              </label>
              <label>
                {t("routes.field.oif")}
                <input
                  type="text"
                  list="system-iface-options"
                  value={ruleDraft.oifname}
                  onChange={(e) =>
                    setRuleDraft({ ...ruleDraft, oifname: e.target.value })
                  }
                />
              </label>
            </div>
            <label className="system-check">
              <input
                type="checkbox"
                checked={ruleDraft.invert}
                onChange={(e) =>
                  setRuleDraft({ ...ruleDraft, invert: e.target.checked })
                }
              />
              {t("routes.field.invert")}
            </label>
          </div>
        )}
      </Modal>
    </section>
  );
}
