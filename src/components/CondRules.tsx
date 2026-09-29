import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { confirm } from "@tauri-apps/plugin-dialog";
import {
  CondRulesListResult,
  CondRulesPutResult,
  ConditionalRuleEntry,
  ConditionalRouteRule,
  ConditionalRuleState,
  PlatformCapabilities,
  PolicyRoute,
} from "../types";
import { ConditionsIcon, PlusIcon, CloseIcon } from "../icons";
import Modal from "./Modal";
import Page from "./Page";
import ToggleSwitch from "./ui/ToggleSwitch";
import { useToast } from "./ui/Toast";

const STATE_LABELS: Record<ConditionalRuleState, string> = {
  active: "Active",
  inactive: "Inactive",
  disabled: "Disabled",
  error: "Error",
};

const STATE_HINTS: Record<ConditionalRuleState, string> = {
  active: "Condition holds; routes are installed",
  inactive: "Outside the conditioned network; nothing is installed",
  disabled: "Rule is switched off",
  error: "Last apply or remove failed",
};

function stateClass(state: ConditionalRuleState): string {
  switch (state) {
    case "active": return "state-up";
    case "inactive": return "state-unknown";
    case "disabled": return "state-unknown";
    case "error": return "state-down";
  }
}

function conditionText(rule: ConditionalRouteRule): string {
  switch (rule.condition.kind) {
    case "interfaceAddressIn":
      return `Interface address inside ${rule.condition.prefix}`;
  }
}

function routeText(route: PolicyRoute): string {
  const via = route.via ? ` via ${route.via}` : "";
  return `${route.destination} metric ${route.metric}${via}`;
}

function slugify(name: string): string {
  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/^[^a-z0-9]+/, "")
    .slice(0, 48);
  return slug;
}

interface DraftRoute {
  destination: string;
  metric: string;
  via: string;
}

interface Draft {
  id: string;
  name: string;
  enabled: boolean;
  prefix: string;
  routes: DraftRoute[];
  /** Original rule id when editing; new rules derive the id from the name. */
  editingId: string | null;
}

function draftOf(rule?: ConditionalRouteRule): Draft {
  return {
    id: rule?.id ?? "",
    name: rule?.name ?? "",
    enabled: rule?.enabled ?? true,
    prefix:
      rule?.condition.kind === "interfaceAddressIn" ? rule.condition.prefix : "",
    routes: (rule?.routes ?? []).map((route) => ({
      destination: route.destination,
      metric: String(route.metric),
      via: route.via ?? "",
    })),
    editingId: rule?.id ?? null,
  };
}

function draftToRule(draft: Draft): ConditionalRouteRule | string {
  const id = draft.editingId ?? (draft.id.trim() || slugify(draft.name));
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,47}$/.test(id)) {
    return "Id must start with a letter or digit and use [a-z0-9._-] only";
  }
  if (!draft.name.trim()) {
    return "Name is required";
  }
  if (!/^\S+\/\d+$/.test(draft.prefix.trim())) {
    return "Condition prefix must look like 10.228.32.0/21";
  }
  const routes: PolicyRoute[] = [];
  for (const route of draft.routes) {
    const destination = route.destination.trim();
    if (!/^\S+\/\d+$/.test(destination)) {
      return `Route destination "${destination || "?"}" must look like 10.99.0.0/24`;
    }
    const metric = Number(route.metric);
    if (!Number.isInteger(metric) || metric < 0 || metric > 4_294_967_295) {
      return `Route metric for ${destination} must be a number`;
    }
    const via = route.via.trim();
    routes.push({ destination, metric, via: via ? via : null });
  }
  if (routes.length === 0) {
    return "Add at least one route";
  }
  return {
    id,
    name: draft.name.trim(),
    enabled: draft.enabled,
    condition: { kind: "interfaceAddressIn", prefix: draft.prefix.trim() },
    routes,
  };
}

export default function CondRules() {
  const toast = useToast();
  const [entries, setEntries] = useState<ConditionalRuleEntry[]>([]);
  const [caps, setCaps] = useState<PlatformCapabilities | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const idTouched = useRef(false);

  const refresh = useCallback(async () => {
    try {
      const data = await invoke<CondRulesListResult>("list_conditional_rules");
      setEntries(data.rules);
      setError(null);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    invoke<PlatformCapabilities>("get_platform_capabilities")
      .then(setCaps)
      .catch(() => setCaps(null));
    refresh();
    const handler = () => refresh();
    window.addEventListener("route-changed", handler);
    const interval = setInterval(refresh, 5000);
    return () => {
      window.removeEventListener("route-changed", handler);
      clearInterval(interval);
    };
  }, [refresh]);

  const save = async () => {
    if (!draft) return;
    const rule = draftToRule(draft);
    if (typeof rule === "string") {
      setFormError(rule);
      return;
    }
    setSaving(true);
    setFormError(null);
    try {
      const result = await invoke<CondRulesPutResult>("put_conditional_rule", {
        rule,
      });
      setDraft(null);
      const status = result.status;
      if (status.state === "active") {
        toast("success", `${rule.name}: active on ${status.matchedInterface ?? "?"}`);
      } else if (status.state === "inactive") {
        toast("info", `${rule.name}: stored, waiting for the conditioned network`);
      } else if (status.state === "error") {
        toast("error", `${rule.name}: ${status.detail ?? "apply failed"}`);
      } else {
        toast("info", `${rule.name}: stored (disabled)`);
      }
      await refresh();
    } catch (err) {
      setFormError(String(err));
    } finally {
      setSaving(false);
    }
  };

  const remove = async (rule: ConditionalRouteRule) => {
    const ok = await confirm(
      `Delete rule "${rule.name}"? Its routes are withdrawn immediately.`,
      { title: "Delete conditional rule", kind: "warning" },
    );
    if (!ok) return;
    setBusyId(rule.id);
    try {
      await invoke("remove_conditional_rule", { ruleId: rule.id });
      toast("info", `${rule.name}: removed`);
      await refresh();
    } catch (err) {
      toast("error", String(err));
    } finally {
      setBusyId(null);
    }
  };

  const toggle = async (entry: ConditionalRuleEntry) => {
    const rule = { ...entry.rule, enabled: !entry.rule.enabled };
    setBusyId(rule.id);
    try {
      await invoke<CondRulesPutResult>("put_conditional_rule", { rule });
      await refresh();
    } catch (err) {
      toast("error", String(err));
    } finally {
      setBusyId(null);
    }
  };

  const supported = caps === null || caps.os === "linux";

  return (
    <Page width="wide">
      <section>
        <div className="page-head">
          <h2>Conditional rules</h2>
          <button
            type="button"
            className="btn-primary btn-with-icon"
            onClick={() => {
              idTouched.current = false;
              setFormError(null);
              setDraft(draftOf());
            }}
            disabled={!supported}
          >
            <PlusIcon size={14} />
            New rule
          </button>
        </div>
        <p className="page-subtitle">
          Routes that exist only while a condition holds — e.g. "on the office
          LAN, reach internal subnets directly". The daemon evaluates them
          against local interface addresses and installs or withdraws routes
          automatically.
        </p>
        {!supported && (
          <p className="runtime-notice">
            Conditional rules are available on Linux only — they are evaluated
            by the privileged daemon.
          </p>
        )}
        {error && <p className="error">Error loading rules: {error}</p>}

        {!loading && supported && entries.length === 0 && !error && (
          <div className="empty-state">
            <ConditionsIcon size={32} />
            <p>No conditional rules yet.</p>
            <p>
              Example: prefix <span className="mono">10.228.32.0/21</span> marks
              the office LAN — while an uplink holds an address from it, the
              rule's routes are installed; away from the office they disappear.
            </p>
          </div>
        )}

        <div className="cond-list">
          {entries.map((entry) => {
            const { rule, status } = entry;
            return (
              <div key={rule.id} className="interface-card cond-card">
                <div className="interface-header">
                  <div className="interface-title">
                    <ToggleSwitch
                      checked={rule.enabled}
                      busy={busyId === rule.id}
                      onChange={() => toggle(entry)}
                      title={rule.enabled ? "Disable rule" : "Enable rule"}
                    />
                    <span className="interface-name">{rule.name}</span>
                    <span className="meta-label mono">{rule.id}</span>
                  </div>
                  <span
                    className={`state-badge ${stateClass(status.state)}`}
                    title={STATE_HINTS[status.state]}
                  >
                    {STATE_LABELS[status.state]}
                  </span>
                </div>
                <div className="interface-meta">
                  <span className="meta-label">{conditionText(rule)}</span>
                  {status.matchedInterface && (
                    <span className="meta-label">
                      on {status.matchedInterface}
                    </span>
                  )}
                  <span className="meta-label">
                    {status.appliedRoutes}/{rule.routes.length} route
                    {rule.routes.length === 1 ? "" : "s"} installed
                  </span>
                </div>
                {status.detail && (
                  <p className="error cond-error">{status.detail}</p>
                )}
                <ul className="cond-routes">
                  {rule.routes.map((route, i) => (
                    <li key={i} className="mono">
                      {routeText(route)}
                    </li>
                  ))}
                </ul>
                <div className="cond-actions">
                  <button
                    type="button"
                    className="btn-sm"
                    onClick={() => {
                      idTouched.current = true;
                      setFormError(null);
                      setDraft(draftOf(rule));
                    }}
                  >
                    Edit
                  </button>
                  <button
                    type="button"
                    className="btn-sm btn-danger"
                    disabled={busyId === rule.id}
                    onClick={() => remove(rule)}
                  >
                    Delete
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      <Modal
        open={draft !== null}
        title={draft?.editingId ? "Edit conditional rule" : "New conditional rule"}
        onClose={() => setDraft(null)}
        footer={
          <>
            <button type="button" onClick={() => setDraft(null)} disabled={saving}>
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
        {draft && (
          <div className="modal-tab-body">
            {formError && <p className="error">{formError}</p>}
            <label>
              Name
              <input
                type="text"
                value={draft.name}
                autoFocus
                placeholder="Office LAN direct"
                onChange={(e) => {
                  const name = e.target.value;
                  setDraft((current) =>
                    current && {
                      ...current,
                      name,
                      id:
                        current.editingId || idTouched.current
                          ? current.id
                          : slugify(name),
                    },
                  );
                }}
              />
            </label>
            <label>
              Id
              <input
                type="text"
                className="mono"
                value={draft.editingId ?? draft.id}
                disabled={draft.editingId !== null}
                placeholder="office-lan"
                onChange={(e) => {
                  idTouched.current = true;
                  setDraft((current) =>
                    current && { ...current, id: e.target.value },
                  );
                }}
              />
            </label>
            <label>
              Condition — uplink address inside prefix
              <input
                type="text"
                className="mono"
                value={draft.prefix}
                placeholder="10.228.32.0/21"
                onChange={(e) =>
                  setDraft((current) =>
                    current && { ...current, prefix: e.target.value },
                  )
                }
              />
            </label>
            <label className="cond-enabled">
              <input
                type="checkbox"
                checked={draft.enabled}
                onChange={(e) =>
                  setDraft((current) =>
                    current && { ...current, enabled: e.target.checked },
                  )
                }
              />
              Enabled
            </label>
            <div className="cond-route-editor">
              <span className="section-label">Routes while the condition holds</span>
              {draft.routes.map((route, i) => (
                <div key={i} className="cond-route-row">
                  <input
                    type="text"
                    className="mono"
                    value={route.destination}
                    placeholder="10.99.0.0/24"
                    onChange={(e) =>
                      setDraft((current) => {
                        if (!current) return current;
                        const routes = [...current.routes];
                        routes[i] = { ...routes[i], destination: e.target.value };
                        return { ...current, routes };
                      })
                    }
                  />
                  <input
                    type="text"
                    className="mono"
                    value={route.metric}
                    placeholder="metric"
                    title="Metric"
                    onChange={(e) =>
                      setDraft((current) => {
                        if (!current) return current;
                        const routes = [...current.routes];
                        routes[i] = { ...routes[i], metric: e.target.value };
                        return { ...current, routes };
                      })
                    }
                  />
                  <input
                    type="text"
                    className="mono"
                    value={route.via}
                    placeholder="via (optional)"
                    title="Gateway"
                    onChange={(e) =>
                      setDraft((current) => {
                        if (!current) return current;
                        const routes = [...current.routes];
                        routes[i] = { ...routes[i], via: e.target.value };
                        return { ...current, routes };
                      })
                    }
                  />
                  <button
                    type="button"
                    className="btn-sm"
                    title="Remove route"
                    onClick={() =>
                      setDraft((current) =>
                        current && {
                          ...current,
                          routes: current.routes.filter((_, j) => j !== i),
                        },
                      )
                    }
                  >
                    <CloseIcon size={14} />
                  </button>
                </div>
              ))}
              <button
                type="button"
                className="btn-sm btn-with-icon"
                onClick={() =>
                  setDraft((current) =>
                    current && {
                      ...current,
                      routes: [
                        ...current.routes,
                        { destination: "", metric: "5", via: "" },
                      ],
                    },
                  )
                }
              >
                <PlusIcon size={12} />
                Add route
              </button>
            </div>
          </div>
        )}
      </Modal>
    </Page>
  );
}
