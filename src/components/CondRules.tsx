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
import { pluralize, t, TranslationKey, useT } from "../i18n";

const STATE_LABEL_KEYS: Record<ConditionalRuleState, TranslationKey> = {
  active: "cond.stateActive",
  inactive: "cond.stateInactive",
  disabled: "cond.stateDisabled",
  error: "cond.stateError",
};

const STATE_HINT_KEYS: Record<ConditionalRuleState, TranslationKey> = {
  active: "cond.hintActive",
  inactive: "cond.hintInactive",
  disabled: "cond.hintDisabled",
  error: "cond.hintError",
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
      return t("cond.conditionText", { prefix: rule.condition.prefix });
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
    return t("cond.errId");
  }
  if (!draft.name.trim()) {
    return t("cond.errName");
  }
  if (!/^\S+\/\d+$/.test(draft.prefix.trim())) {
    return t("cond.errPrefix");
  }
  const routes: PolicyRoute[] = [];
  for (const route of draft.routes) {
    const destination = route.destination.trim();
    if (!/^\S+\/\d+$/.test(destination)) {
      return t("cond.errDest", { dest: destination || "?" });
    }
    const metric = Number(route.metric);
    if (!Number.isInteger(metric) || metric < 0 || metric > 4_294_967_295) {
      return t("cond.errMetric", { dest: destination });
    }
    const via = route.via.trim();
    routes.push({ destination, metric, via: via ? via : null });
  }
  if (routes.length === 0) {
    return t("cond.errNoRoutes");
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
  const tr = useT();
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
        toast("success", t("cond.toastActive", { name: rule.name, iface: status.matchedInterface ?? "?" }));
      } else if (status.state === "inactive") {
        toast("info", t("cond.toastInactive", { name: rule.name }));
      } else if (status.state === "error") {
        toast("error", t("cond.toastError", { name: rule.name, detail: status.detail ?? t("cond.applyFailed") }));
      } else {
        toast("info", t("cond.toastDisabled", { name: rule.name }));
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
      t("cond.deleteConfirm", { name: rule.name }),
      { title: t("cond.deleteTitle"), kind: "warning" },
    );
    if (!ok) return;
    setBusyId(rule.id);
    try {
      await invoke("remove_conditional_rule", { ruleId: rule.id });
      toast("info", t("cond.toastRemoved", { name: rule.name }));
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
          <h2>{tr("cond.title")}</h2>
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
            {tr("cond.newRule")}
          </button>
        </div>
        <p className="page-subtitle">
          {tr("cond.subtitle")}
        </p>
        {!supported && (
          <p className="runtime-notice">
            {tr("cond.linuxOnly")}
          </p>
        )}
        {error && <p className="error">{tr("cond.loadError", { err: error })}</p>}

        {!loading && supported && entries.length === 0 && !error && (
          <div className="empty-state">
            <ConditionsIcon size={32} />
            <p>{tr("cond.emptyTitle")}</p>
            <p>
              {tr("cond.emptyExampleA")}{" "}
              <span className="mono">10.228.32.0/21</span>{" "}
              {tr("cond.emptyExampleB")}
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
                      title={rule.enabled ? tr("cond.toggleDisable") : tr("cond.toggleEnable")}
                    />
                    <span className="interface-name">{rule.name}</span>
                    <span className="meta-label mono">{rule.id}</span>
                  </div>
                  <span
                    className={`state-badge ${stateClass(status.state)}`}
                    title={tr(STATE_HINT_KEYS[status.state])}
                  >
                    {tr(STATE_LABEL_KEYS[status.state])}
                  </span>
                </div>
                <div className="interface-meta">
                  <span className="meta-label">{conditionText(rule)}</span>
                  {status.matchedInterface && (
                    <span className="meta-label">
                      {tr("cond.onIface", { iface: status.matchedInterface })}
                    </span>
                  )}
                  <span className="meta-label">
                    {tr("cond.installedCount", {
                      applied: status.appliedRoutes,
                      total: rule.routes.length,
                      unit: pluralize(
                        rule.routes.length,
                        ["маршрут", "маршрута", "маршрутов"],
                        ["route", "routes"],
                      ),
                    })}
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
                    {tr("common.edit")}
                  </button>
                  <button
                    type="button"
                    className="btn-sm btn-danger"
                    disabled={busyId === rule.id}
                    onClick={() => remove(rule)}
                  >
                    {tr("common.delete")}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      <Modal
        open={draft !== null}
        title={draft?.editingId ? tr("cond.editTitle") : tr("cond.newTitle")}
        onClose={() => setDraft(null)}
        footer={
          <>
            <button type="button" onClick={() => setDraft(null)} disabled={saving}>
              {tr("common.cancel")}
            </button>
            <button
              type="button"
              className="btn-primary"
              onClick={save}
              disabled={saving}
            >
              {saving ? tr("common.saving") : tr("common.save")}
            </button>
          </>
        }
      >
        {draft && (
          <div className="modal-tab-body">
            {formError && <p className="error">{formError}</p>}
            <label>
              {tr("cond.name")}
              <input
                type="text"
                value={draft.name}
                autoFocus
                placeholder={tr("cond.namePh")}
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
              {tr("cond.id")}
              <input
                type="text"
                className="mono"
                value={draft.editingId ?? draft.id}
                disabled={draft.editingId !== null}
                placeholder={tr("cond.idPh")}
                onChange={(e) => {
                  idTouched.current = true;
                  setDraft((current) =>
                    current && { ...current, id: e.target.value },
                  );
                }}
              />
            </label>
            <label>
              {tr("cond.condPrefix")}
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
              {tr("cond.enabled")}
            </label>
            <div className="cond-route-editor">
              <span className="section-label">{tr("cond.routesWhile")}</span>
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
                    placeholder={tr("cond.metricPh")}
                    title={tr("routes.metricCol")}
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
                    placeholder={tr("cond.viaPh")}
                    title={tr("cond.gwTitle")}
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
                    title={tr("cond.removeRoute")}
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
                {tr("cond.addRoute")}
              </button>
            </div>
          </div>
        )}
      </Modal>
    </Page>
  );
}
