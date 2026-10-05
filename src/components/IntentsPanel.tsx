import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { confirm } from "@tauri-apps/plugin-dialog";
import {
  ExplainStatus,
  NetIntentListResult,
  NetIntentSetParams,
  NetIntentView,
  NetTablesResult,
  NetworkInterface,
  Profile,
} from "../types";
import {
  analyzeIntents,
  IntentSuggestion,
  uncoveredEndpointIntents,
} from "../intentDoctor";
import { useT } from "../i18n";
import { useToast } from "./ui/Toast";
import Modal from "./Modal";
import { PlusIcon } from "../icons";

const STATUS_CLASS: Record<ExplainStatus, string> = {
  effective: "state-up",
  active: "state-up",
  deferred: "state-deferred",
  conflicted: "state-down",
  missing: "state-missing",
  disabled: "state-disabled",
};

/** What the rule captures: hand-picked prefixes or default traffic. */
type Scope = "networks" | "all";

const ALL_V4_DESTINATIONS = "0.0.0.0/1 128.0.0.0/1";

interface IntentDraft {
  id: string;
  scope: Scope;
  destinations: string;
  /** `direct` or an interface name. */
  path: string;
  metric: string;
  /** Preserved on edit — absent in a fresh draft (defaults to on). */
  enabled?: boolean;
  /** Set when editing an existing intent — the id is the identity. */
  editing: boolean;
}

const EMPTY_DRAFT: IntentDraft = {
  id: "",
  scope: "networks",
  destinations: "",
  path: "direct",
  metric: "",
  editing: false,
};

function pathLabel(intent: NetIntentView): string {
  return intent.path.kind === "direct"
    ? "direct"
    : (intent.path.interface ?? "?");
}

function slug(text: string): string {
  return (
    text
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, "-")
      .replace(/^-+|-+$/g, "") || "path"
  );
}

/** "Which destinations go through which path" — the user-facing routing
 *  rules the daemon enforces and re-arms across restarts. */
export default function IntentsPanel() {
  const t = useT();
  const toast = useToast();
  const [intents, setIntents] = useState<NetIntentView[] | null>(null);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [suggestions, setSuggestions] = useState<IntentSuggestion[]>([]);
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());
  const [ifaces, setIfaces] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [draft, setDraft] = useState<IntentDraft | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [result, tables, interfaces, profiles] = await Promise.all([
        invoke<NetIntentListResult>("net_intent_list"),
        invoke<NetTablesResult>("get_net_tables").catch(() => null),
        invoke<NetworkInterface[]>("get_interfaces").catch(() => []),
        invoke<Profile[]>("get_profiles").catch(() => []),
      ]);
      setIntents(result.intents);
      setProfiles(profiles);
      setSuggestions(
        analyzeIntents({
          intents: result.intents,
          routes: tables?.routes ?? [],
          interfaces,
          profiles,
        }),
      );
      if (tables) {
        setIfaces(
          [
            ...new Set(
              tables.routes.flatMap((route) =>
                route.interfaceName ? [route.interfaceName] : [],
              ),
            ),
          ].sort(),
        );
      }
      setError(null);
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

  const save = async () => {
    if (!draft) return;
    setSaving(true);
    setFormError(null);
    try {
      const destinations =
        draft.scope === "all"
          ? ALL_V4_DESTINATIONS.split(" ")
          : draft.destinations
              .split(/[\s,;]+/)
              .map((item) => item.trim())
              .filter(Boolean);
      const path = draft.path.trim();
      const id =
        draft.id.trim() ||
        (path === "direct" || path === "" ? `via-uplink` : `via-${slug(path)}`);
      if (destinations.length === 0) {
        throw new Error(t("intents.required"));
      }
      const metric = draft.metric.trim();
      const metricNum = metric === "" ? undefined : Number(metric);
      if (
        metricNum !== undefined &&
        (!Number.isInteger(metricNum) || metricNum < 0)
      ) {
        throw new Error(t("intents.badMetric"));
      }
      const params: NetIntentSetParams = {
        id,
        destinations,
        path:
          path === "direct" || path === ""
            ? { kind: "direct" }
            : { kind: "interface", interface: path },
        metric: metricNum,
        enabled: draft.editing ? draft.enabled : undefined,
      };
      await invoke("net_intent_set", { params });
      let bypassed = 0;
      if (draft.scope === "all" && params.path.kind === "interface") {
        for (const fix of uncoveredEndpointIntents(
          profiles,
          intents ?? [],
          params.path.interface ?? "uplink",
          [params.id],
        )) {
          await invoke("net_intent_set", { params: fix });
          bypassed += fix.destinations.length;
        }
      }
      setDraft(null);
      toast(
        "success",
        bypassed > 0
          ? t("intents.savedWithBypass", { n: bypassed })
          : t("intents.savedToast"),
      );
      await refresh();
    } catch (err) {
      setFormError(String(err));
    } finally {
      setSaving(false);
    }
  };

  const openEdit = (intent: NetIntentView) => {
    setFormError(null);
    setDraft({
      id: intent.id,
      scope: intent.destinations.some(
        (d) => d === "0.0.0.0/1" || d === "128.0.0.0/1" || d === "0.0.0.0/0",
      )
        ? "all"
        : "networks",
      destinations: intent.destinations.join(" "),
      path:
        intent.path.kind === "direct"
          ? "direct"
          : (intent.path.interface ?? ""),
      metric: String(intent.metric),
      enabled: intent.enabled,
      editing: true,
    });
  };

  const toggle = async (intent: NetIntentView) => {
    setBusy(intent.id);
    try {
      const params: NetIntentSetParams = {
        id: intent.id,
        destinations: intent.destinations,
        path: intent.path,
        metric: intent.metric,
        enabled: !intent.enabled,
      };
      await invoke("net_intent_set", { params });
      await refresh();
    } catch (err) {
      toast("error", t("routes.editError", { err: String(err) }));
    } finally {
      setBusy(null);
    }
  };

  const del = async (intent: NetIntentView) => {
    const ok = await confirm(t("intents.delConfirm", { id: intent.id }), {
      title: t("routes.delTitle"),
      kind: "warning",
    });
    if (!ok) return;
    setBusy(intent.id);
    try {
      await invoke("net_intent_del", { id: intent.id });
      toast("success", t("intents.deletedToast"));
      await refresh();
    } catch (err) {
      toast("error", t("routes.editError", { err: String(err) }));
    } finally {
      setBusy(null);
    }
  };

  const applySuggestion = async (suggestion: IntentSuggestion) => {
    setBusy(suggestion.key);
    try {
      for (const fix of suggestion.fixes) {
        await invoke("net_intent_set", { params: fix });
      }
      toast("success", t("intents.savedToast"));
      await refresh();
    } catch (err) {
      toast("error", t("routes.editError", { err: String(err) }));
    } finally {
      setBusy(null);
    }
  };

  const suppressForeign = async (suggestion: IntentSuggestion) => {
    if (!suggestion.foreignRoute) return;
    setBusy(suggestion.key);
    try {
      await invoke("net_route_del", { route: suggestion.foreignRoute });
      toast("success", t("intents.suppressedToast"));
      await refresh();
    } catch (err) {
      toast("error", t("routes.editError", { err: String(err) }));
    } finally {
      setBusy(null);
    }
  };

  const visibleSuggestions = suggestions.filter((s) => !dismissed.has(s.key));
  const canSave =
    !saving &&
    !!draft &&
    (draft.scope === "all" || !!draft.destinations.trim());

  return (
    <section>
      <div className="system-head-row">
        <h3 className="system-tables-heading">{t("intents.title")}</h3>
        <button
          type="button"
          className="btn-sm btn-with-icon"
          onClick={() => {
            setFormError(null);
            setDraft({ ...EMPTY_DRAFT });
          }}
        >
          <PlusIcon size={12} />
          {t("intents.add")}
        </button>
      </div>
      <p className="flow-hint">{t("intents.hint")}</p>

      {visibleSuggestions.length > 0 && (
        <div className="intent-doctor">
          {visibleSuggestions.map((suggestion) => (
            <div key={suggestion.key} className="intent-doctor-card">
              <div className="intent-doctor-text">
                <strong>
                  {suggestion.kind === "endpointViaTunnel"
                    ? t("intents.doctor.endpointTitle", {
                        iface: suggestion.viaInterface ?? "?",
                      })
                    : suggestion.kind === "uncoveredEndpoints"
                      ? t("intents.doctor.uncoveredTitle", {
                          iface: suggestion.viaInterface ?? "?",
                        })
                      : t("intents.doctor.conflictTitle", {
                          id: suggestion.intentId ?? "?",
                        })}
                </strong>
                <span>
                  {suggestion.kind === "conflict"
                    ? t("intents.doctor.conflictDetail", {
                        dest: suggestion.destination ?? "?",
                        via: suggestion.foreignRoute?.interfaceName ?? "?",
                      })
                    : t("intents.doctor.endpointDetail", {
                        ips: suggestion.endpoints.join(", "),
                      })}
                </span>
              </div>
              <div className="intent-doctor-actions">
                {suggestion.kind === "conflict" ? (
                  <button
                    type="button"
                    className="btn-sm"
                    disabled={busy === suggestion.key}
                    onClick={() => suppressForeign(suggestion)}
                  >
                    {t("intents.doctor.suppress")}
                  </button>
                ) : (
                  <button
                    type="button"
                    className="btn-sm btn-primary"
                    disabled={busy === suggestion.key}
                    onClick={() => applySuggestion(suggestion)}
                  >
                    {t("intents.doctor.fix")}
                  </button>
                )}
                <button
                  type="button"
                  className="btn-sm btn-ghost"
                  onClick={() =>
                    setDismissed(new Set([...dismissed, suggestion.key]))
                  }
                >
                  {t("intents.doctor.dismiss")}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {loading ? (
        <p>{t("routes.systemLoading")}</p>
      ) : error ? (
        <p className="error">{t("routes.systemError", { err: error })}</p>
      ) : !intents || intents.length === 0 ? (
        <div className="system-intent-empty">
          <p>{t("intents.empty")}</p>
          <p className="flow-hint">{t("intents.emptySteps")}</p>
        </div>
      ) : (
        <table className="route-table">
          <thead>
            <tr>
              <th>{t("intents.colId")}</th>
              <th>{t("intents.colDestinations")}</th>
              <th>{t("intents.colPath")}</th>
              <th className="num">{t("routes.metricCol")}</th>
              <th>{t("routes.intentStatus")}</th>
              <th>{t("routes.intentDetail")}</th>
              <th aria-label={t("routes.colActions")} />
            </tr>
          </thead>
          <tbody>
            {intents.map((intent) => (
              <tr key={intent.id}>
                <td className="mono">{intent.id}</td>
                <td className="mono system-route-details">
                  {intent.destinations.join(" ")}
                </td>
                <td className="mono">{pathLabel(intent)}</td>
                <td className="num mono">{intent.metric}</td>
                <td>
                  <span
                    className={`state-badge ${STATUS_CLASS[intent.status]}`}
                  >
                    {t(`routes.status.${intent.status}`)}
                  </span>
                </td>
                <td>
                  {intent.detail}
                  {intent.wanted > 0 && (
                    <span className="mono system-route-details">
                      {" "}
                      {intent.installed}/{intent.wanted}
                    </span>
                  )}
                </td>
                <td className="system-actions">
                  <button
                    type="button"
                    className="btn-sm"
                    disabled={busy === intent.id}
                    title={
                      intent.enabled
                        ? t("intents.disable")
                        : t("intents.enable")
                    }
                    onClick={() => toggle(intent)}
                  >
                    {intent.enabled
                      ? t("intents.disable")
                      : t("intents.enable")}
                  </button>
                  <button
                    type="button"
                    className="btn-sm"
                    disabled={busy === intent.id}
                    onClick={() => openEdit(intent)}
                  >
                    {t("intents.edit")}
                  </button>
                  <button
                    type="button"
                    className="btn-sm btn-danger"
                    disabled={busy === intent.id}
                    onClick={() => del(intent)}
                  >
                    {t("common.delete")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <Modal
        open={draft !== null}
        title={draft?.editing ? t("intents.editTitle") : t("intents.addTitle")}
        onClose={() => setDraft(null)}
        footer={
          <>
            <button
              type="button"
              onClick={() => setDraft(null)}
              disabled={saving}
            >
              {t("common.cancel")}
            </button>
            <button
              type="button"
              className="btn-primary"
              onClick={save}
              disabled={!canSave}
            >
              {saving ? t("common.saving") : t("common.save")}
            </button>
          </>
        }
      >
        {draft && (
          <div className="modal-tab-body">
            {formError && <p className="error">{formError}</p>}
            <label>
              {t("intents.fieldScope")}
              <select
                value={draft.scope}
                disabled={draft.editing}
                onChange={(e) =>
                  setDraft({
                    ...draft,
                    scope: e.currentTarget.value as Scope,
                  })
                }
              >
                <option value="networks">{t("intents.scopeNetworks")}</option>
                <option value="all">{t("intents.scopeAll")}</option>
              </select>
            </label>
            {draft.scope === "all" ? (
              <p className="row-hint">{t("intents.scopeAllHint")}</p>
            ) : (
              <label>
                {t("intents.fieldDestinations")}
                <input
                  type="text"
                  className="mono"
                  value={draft.destinations}
                  placeholder="10.0.0.0/8, 192.168.9.0/24"
                  onChange={(e) =>
                    setDraft({ ...draft, destinations: e.currentTarget.value })
                  }
                />
              </label>
            )}
            <label>
              {t("intents.fieldPath")}
              <input
                type="text"
                list="intent-path-options"
                value={draft.path}
                placeholder="direct"
                onChange={(e) =>
                  setDraft({ ...draft, path: e.currentTarget.value })
                }
              />
              <datalist id="intent-path-options">
                <option value="direct">{t("intents.pathDirect")}</option>
                {ifaces.map((name) => (
                  <option key={name} value={name} />
                ))}
              </datalist>
            </label>
            <label>
              {t("intents.fieldId")}
              <input
                type="text"
                value={draft.id}
                autoFocus={!draft.editing}
                disabled={draft.editing}
                placeholder={
                  draft.editing ? undefined : t("intents.fieldIdAuto")
                }
                onChange={(e) =>
                  setDraft({ ...draft, id: e.currentTarget.value })
                }
              />
            </label>
            <label>
              {t("intents.fieldMetric")}
              <input
                type="text"
                inputMode="numeric"
                value={draft.metric}
                placeholder="100"
                onChange={(e) =>
                  setDraft({ ...draft, metric: e.currentTarget.value })
                }
              />
            </label>
            <p className="row-hint">{t("intents.formHint")}</p>
          </div>
        )}
      </Modal>
    </section>
  );
}
