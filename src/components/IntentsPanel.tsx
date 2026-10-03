import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { confirm } from "@tauri-apps/plugin-dialog";
import {
  ExplainStatus,
  NetIntentListResult,
  NetIntentSetParams,
  NetIntentView,
  NetTablesResult,
} from "../types";
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
};

interface IntentDraft {
  id: string;
  destinations: string;
  /** `direct` or an interface name. */
  path: string;
  metric: string;
}

const EMPTY_DRAFT: IntentDraft = {
  id: "",
  destinations: "",
  path: "direct",
  metric: "",
};

function pathLabel(intent: NetIntentView): string {
  return intent.path.kind === "direct"
    ? "direct"
    : (intent.path.interface ?? "?");
}

/** "Which destinations go through which path" — the user-facing routing
 *  rules the daemon enforces and re-arms across restarts. */
export default function IntentsPanel() {
  const t = useT();
  const toast = useToast();
  const [intents, setIntents] = useState<NetIntentView[] | null>(null);
  const [ifaces, setIfaces] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [draft, setDraft] = useState<IntentDraft | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [result, tables] = await Promise.all([
        invoke<NetIntentListResult>("net_intent_list"),
        invoke<NetTablesResult>("get_net_tables").catch(() => null),
      ]);
      setIntents(result.intents);
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
      const destinations = draft.destinations
        .split(/[\s,;]+/)
        .map((item) => item.trim())
        .filter(Boolean);
      if (destinations.length === 0 || !draft.id.trim()) {
        throw new Error(t("intents.required"));
      }
      const path = draft.path.trim();
      const metric = draft.metric.trim();
      const params: NetIntentSetParams = {
        id: draft.id.trim(),
        destinations,
        path:
          path === "direct" || path === ""
            ? { kind: "direct" }
            : { kind: "interface", interface: path },
        metric: metric ? Number(metric) : undefined,
      };
      await invoke("net_intent_set", { params });
      setDraft(null);
      toast("success", t("intents.savedToast"));
      await refresh();
    } catch (err) {
      setFormError(String(err));
    } finally {
      setSaving(false);
    }
  };

  const del = async (intent: NetIntentView) => {
    const ok = await confirm(
      t("intents.delConfirm", { id: intent.id }),
      { title: t("routes.delTitle"), kind: "warning" },
    );
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
      {loading ? (
        <p>{t("routes.systemLoading")}</p>
      ) : error ? (
        <p className="error">{t("routes.systemError", { err: error })}</p>
      ) : !intents || intents.length === 0 ? (
        <p className="system-intent-empty">{t("intents.empty")}</p>
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
        title={t("intents.addTitle")}
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
              disabled={
                saving || !draft?.id.trim() || !draft?.destinations.trim()
              }
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
              {t("intents.fieldId")}
              <input
                type="text"
                value={draft.id}
                autoFocus
                placeholder={t("intents.fieldIdPlaceholder")}
                onChange={(e) =>
                  setDraft({ ...draft, id: e.currentTarget.value })
                }
              />
            </label>
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
