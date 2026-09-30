import { useCallback, useEffect, useState } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { ensureElevation } from "../elevation";
import { RecoveryReport } from "../types";
import { useT } from "../i18n";

function RecoveryPrompt() {
  const t = useT();
  const [report, setReport] = useState<RecoveryReport | null>(null);
  const [dismissed, setDismissed] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadReport = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setReport(await invoke<RecoveryReport>("get_recovery_report"));
    } catch (err) {
      setError(t("recovery.inspectFailed", { err: String(err) }));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    if (!isTauri()) return;
    void loadReport();
  }, [loadReport]);

  if (dismissed || loading || (report && report.issues.length === 0)) {
    return null;
  }

  if (!report) {
    return (
      <div className="recovery-overlay">
        <div className="recovery-panel">
          <h2>{t("recovery.checkFailed")}</h2>
          {error && <p className="error">{error}</p>}
          <div className="recovery-actions">
            <button onClick={() => setDismissed(true)}>
              {t("recovery.keep")}
            </button>
            <button className="btn-primary" onClick={loadReport}>
              {t("common.retry")}
            </button>
          </div>
        </div>
      </div>
    );
  }

  const onCleanup = async () => {
    setBusy(true);
    setError(null);
    try {
      if (
        report.requiresElevation &&
        !(await ensureElevation(t("recovery.elevationReason")))
      ) {
        return;
      }
      const next = await invoke<RecoveryReport>("cleanup_recovery");
      setReport(next);
      if (next.issues.length === 0) setDismissed(true);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="recovery-overlay">
      <div className="recovery-panel">
        <h2>{t("recovery.required")}</h2>
        <p>{t("recovery.explanation")}</p>
        <ul className="recovery-issues">
          {report.issues.map((issue, index) => (
            <li key={index}>{issue.message}</li>
          ))}
        </ul>
        {error && <p className="error">{error}</p>}
        <div className="recovery-actions">
          <button onClick={() => setDismissed(true)} disabled={busy}>
            {t("recovery.keep")}
          </button>
          <button
            className="btn-primary"
            onClick={onCleanup}
            disabled={busy}
          >
            {t("recovery.cleanUp")}
          </button>
        </div>
      </div>
    </div>
  );
}

export default RecoveryPrompt;
