import { tr } from "../i18n";
import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ensureElevation } from "../elevation";
import { RecoveryReport } from "../types";

function RecoveryPrompt() {
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
      setError(
        tr("Could not inspect resources from the previous session: {value0}", { value0: String(String(err)) })
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadReport();
  }, [loadReport]);

  if (dismissed || loading || (report && report.issues.length === 0)) {
    return null;
  }

  if (!report) {
    return (
      <div className="recovery-overlay">
        <div className="recovery-panel">
          <h2>{tr("Recovery check failed")}</h2>
          {error && <p className="error">{tr(error)}</p>}
          <div className="recovery-actions">
            <button onClick={() => setDismissed(true)}>{tr("Keep for now")}</button>
            <button className="recovery-cleanup-btn" onClick={loadReport}>
              {tr("Retry")}</button>
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
        !(await ensureElevation(
          tr("Cleaning up resources from the previous session")
        ))
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
        <h2>{tr("Recovery required")}</h2>
        <p>
          {tr("The previous session left behind resources owned by this application. No changes were made automatically.")}</p>
        <ul className="recovery-issues">
          {report.issues.map((issue, index) => (
            <li key={index}>{issue.message}</li>
          ))}
        </ul>
        {error && <p className="error">{tr(error)}</p>}
        <div className="recovery-actions">
          <button onClick={() => setDismissed(true)} disabled={busy}>
            {tr("Keep for now")}</button>
          <button
            className="recovery-cleanup-btn"
            onClick={onCleanup}
            disabled={busy}
          >
            {tr("Clean up")}</button>
        </div>
      </div>
    </div>
  );
}

export default RecoveryPrompt;
