import { useEffect, useState } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { TranslationKey, useT } from "../i18n";
import type { DaemonStatus } from "../types";

const DAEMON_STATE_UI: Record<
  DaemonStatus["state"],
  { dot: string; key: TranslationKey }
> = {
  ready: { dot: "state-running", key: "statusbar.state.ready" },
  notRequired: { dot: "state-unknown", key: "statusbar.state.inProcess" },
  notInstalled: { dot: "state-unknown", key: "statusbar.state.absent" },
  notRunning: { dot: "state-stopped", key: "statusbar.state.stopped" },
  incompatible: { dot: "state-failed", key: "statusbar.state.incompatible" },
  error: { dot: "state-failed", key: "statusbar.state.error" },
};

interface StatusBarProps {
  activeCount: number;
}

export default function StatusBar({ activeCount }: StatusBarProps) {
  const t = useT();
  const [daemon, setDaemon] = useState<DaemonStatus | null>(null);

  useEffect(() => {
    if (!isTauri()) return;
    const poll = async () => {
      try {
        setDaemon(await invoke<DaemonStatus>("daemon_status"));
      } catch {
        setDaemon(null);
      }
    };
    poll();
    const interval = setInterval(poll, 10000);
    return () => clearInterval(interval);
  }, []);

  const daemonUi = daemon ? DAEMON_STATE_UI[daemon.state] : null;

  return (
    <div className="status-bar">
      {daemon && daemonUi && (
        <span
          className="status-bar-cell"
          title={daemon.message || undefined}
        >
          <span className={`status-dot ${daemonUi.dot}`} />
          {t("statusbar.daemon")}:{" "}
          <span className="status-bar-mono">{t(daemonUi.key)}</span>
        </span>
      )}
      <span className="status-bar-right">
        <span className="status-bar-cell">
          {t("statusbar.active", { count: activeCount })}
        </span>
      </span>
    </div>
  );
}
