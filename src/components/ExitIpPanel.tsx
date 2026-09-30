import { useState } from "react";
import { invoke, Channel } from "@tauri-apps/api/core";
import { ExitIpEntry } from "../types";
import { useT } from "../i18n";

type ExitIpEvent =
  | { kind: "pending"; names: string[] }
  | { kind: "result"; entry: ExitIpEntry };

/** Queries external IP-echo services through the current system routing.
 * Results stream in per-checker: with a split tunnel up, different checkers
 * may report different exit IPs — live proof the rules classify correctly. */
export default function ExitIpPanel() {
  const [names, setNames] = useState<string[]>([]);
  const [results, setResults] = useState<Record<string, ExitIpEntry>>({});
  const [started, setStarted] = useState(false);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const t = useT();

  const check = async () => {
    setChecking(true);
    setError(null);
    setResults({});
    setStarted(true);
    const channel = new Channel<ExitIpEvent>();
    channel.onmessage = (event) => {
      if (event.kind === "pending") {
        setNames(event.names);
      } else {
        setResults((prev) => ({ ...prev, [event.entry.name]: event.entry }));
      }
    };
    try {
      await invoke("check_exit_ips", { onEvent: channel });
    } catch (err) {
      setError(String(err));
    } finally {
      setChecking(false);
    }
  };

  const ips = names
    .map((name) => results[name]?.ip)
    .filter((ip): ip is string => !!ip);
  const distinct = new Set(ips);
  const done = names.length > 0 && ips.length + names.filter((n) => results[n]?.error).length === names.length;

  return (
    <div className="exit-ip-panel">
      <div className="interface-row">
        <span className="row-label">{t("exitIp.label")}</span>
        <span className="row-value">
          {done && (
            <span className="exit-ip-summary">
              {distinct.size === 0
                ? t("exitIp.noResponse")
                : distinct.size === 1
                  ? t("exitIp.oneExit", { ip: [...distinct][0] })
                  : t("exitIp.multiExit", { count: distinct.size })}
            </span>
          )}
          <button
            type="button"
            className="filter-btn"
            onClick={check}
            disabled={checking}
          >
            {checking
              ? t("exitIp.checking")
              : started
                ? t("exitIp.recheck")
                : t("exitIp.check")}
          </button>
        </span>
      </div>
      {error && <p className="error">{error}</p>}
      {names.length > 0 && (
        <div className="exit-ip-grid">
          {names.map((name) => {
            const entry = results[name];
            return (
              <div key={name} className="interface-row">
                <span className="row-label">{name}</span>
                <span className="row-value mono">
                  {!entry
                    ? "…"
                    : entry.ip
                      ? `${entry.ip}${entry.country ? ` ${entry.country}` : ""}`
                      : entry.error ?? "…"}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
