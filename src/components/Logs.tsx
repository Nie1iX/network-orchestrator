import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import Page from "./Page";
import { LogEvent, LogLevel } from "../types";

const POLL_MS = 2000;
const MAX_RENDERED = 1000;

function formatTime(tsUnix: number): string {
  const d = new Date(tsUnix * 1000);
  const pad = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
}

export default function Logs() {
  const [events, setEvents] = useState<LogEvent[]>([]);
  const [daemonLines, setDaemonLines] = useState<LogEvent[]>([]);
  const [search, setSearch] = useState("");
  const [levelFilter, setLevelFilter] = useState<"all" | LogLevel>("all");
  const [daemonOpen, setDaemonOpen] = useState(false);
  const bottomRef = useRef<HTMLDivElement | null>(null);
  const stickToBottom = useRef(true);

  const refresh = useCallback(async () => {
    try {
      const data = await invoke<LogEvent[]>("get_logs");
      setEvents(data);
    } catch {
      // Log view must never break the UI; a failed fetch just keeps stale data.
    }
  }, []);

  const refreshDaemon = useCallback(async () => {
    try {
      const lines = await invoke<LogEvent[]>("daemon_log_tail", { lines: 200 });
      setDaemonLines(lines);
    } catch (e) {
      setDaemonLines([
        {
          tsUnix: Math.floor(Date.now() / 1000),
          level: "warn",
          source: "app",
          message: `daemon log unavailable: ${e}`,
        },
      ]);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const id = setInterval(() => void refresh(), POLL_MS);
    return () => clearInterval(id);
  }, [refresh]);

  useEffect(() => {
    if (daemonOpen) void refreshDaemon();
  }, [daemonOpen, refreshDaemon]);

  useEffect(() => {
    if (stickToBottom.current) {
      bottomRef.current?.scrollIntoView({ block: "end" });
    }
  }, [events, daemonLines]);

  const query = search.trim().toLowerCase();
  const filtered = events.filter((e) => {
    if (levelFilter !== "all" && e.level !== levelFilter) return false;
    if (query && !e.message.toLowerCase().includes(query)) return false;
    return true;
  });
  const shown = filtered.slice(-MAX_RENDERED);

  const clear = async () => {
    try {
      await invoke("clear_logs");
      setEvents([]);
    } catch {
      // keep the stale list visible
    }
  };

  return (
    <Page width="wide">
      <div className="filter-bar">
        <input
          className="filter-search"
          type="text"
          placeholder="Filter log messages..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select
          className="filter-select"
          value={levelFilter}
          onChange={(e) => setLevelFilter(e.target.value as "all" | LogLevel)}
        >
          <option value="all">All levels</option>
          <option value="info">Info</option>
          <option value="warn">Warnings</option>
          <option value="error">Errors</option>
        </select>
        <button className="btn-sm" onClick={() => void refresh()}>
          Refresh
        </button>
        <button className="btn-sm" onClick={() => void clear()}>
          Clear
        </button>
      </div>

      <div
        className="log-view"
        onScroll={(e) => {
          const el = e.currentTarget;
          stickToBottom.current =
            el.scrollHeight - el.scrollTop - el.clientHeight < 40;
        }}
      >
        {shown.length === 0 ? (
          <div className="log-empty">
            {events.length === 0
              ? "No log entries yet. Connect or disconnect a profile to see activity."
              : "No entries match the current filters."}
          </div>
        ) : (
          shown.map((e, i) => (
            <div key={`${e.tsUnix}-${i}`} className={`log-line log-${e.level}`}>
              <span className="log-ts">{formatTime(e.tsUnix)}</span>
              <span className={`log-level log-level-${e.level}`}>{e.level}</span>
              <span className="log-msg">{e.message}</span>
            </div>
          ))
        )}
        {filtered.length > MAX_RENDERED && (
          <div className="log-empty">
            Showing last {MAX_RENDERED} of {filtered.length} matching entries.
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      <div className="daemon-log">
        <button
          className="filter-btn daemon-log-toggle"
          onClick={() => setDaemonOpen((v) => !v)}
        >
          {daemonOpen ? "Hide daemon log" : "Show daemon log (journald tail)"}
        </button>
        {daemonOpen && (
          <div className="log-view log-view-daemon">
            {daemonLines.map((e, i) => (
              <div key={`d-${e.tsUnix}-${i}`} className={`log-line log-${e.level}`}>
                <span className="log-ts">{formatTime(e.tsUnix)}</span>
                <span className={`log-level log-level-${e.level}`}>{e.level}</span>
                <span className="log-msg">{e.message}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </Page>
  );
}
