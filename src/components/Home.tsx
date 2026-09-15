import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import AddConnectionMenu from "./AddConnectionMenu";
import Page from "./Page";
import ProfileFormModal, {
  newFormState,
  type ProfileFormState,
} from "./ProfileFormModal";
import ImportModal from "./ImportModal";
import Skeleton from "./ui/Skeleton";
import { backendIcon } from "../icons";
import type { Tab } from "./NavRail";
import { NetworkInterface, Profile, TunnelBackend, TunnelStatus } from "../types";

function formatRate(bytesPerSec: number): string {
  if (bytesPerSec < 1024) return `${bytesPerSec.toFixed(0)} B/s`;
  if (bytesPerSec < 1024 * 1024) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
  return `${(bytesPerSec / (1024 * 1024)).toFixed(1)} MB/s`;
}

interface Throughput {
  rxRate: number;
  txRate: number;
}

interface HomeProps {
  onNavigate: (tab: Tab) => void;
}

export default function Home({ onNavigate }: HomeProps) {
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [statuses, setStatuses] = useState<TunnelStatus[]>([]);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [throughput, setThroughput] = useState<Record<number, Throughput>>({});
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<Set<string>>(new Set());
  const [editing, setEditing] = useState<ProfileFormState | null>(null);
  const [formOpen, setFormOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [addMenuOpen, setAddMenuOpen] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const prevStats = useRef<Record<number, { rx: number; tx: number; time: number }>>({});

  const refresh = useCallback(async () => {
    try {
      const [profileData, statusData] = await Promise.all([
        invoke<Profile[]>("get_profiles"),
        invoke<TunnelStatus[]>("get_tunnel_statuses"),
      ]);
      setProfiles(profileData);
      setStatuses(statusData);
    } catch {
      // keep last known state on poll failure
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    const interval = setInterval(refresh, 2000);
    return () => clearInterval(interval);
  }, [refresh]);

  useEffect(() => {
    const poll = async () => {
      try {
        const data = await invoke<NetworkInterface[]>("get_interfaces");
        setInterfaces(data);
        const now = Date.now();
        const next: Record<number, Throughput> = {};
        for (const iface of data) {
          if (iface.rxBytes === null || iface.txBytes === null) continue;
          const prev = prevStats.current[iface.ifIndex];
          if (prev) {
            const dt = (now - prev.time) / 1000;
            if (dt > 0) {
              next[iface.ifIndex] = {
                rxRate: Math.max(0, (iface.rxBytes - prev.rx) / dt),
                txRate: Math.max(0, (iface.txBytes - prev.tx) / dt),
              };
            }
          }
          prevStats.current[iface.ifIndex] = {
            rx: iface.rxBytes,
            tx: iface.txBytes,
            time: now,
          };
        }
        setThroughput(next);
      } catch {
        // ignore polling errors
      }
    };
    poll();
    const interval = setInterval(poll, 1000);
    return () => clearInterval(interval);
  }, []);

  const statusFor = (id: string): TunnelStatus =>
    statuses.find((s) => s.profileId === id) ?? {
      profileId: id,
      state: "stopped",
      message: null,
    };

  const running = profiles.filter((p) => statusFor(p.id).state === "running");

  const rateFor = (profile: Profile): Throughput | null => {
    const iface = interfaces.find(
      (i) => i.name === profile.interfaceName || i.friendlyName === profile.interfaceName,
    );
    if (!iface) return null;
    return throughput[iface.ifIndex] ?? null;
  };

  const totalRate = running.reduce(
    (acc, p) => {
      const r = rateFor(p);
      if (r) {
        acc.rx += r.rxRate;
        acc.tx += r.txRate;
      }
      return acc;
    },
    { rx: 0, tx: 0 },
  );

  const onDisconnect = async (profile: Profile) => {
    setBusy((prev) => new Set(prev).add(profile.id));
    try {
      await invoke("disconnect_profile", { id: profile.id });
      await refresh();
    } catch (err) {
      setNotice(String(err));
    } finally {
      setBusy((prev) => {
        const next = new Set(prev);
        next.delete(profile.id);
        return next;
      });
    }
  };

  const openNew = (backend?: TunnelBackend) => {
    setEditing(newFormState(backend));
    setFormOpen(true);
  };

  const handleChooseImport = () => {
    setAddMenuOpen(false);
    setImportOpen(true);
  };

  const handleChooseBackend = (backend: TunnelBackend) => {
    setAddMenuOpen(false);
    openNew(backend);
  };

  if (loading) {
    return (
      <Page width="narrow">
        <div className="status-strip">
          <Skeleton width="12px" height="12px" radius="50%" />
          <div className="status-strip-text">
            <Skeleton width="160px" height="1.05rem" />
          </div>
        </div>
        <section>
          <h2>Active now</h2>
          <div className="active-now-list">
            <div className="active-now-card">
              <Skeleton width="30px" height="30px" radius="50%" />
              <div className="active-now-info">
                <Skeleton width="120px" height="0.88rem" />
                <Skeleton width="80px" height="0.75rem" />
              </div>
            </div>
          </div>
        </section>
      </Page>
    );
  }

  return (
    <Page width="narrow">
      <div className="status-strip">
        <span className={`status-strip-indicator ${running.length > 0 ? "active" : ""}`} />
        <div className="status-strip-text">
          <span className="status-strip-title">
            {running.length === 0
              ? "All disconnected"
              : `${running.length} tunnel${running.length === 1 ? "" : "s"} active`}
          </span>
          {running.length > 0 && (
            <span className="status-strip-sub">
              ↓ {formatRate(totalRate.rx)} · ↑ {formatRate(totalRate.tx)}
            </span>
          )}
        </div>
      </div>

      {notice && (
        <div className="runtime-notice">
          <span>{notice}</span>
          <button type="button" onClick={() => setNotice(null)}>
            Dismiss
          </button>
        </div>
      )}

      <section>
        <h2>Active now</h2>
        {running.length === 0 ? (
          <p className="empty-state">
            No tunnels are running.{" "}
            <button type="button" className="link-btn" onClick={() => onNavigate("connections")}>
              Open Connections
            </button>{" "}
            to start one.
          </p>
        ) : (
          <div className="active-now-list">
            {running.map((profile) => {
              const rate = rateFor(profile);
              return (
                <div key={profile.id} className="active-now-card">
                  <span className={`backend-avatar backend-avatar-${profile.backend}`}>
                    {backendIcon(profile.backend, 16)}
                  </span>
                  <div className="active-now-info">
                    <span className="active-now-name">{profile.name}</span>
                    <span className="active-now-meta">
                      {rate
                        ? `↓ ${formatRate(rate.rxRate)} · ↑ ${formatRate(rate.txRate)}`
                        : profile.interfaceName}
                    </span>
                  </div>
                  <button
                    type="button"
                    className="active-now-disconnect"
                    onClick={() => onDisconnect(profile)}
                    disabled={busy.has(profile.id)}
                    title="Disconnect"
                  >
                    Disconnect
                  </button>
                </div>
              );
            })}
          </div>
        )}
      </section>

      <section>
        <h2>Quick actions</h2>
        <div className="quick-actions">
          <button
            type="button"
            className="quick-action-btn"
            onClick={() => setAddMenuOpen(true)}
          >
            + Add connection
          </button>
          <button type="button" className="quick-action-btn" onClick={() => setImportOpen(true)}>
            Import…
          </button>
        </div>
      </section>

      <section>
        <h2>Advanced</h2>
        <div className="advanced-shortcuts">
          <button
            type="button"
            className="advanced-shortcut-card"
            onClick={() => onNavigate("network")}
          >
            <span className="advanced-shortcut-title">Network</span>
            <span className="advanced-shortcut-desc">
              Inspect adapters, addresses, and live throughput.
            </span>
          </button>
          <button
            type="button"
            className="advanced-shortcut-card"
            onClick={() => onNavigate("routes")}
          >
            <span className="advanced-shortcut-title">Routes</span>
            <span className="advanced-shortcut-desc">
              Diagnose routing conflicts and traffic flow.
            </span>
          </button>
        </div>
      </section>

      <ProfileFormModal
        open={formOpen}
        editing={editing}
        interfaces={interfaces}
        onClose={() => {
          setFormOpen(false);
          setEditing(null);
        }}
        onSaved={() => {
          setFormOpen(false);
          setEditing(null);
          void refresh();
          onNavigate("connections");
        }}
        onError={(message) => setNotice(message)}
      />

      <ImportModal
        open={importOpen}
        onClose={() => setImportOpen(false)}
        onImported={() => {
          setImportOpen(false);
          void refresh();
          onNavigate("connections");
        }}
        onError={(message) => setNotice(message)}
      />

      <AddConnectionMenu
        open={addMenuOpen}
        onClose={() => setAddMenuOpen(false)}
        onChooseImport={handleChooseImport}
        onChooseBackend={handleChooseBackend}
      />
    </Page>
  );
}
