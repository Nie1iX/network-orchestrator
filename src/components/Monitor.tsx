import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ensureElevation, requiresElevation } from "../elevation";
import { backendIcon } from "../icons";
import ExitIpPanel from "./ExitIpPanel";
import Page from "./Page";
import RateText from "./ui/RateText";
import Skeleton from "./ui/Skeleton";
import { useToast } from "./ui/Toast";
import { NetworkInterface, Profile, TunnelStatus } from "../types";
import { pluralize, useT } from "../i18n";

interface Throughput {
  rxRate: number;
  txRate: number;
}

interface Sample {
  rx: number;
  tx: number;
}

const MAX_SAMPLES = 90;
const CHART_W = 600;
const CHART_H = 96;

function ThroughputChart({ samples }: { samples: Sample[] }) {
  const t = useT();
  if (samples.length < 2) {
    return <div className="chart-empty">{t("monitor.collecting")}</div>;
  }
  const pad = 4;
  const max = Math.max(
    1024,
    ...samples.map((s) => Math.max(s.rx, s.tx)),
  );
  const stepX = (CHART_W - pad * 2) / (MAX_SAMPLES - 1);
  const offset = MAX_SAMPLES - samples.length;
  const points = (key: "rx" | "tx") =>
    samples
      .map((s, i) => {
        const x = pad + (i + offset) * stepX;
        const y = pad + (CHART_H - pad * 2) * (1 - s[key] / max);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");
  return (
    <svg
      viewBox={`0 0 ${CHART_W} ${CHART_H}`}
      className="throughput-chart"
      preserveAspectRatio="none"
      aria-hidden="true"
    >
      <polyline className="chart-tx" points={points("tx")} />
      <polyline className="chart-rx" points={points("rx")} />
    </svg>
  );
}

export default function Monitor() {
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [statuses, setStatuses] = useState<TunnelStatus[]>([]);
  const [throughput, setThroughput] = useState<Record<number, Throughput>>({});
  const [samples, setSamples] = useState<Sample[]>([]);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<Set<string>>(new Set());
  const prevStats = useRef<Record<number, { rx: number; tx: number; time: number }>>({});
  const liveRef = useRef<{ profiles: Profile[]; statuses: TunnelStatus[] }>({
    profiles: [],
    statuses: [],
  });
  const toast = useToast();
  const t = useT();

  useEffect(() => {
    liveRef.current = { profiles, statuses };
  }, [profiles, statuses]);

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
    const interval = setInterval(refresh, 2000);
    const onRouteChanged = () => refresh();
    window.addEventListener("route-changed", onRouteChanged);
    return () => {
      clearInterval(interval);
      window.removeEventListener("route-changed", onRouteChanged);
    };
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

        const { profiles: profs, statuses: stats } = liveRef.current;
        const runningIfaces = new Set(
          profs
            .filter(
              (p) =>
                stats.find((s) => s.profileId === p.id)?.state === "running",
            )
            .flatMap((p) => [p.interfaceName]),
        );
        let rx = 0;
        let tx = 0;
        for (const iface of data) {
          if (
            !runningIfaces.has(iface.name) &&
            !runningIfaces.has(iface.friendlyName)
          ) {
            continue;
          }
          const tp = next[iface.ifIndex];
          if (tp) {
            rx += tp.rxRate;
            tx += tp.txRate;
          }
        }
        setSamples((prev) => [...prev.slice(-(MAX_SAMPLES - 1)), { rx, tx }]);
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

  const rateFor = (profile: Profile): Throughput | null => {
    const iface = interfaces.find(
      (i) =>
        i.name === profile.interfaceName ||
        i.friendlyName === profile.interfaceName,
    );
    if (!iface) return null;
    return throughput[iface.ifIndex] ?? null;
  };

  const running = profiles.filter((p) => statusFor(p.id).state === "running");
  const failed = profiles.filter((p) => statusFor(p.id).state === "failed");

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
    if (requiresElevation(profile)) {
      try {
        if (!(await ensureElevation(`Disconnecting ${profile.name}`))) return;
      } catch (err) {
        toast("error", String(err));
        return;
      }
    }
    setBusy((prev) => new Set(prev).add(profile.id));
    try {
      await invoke("disconnect_profile", { id: profile.id });
      await refresh();
    } catch (err) {
      toast("error", String(err));
    } finally {
      setBusy((prev) => {
        const next = new Set(prev);
        next.delete(profile.id);
        return next;
      });
    }
  };

  if (loading) {
    return (
      <Page width="wide">
        <div className="status-strip">
          <Skeleton width="12px" height="12px" radius="50%" />
          <div className="status-strip-text">
            <Skeleton width="160px" height="1.05rem" />
          </div>
        </div>
        <section>
          <h2>{t("monitor.activeTunnels")}</h2>
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
    <Page width="wide">
      <div className="status-strip">
        <span
          className={`status-strip-indicator ${running.length > 0 ? "active" : ""}`}
        />
        <div className="status-strip-text">
          <span className="status-strip-title">
            {running.length === 0
              ? failed.length > 0
                ? t("monitor.tunnelsFailed", {
                    n: failed.length,
                    word: pluralize(
                      failed.length,
                      ["туннель", "туннеля", "туннелей"],
                      ["tunnel", "tunnels"],
                    ),
                  })
                : t("monitor.allDisconnected")
              : t("monitor.tunnelsActive", {
                    n: running.length,
                    total: profiles.length,
                    word: pluralize(
                      profiles.length,
                      ["туннеля", "туннелей", "туннелей"],
                      ["tunnel", "tunnels"],
                    ),
                  })}
          </span>
          <span className="status-strip-sub">
            {running.length > 0 ? (
              <RateText rx={totalRate.rx} tx={totalRate.tx} live />
            ) : (
              t("monitor.profilesConfigured", { count: profiles.length })
            )}
            {failed.length > 0 && running.length > 0 && (
              <span className="monitor-failed-note">
                {" "}
                · {t("monitor.failedSuffix", { n: failed.length })}
              </span>
            )}
          </span>
        </div>
      </div>

      <div className="monitor-grid">
        <section className="monitor-card">
          <h3>{t("monitor.throughput")}</h3>
          <ThroughputChart samples={samples} />
          <div className="chart-legend">
            <span className="chart-legend-item chart-rx-text">↓ {t("monitor.download")}</span>
            <span className="chart-legend-item chart-tx-text">↑ {t("monitor.upload")}</span>
          </div>
        </section>
        <section className="monitor-card">
          <h3>{t("monitor.exitAddresses")}</h3>
          <ExitIpPanel />
        </section>
      </div>

      <section>
        <h2>{t("monitor.activeTunnels")}</h2>
        {running.length === 0 ? (
          <p className="empty-state">{t("monitor.noTunnels")}</p>
        ) : (
          <div className="active-now-list">
            {running.map((profile) => {
              const rate = rateFor(profile);
              return (
                <div key={profile.id} className="active-now-card">
                  <span
                    className={`backend-avatar backend-avatar-${profile.backend}`}
                  >
                    {backendIcon(profile.backend, 16)}
                  </span>
                  <div className="active-now-info">
                    <span className="active-now-name">{profile.name}</span>
                    <span className="active-now-meta">
                      {rate ? (
                        <RateText rx={rate.rxRate} tx={rate.txRate} />
                      ) : (
                        profile.interfaceName
                      )}
                    </span>
                  </div>
                  <button
                    type="button"
                    className="btn-sm"
                    onClick={() => onDisconnect(profile)}
                    disabled={busy.has(profile.id)}
                    title={t("common.disconnect")}
                  >
                    {t("common.disconnect")}
                  </button>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {failed.length > 0 && (
        <section>
          <h2>{t("monitor.needsAttention")}</h2>
          <div className="active-now-list">
            {failed.map((profile) => {
              const status = statusFor(profile.id);
              return (
                <div key={profile.id} className="active-now-card failed">
                  <span
                    className={`backend-avatar backend-avatar-${profile.backend}`}
                  >
                    {backendIcon(profile.backend, 16)}
                  </span>
                  <div className="active-now-info">
                    <span className="active-now-name">{profile.name}</span>
                    <span className="active-now-meta">
                      {status.message ?? t("monitor.connectionFailed")}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      )}
    </Page>
  );
}
