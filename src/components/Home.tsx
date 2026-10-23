import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ensureElevation, requiresElevation } from "../elevation";
import { backendIcon } from "../icons";
import { BACKEND_LABEL_KEYS } from "../i18n/labels";
import { getLastProfileId, setLastProfileId } from "../prefs";
import { Profile, TunnelStatus } from "../types";
import { useT } from "../i18n";
import type { Tab } from "./NavRail";
import OpenVpnCredentialsModal from "./OpenVpnCredentialsModal";
import Page from "./Page";
import { useToast } from "./ui/Toast";

interface HomeProps {
  onNavigate: (tab: Tab) => void;
}

/** `export` lines for a shell, pointing at the profile's loopback proxies. */
export function terminalProxyCommands(profile: Profile): string | null {
  if (profile.xraySocksPort === null) return null;
  const socks = `socks5h://127.0.0.1:${profile.xraySocksPort}`;
  const http =
    profile.xrayHttpPort !== null
      ? `http://127.0.0.1:${profile.xrayHttpPort}`
      : socks;
  return `export HTTP_PROXY=${http} HTTPS_PROXY=${http} ALL_PROXY=${socks} NO_PROXY=localhost,127.0.0.1,.local`;
}

/** Landing screen: overall state, running connections and one-click reconnect
 * of the last used profile. */
export default function Home({ onNavigate }: HomeProps) {
  const t = useT();
  const toast = useToast();
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [statuses, setStatuses] = useState<TunnelStatus[]>([]);
  const [busy, setBusy] = useState<Set<string>>(new Set());
  const [credentialProfile, setCredentialProfile] = useState<Profile | null>(null);
  const [lastId, setLastId] = useState<string | null>(getLastProfileId);

  const refresh = useCallback(async () => {
    try {
      const [p, s] = await Promise.all([
        invoke<Profile[]>("get_profiles"),
        invoke<TunnelStatus[]>("get_tunnel_statuses"),
      ]);
      setProfiles(p);
      setStatuses(s);
    } catch (err) {
      toast("error", String(err));
    }
  }, [toast]);

  useEffect(() => {
    void refresh();
    const interval = setInterval(refresh, 2000);
    window.addEventListener("route-changed", refresh);
    return () => {
      clearInterval(interval);
      window.removeEventListener("route-changed", refresh);
    };
  }, [refresh]);

  const isRunning = (id: string) =>
    statuses.some((s) => s.profileId === id && s.state === "running");
  const running = profiles.filter((p) => isRunning(p.id));
  const last = profiles.find((p) => p.id === lastId) ?? null;

  const rememberLast = (profile: Profile) => {
    setLastProfileId(profile.id);
    setLastId(profile.id);
  };

  const run = async (profile: Profile, action: () => Promise<void>) => {
    setBusy((prev) => new Set(prev).add(profile.id));
    try {
      await action();
    } catch (err) {
      if (
        profile.backend === "openVpn" &&
        String(err) === "OpenVPN credentials required"
      ) {
        setCredentialProfile(profile);
      } else {
        toast("error", String(err));
      }
    } finally {
      setBusy((prev) => {
        const next = new Set(prev);
        next.delete(profile.id);
        return next;
      });
      void refresh();
    }
  };

  const connect = (profile: Profile) =>
    run(profile, async () => {
      if (
        requiresElevation(profile) &&
        !(await ensureElevation(t("profiles.connecting", { name: profile.name })))
      ) {
        return;
      }
      const status = await invoke<TunnelStatus>("connect_profile", {
        id: profile.id,
      });
      if (status.state === "failed") {
        toast(
          "error",
          status.message ??
            t("profiles.connectFailedDiag", { name: profile.name }),
        );
        return;
      }
      rememberLast(profile);
      if (status.message) toast("info", status.message);
    });

  const disconnect = (profile: Profile) =>
    run(profile, async () => {
      if (
        requiresElevation(profile) &&
        !(await ensureElevation(t("profiles.disconnecting", { name: profile.name })))
      ) {
        return;
      }
      await invoke("disconnect_profile", { id: profile.id });
    });

  const copyProxy = async (profile: Profile) => {
    const text = terminalProxyCommands(profile);
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      toast("success", t("native.copied"));
    } catch {
      toast("error", t("native.copyFailed"));
    }
  };

  return (
    <Page width="wide">
      <div className="status-strip">
        <span
          className={`status-strip-indicator ${running.length > 0 ? "active" : ""}`}
        />
        <div className="status-strip-text">
          <span className="status-strip-title">
            {running.length === 0
              ? t("All disconnected")
              : t("native.connectedCount", { count: running.length })}
          </span>
        </div>
      </div>

      <section>
        <h2>{t("Active now")}</h2>
        {running.length === 0 ? (
          <p className="empty-state">
            {t("No tunnels are running.")}{" "}
            <button
              type="button"
              className="btn-ghost btn-sm"
              onClick={() => onNavigate("profiles")}
            >
              {t("Open Connections")}
            </button>{" "}
            {t("to view your profiles.")}
          </p>
        ) : (
          <div className="active-now-list">
            {running.map((profile) => (
              <div className="active-now-card" key={profile.id}>
                <span
                  className={`backend-avatar backend-avatar-${profile.backend}`}
                >
                  {backendIcon(profile.backend, 14)}
                </span>
                <div className="active-now-info">
                  <span className="monitor-name">{profile.name}</span>
                  <span className="profile-detail-meta">
                    {[
                      t(BACKEND_LABEL_KEYS[profile.backend]),
                      profile.tunnelRole === "secondary"
                        ? t("native.roleSecondary")
                        : null,
                      profile.xraySocksPort !== null
                        ? `SOCKS 127.0.0.1:${profile.xraySocksPort}`
                        : null,
                    ]
                      .filter(Boolean)
                      .join(" · ")}
                  </span>
                </div>
                {terminalProxyCommands(profile) && (
                  <button
                    type="button"
                    className="btn-sm"
                    onClick={() => void copyProxy(profile)}
                  >
                    {t("native.copyTerminal")}
                  </button>
                )}
                <button
                  type="button"
                  className="btn-sm btn-danger"
                  onClick={() => void disconnect(profile)}
                  disabled={busy.has(profile.id)}
                >
                  {t("common.disconnect")}
                </button>
              </div>
            ))}
          </div>
        )}
      </section>

      <section>
        <h2>{t("Quick actions")}</h2>
        <div className="home-actions">
          {last && !isRunning(last.id) && (
            <button
              type="button"
              className="btn-primary"
              onClick={() => void connect(last)}
              disabled={busy.has(last.id)}
            >
              {t("Connect {name}", { name: last.name })}
            </button>
          )}
          <button type="button" onClick={() => onNavigate("profiles")}>
            {t("nav.profiles")}
          </button>
        </div>
      </section>

      <section>
        <h2>{t("Advanced")}</h2>
        <div className="home-actions">
          <button type="button" onClick={() => onNavigate("network")}>
            {t("Network")}
          </button>
          <button type="button" onClick={() => onNavigate("routes")}>
            {t("Routes")}
          </button>
        </div>
      </section>
      <OpenVpnCredentialsModal
        profile={credentialProfile}
        onClose={() => setCredentialProfile(null)}
        onConnected={(profile, status) => {
          if (status.message) toast("info", status.message);
          rememberLast(profile);
          setCredentialProfile(null);
          void refresh();
        }}
      />
    </Page>
  );
}
