import { useEffect, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import { invoke } from "@tauri-apps/api/core";
import BackendStatus from "./BackendStatus";
import UpdateChecker from "./UpdateChecker";
import Page from "./Page";
import ToggleSwitch from "./ui/ToggleSwitch";
import { usePlatformCapabilities } from "../platform";
import { VpnAuthMode } from "../types";

const VPN_AUTH_MODES: { value: VpnAuthMode; label: string }[] = [
  { value: "noPrompt", label: "Never" },
  { value: "fullTunnelOnly", label: "Full tunnel and OpenVPN only" },
  { value: "always", label: "Every connection" },
];

export default function Settings() {
  const [version, setVersion] = useState<string | null>(null);
  const [loginAutostart, setLoginAutostart] = useState<boolean | null>(null);
  const [autostartBusy, setAutostartBusy] = useState(false);
  const [autostartError, setAutostartError] = useState<string | null>(null);
  const caps = usePlatformCapabilities();
  const [vpnAuthMode, setVpnAuthMode] = useState<VpnAuthMode | null>(null);
  const [vpnAuthBusy, setVpnAuthBusy] = useState(false);
  const [vpnAuthError, setVpnAuthError] = useState<string | null>(null);

  useEffect(() => {
    getVersion().then(setVersion).catch(() => setVersion(null));
  }, []);

  useEffect(() => {
    if (caps?.os !== "linux") return;
    let active = true;
    invoke<boolean>("get_login_autostart")
      .then((enabled) => {
        if (active) setLoginAutostart(enabled);
      })
      .catch(() => {
        if (active) setAutostartError("Could not read login autostart setting.");
      });
    return () => {
      active = false;
    };
  }, [caps?.os]);

  useEffect(() => {
    if (caps?.os !== "linux") return;
    let active = true;
    invoke<VpnAuthMode | null>("get_vpn_auth_mode")
      .then((mode) => {
        if (active) setVpnAuthMode(mode);
      })
      .catch((err) => {
        if (active) setVpnAuthError(String(err));
      });
    return () => {
      active = false;
    };
  }, [caps?.os]);

  const changeVpnAuthMode = async (mode: VpnAuthMode) => {
    setVpnAuthBusy(true);
    setVpnAuthError(null);
    try {
      await invoke("set_vpn_auth_mode", { mode });
      setVpnAuthMode(mode);
    } catch (err) {
      setVpnAuthError(String(err));
    } finally {
      setVpnAuthBusy(false);
    }
  };

  const toggleLoginAutostart = async () => {
    if (loginAutostart === null) return;
    setAutostartBusy(true);
    setAutostartError(null);
    try {
      setLoginAutostart(
        await invoke<boolean>("set_login_autostart", {
          enabled: !loginAutostart,
        }),
      );
    } catch {
      setAutostartError("Could not update login autostart setting.");
    } finally {
      setAutostartBusy(false);
    }
  };

  return (
    <Page width="narrow">
      <h2>Settings</h2>

      <div className="settings-group">
        <div className="settings-group-title">Backend &amp; dependencies</div>
        <div className="settings-group-body">
          <BackendStatus />
        </div>
      </div>

      {caps?.os === "linux" && (
        <div className="settings-group">
          <div className="settings-group-title">Startup</div>
          <div className="settings-group-body">
            <div className="settings-row">
              <div className="settings-row-main">
                <span className="settings-row-label">Start at login</span>
                <span className="settings-row-sub">
                  Launch the app and connect profiles marked for auto-connect.
                </span>
              </div>
              <ToggleSwitch
                checked={loginAutostart ?? false}
                onChange={toggleLoginAutostart}
                disabled={loginAutostart === null}
                busy={autostartBusy}
                title="Start at login"
              />
            </div>
            {autostartError && <p className="error">{autostartError}</p>}
          </div>
        </div>
      )}

      {caps?.os === "linux" && (
        <div className="settings-group">
          <div className="settings-group-title">Security</div>
          <div className="settings-group-body">
            <div className="settings-row">
              <div className="settings-row-main">
                <span className="settings-row-label">
                  Ask for administrator password when connecting VPN
                </span>
                <span className="settings-row-sub">
                  Applies to every user of this computer. Changing it requires
                  an administrator password.
                </span>
              </div>
              <select
                value={vpnAuthMode ?? ""}
                disabled={vpnAuthMode === null || vpnAuthBusy}
                onChange={(e) => changeVpnAuthMode(e.target.value as VpnAuthMode)}
              >
                {VPN_AUTH_MODES.map((mode) => (
                  <option key={mode.value} value={mode.value}>
                    {mode.label}
                  </option>
                ))}
              </select>
            </div>
            {vpnAuthError && <p className="error">{vpnAuthError}</p>}
          </div>
        </div>
      )}

      {caps?.appUpdates && (
        <div className="settings-group">
          <div className="settings-group-title">Updates</div>
          <div className="settings-group-body">
            <div className="settings-row">
              <div className="settings-row-main">
                <span className="settings-row-label">App updates</span>
                <span className="settings-row-sub">
                  Check for and install new versions
                </span>
              </div>
              <UpdateChecker />
            </div>
          </div>
        </div>
      )}

      <div className="settings-group">
        <div className="settings-group-title">About</div>
        <div className="settings-group-body">
          <div className="settings-row">
            <div className="settings-row-main">
              <span className="settings-row-label">Network Orchestrator</span>
              <span className="settings-row-sub">
                {version ? `Version ${version}` : "Loading version…"}
              </span>
            </div>
          </div>
        </div>
      </div>
    </Page>
  );
}
