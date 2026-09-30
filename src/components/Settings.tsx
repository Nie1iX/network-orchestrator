import { useEffect, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import { invoke } from "@tauri-apps/api/core";
import BackendStatus from "./BackendStatus";
import UpdateChecker from "./UpdateChecker";
import Page from "./Page";
import ToggleSwitch from "./ui/ToggleSwitch";
import { usePlatformCapabilities } from "../platform";
import { setProfileListMode, useProfileListMode } from "../prefs";
import {
  readAppearance,
  saveAppearance,
  type Appearance,
} from "../theme";
import { VpnAuthMode } from "../types";
import {
  availableLanguages,
  TranslationKey,
  useLanguage,
  useT,
} from "../i18n";

const VPN_AUTH_MODES: { value: VpnAuthMode; labelKey: TranslationKey }[] = [
  { value: "noPrompt", labelKey: "settings.authNever" },
  { value: "fullTunnelOnly", labelKey: "settings.authFullTunnel" },
  { value: "always", labelKey: "settings.authAlways" },
];

type SettingsTab = "general" | "system" | "about";

const SETTINGS_TAB_KEYS: { id: SettingsTab; labelKey: TranslationKey }[] = [
  { id: "general", labelKey: "settings.tabGeneral" },
  { id: "system", labelKey: "settings.tabSystem" },
  { id: "about", labelKey: "settings.tabAbout" },
];

export default function Settings() {
  const [tab, setTab] = useState<SettingsTab>("general");
  const [version, setVersion] = useState<string | null>(null);
  const [loginAutostart, setLoginAutostart] = useState<boolean | null>(null);
  const [autostartBusy, setAutostartBusy] = useState(false);
  const [autostartError, setAutostartError] = useState<string | null>(null);
  const caps = usePlatformCapabilities();
  const [vpnAuthMode, setVpnAuthMode] = useState<VpnAuthMode | null>(null);
  const [vpnAuthBusy, setVpnAuthBusy] = useState(false);
  const [vpnAuthError, setVpnAuthError] = useState<string | null>(null);
  const listMode = useProfileListMode();
  const locale = useLanguage();
  const [appearance, setAppearance] = useState<Appearance>(readAppearance);
  const t = useT();

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
        if (active) setAutostartError(t("settings.autostartReadErr"));
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
      setAutostartError(t("settings.autostartUpdateErr"));
    } finally {
      setAutostartBusy(false);
    }
  };

  return (
    <Page width="narrow">
      <h2>{t("settings.title")}</h2>

      <nav className="route-tabs" aria-label={t("settings.sectionsAria")}>
        {SETTINGS_TAB_KEYS.map((tabDef) => (
          <button
            key={tabDef.id}
            type="button"
            className={`route-tab ${tab === tabDef.id ? "active" : ""}`}
            onClick={() => setTab(tabDef.id)}
          >
            {t(tabDef.labelKey)}
          </button>
        ))}
      </nav>

      {tab === "general" && (
        <>
          <div className="settings-group">
            <div className="settings-group-title">{t("settings.language")}</div>
            <div className="settings-group-body">
              <div className="settings-row">
                <div className="settings-row-main">
                  <span className="settings-row-label">
                    {t("settings.languageSub")}
                  </span>
                </div>
                <select
                  aria-label={t("settings.language")}
                  value={locale.preference}
                  onChange={(e) => locale.setLanguage(e.target.value)}
                >
                  <option value="system">{t("settings.langSystem")}</option>
                  {availableLanguages.map(({ code, name }) => (
                    <option key={code} value={code}>
                      {name}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </div>

          <div className="settings-group">
            <div className="settings-group-title">
              {t("settings.appearance")}
            </div>
            <div className="settings-group-body">
              <div className="settings-row">
                <div className="settings-row-main">
                  <span className="settings-row-label">
                    {t("settings.theme")}
                  </span>
                  <span className="settings-row-sub">
                    {t("settings.themeSub")}
                  </span>
                </div>
                <select
                  aria-label={t("settings.theme")}
                  value={appearance}
                  onChange={(e) => {
                    const value = e.target.value as Appearance;
                    setAppearance(value);
                    saveAppearance(value);
                  }}
                >
                  <option value="system">{t("settings.themeSystem")}</option>
                  <option value="light">{t("settings.themeLight")}</option>
                  <option value="dark">{t("settings.themeDark")}</option>
                </select>
              </div>
            </div>
          </div>

          <div className="settings-group">
            <div className="settings-group-title">{t("settings.groupProfiles")}</div>
            <div className="settings-group-body">
              <div className="settings-row">
                <div className="settings-row-main">
                  <span className="settings-row-label">
                    {t("settings.groupByBackend")}
                  </span>
                  <span className="settings-row-sub">
                    {t("settings.groupByBackendSub")}
                  </span>
                </div>
                <ToggleSwitch
                  checked={listMode === "grouped"}
                  onChange={() =>
                    setProfileListMode(
                      listMode === "grouped" ? "flat" : "grouped",
                    )
                  }
                  title={t("settings.groupByBackend")}
                />
              </div>
            </div>
          </div>

          {caps?.os === "linux" && (
            <div className="settings-group">
              <div className="settings-group-title">{t("settings.groupStartup")}</div>
              <div className="settings-group-body">
                <div className="settings-row">
                  <div className="settings-row-main">
                    <span className="settings-row-label">{t("settings.startAtLogin")}</span>
                    <span className="settings-row-sub">
                      {t("settings.startAtLoginSub")}
                    </span>
                  </div>
                  <ToggleSwitch
                    checked={loginAutostart ?? false}
                    onChange={toggleLoginAutostart}
                    disabled={loginAutostart === null}
                    busy={autostartBusy}
                    title={t("settings.startAtLogin")}
                  />
                </div>
                {autostartError && <p className="error">{autostartError}</p>}
              </div>
            </div>
          )}
        </>
      )}

      {tab === "system" && (
        <>
          <div className="settings-group">
            <div className="settings-group-title">{t("settings.groupBackend")}</div>
            <div className="settings-group-body">
              <BackendStatus />
            </div>
          </div>

          {caps?.os === "linux" && (
            <div className="settings-group">
              <div className="settings-group-title">{t("settings.groupSecurity")}</div>
              <div className="settings-group-body">
                <div className="settings-row">
                  <div className="settings-row-main">
                    <span className="settings-row-label">
                      {t("settings.vpnAuth")}
                    </span>
                    <span className="settings-row-sub">
                      {t("settings.vpnAuthSub")}
                    </span>
                  </div>
                  <select
                    value={vpnAuthMode ?? ""}
                    disabled={vpnAuthMode === null || vpnAuthBusy}
                    onChange={(e) =>
                      changeVpnAuthMode(e.target.value as VpnAuthMode)
                    }
                  >
                    {VPN_AUTH_MODES.map((mode) => (
                      <option key={mode.value} value={mode.value}>
                        {t(mode.labelKey)}
                      </option>
                    ))}
                  </select>
                </div>
                {vpnAuthError && <p className="error">{vpnAuthError}</p>}
              </div>
            </div>
          )}
        </>
      )}

      {tab === "about" && (
        <>
          {caps?.appUpdates && (
            <div className="settings-group">
              <div className="settings-group-title">{t("settings.groupUpdates")}</div>
              <div className="settings-group-body">
                <div className="settings-row">
                  <div className="settings-row-main">
                    <span className="settings-row-label">{t("settings.appUpdates")}</span>
                    <span className="settings-row-sub">
                      {t("settings.appUpdatesSub")}
                    </span>
                  </div>
                  <UpdateChecker />
                </div>
              </div>
            </div>
          )}

          <div className="settings-group">
            <div className="settings-group-title">{t("settings.tabAbout")}</div>
            <div className="settings-group-body">
              <div className="settings-row">
                <div className="settings-row-main">
                  <span className="settings-row-label">
                    Network Orchestrator
                  </span>
                  <span className="settings-row-sub">
                    {version ? t("settings.version", { v: version }) : t("settings.loadingVersion")}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </Page>
  );
}
