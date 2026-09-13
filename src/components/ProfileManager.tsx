import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { ensureElevation } from "../elevation";
import {
  DomainPolicy,
  DomainRouteTarget,
  NetworkInterface,
  PolicyRoute,
  Profile,
  ProfileDiagnostics,
  ProfileInspection,
  TunnelBackend,
  TunnelStatus,
} from "../types";

const BACKEND_LABELS: Record<TunnelBackend, string> = {
  wireGuard: "WireGuard",
  openVpn: "OpenVPN",
  xray: "Xray/VLESS",
};

const BACKEND_EXTENSIONS: Record<TunnelBackend, string[]> = {
  wireGuard: ["conf", "dpapi"],
  openVpn: ["ovpn", "conf"],
  xray: ["json"],
};

const DOMAIN_TARGET_LABELS: Record<DomainRouteTarget, string> = {
  proxy: "Through proxy",
  direct: "Direct",
};

function newProfileId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function clampMetric(value: number): number {
  if (Number.isNaN(value)) return 0;
  return Math.max(0, Math.min(9999, Math.trunc(value)));
}

function requiresElevation(profile: Profile): boolean {
  return (
    profile.backend === "wireGuard" ||
    profile.backend === "openVpn" ||
    profile.routes.length > 0
  );
}

interface FormState {
  id: string;
  name: string;
  backend: TunnelBackend;
  configPath: string;
  interfaceName: string;
  routes: PolicyRoute[];
  xraySource: "json" | "vless";
  vlessUrl: string;
  xraySocksPort: number | null;
  domainPolicies: DomainPolicy[];
  isNew: boolean;
}

export default function ProfileManager() {
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [statuses, setStatuses] = useState<TunnelStatus[]>([]);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<Set<string>>(new Set());
  const [editing, setEditing] = useState<FormState | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [inspections, setInspections] = useState<Record<string, ProfileInspection>>(
    {}
  );
  const [saveNotice, setSaveNotice] = useState<{
    profileName: string;
    inspection: ProfileInspection;
  } | null>(null);
  const [diagnostics, setDiagnostics] = useState<ProfileDiagnostics | null>(null);
  const [diagBusy, setDiagBusy] = useState<string | null>(null);
  const [runtimeNotice, setRuntimeNotice] = useState<string | null>(null);

  const statusFor = useCallback(
    (id: string): TunnelStatus =>
      statuses.find((s) => s.profileId === id) ?? {
        profileId: id,
        state: "stopped",
        message: null,
      },
    [statuses]
  );

  const refreshStatuses = useCallback(async () => {
    try {
      setStatuses(await invoke<TunnelStatus[]>("get_tunnel_statuses"));
    } catch {
      // keep last known statuses on poll failure
    }
  }, []);

  const refreshAll = useCallback(async () => {
    try {
      setError(null);
      const [profileData, statusData, interfaceData] = await Promise.all([
        invoke<Profile[]>("get_profiles"),
        invoke<TunnelStatus[]>("get_tunnel_statuses"),
        invoke<NetworkInterface[]>("get_interfaces"),
      ]);
      setProfiles(profileData);
      setStatuses(statusData);
      setInterfaces(interfaceData);
      try {
        const inspectionData =
          await invoke<ProfileInspection[]>("inspect_profiles");
        setInspections(
          Object.fromEntries(inspectionData.map((i) => [i.analysis.profileId, i]))
        );
      } catch (err) {
        setError(String(err));
      }
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshAll();
  }, [refreshAll]);

  useEffect(() => {
    const interval = setInterval(refreshStatuses, 2000);
    return () => clearInterval(interval);
  }, [refreshStatuses]);

  const withBusy = async (id: string, action: () => Promise<unknown>) => {
    setBusy((prev) => new Set(prev).add(id));
    try {
      await action();
      await refreshAll();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
  };

  const onConnect = async (profile: Profile) => {
    if (requiresElevation(profile)) {
      try {
        if (!(await ensureElevation(`Connecting ${profile.name}`))) return;
      } catch (err) {
        setError(String(err));
        return;
      }
    }
    withBusy(profile.id, async () => {
      const status = await invoke<TunnelStatus>("connect_profile", {
        id: profile.id,
      });
      if (status.message) setRuntimeNotice(status.message);
    });
  };

  const onDisconnect = async (profile: Profile) => {
    if (requiresElevation(profile)) {
      try {
        if (!(await ensureElevation(`Disconnecting ${profile.name}`))) return;
      } catch (err) {
        setError(String(err));
        return;
      }
    }
    withBusy(profile.id, () => invoke("disconnect_profile", { id: profile.id }));
  };

  const onDiagnose = async (profile: Profile) => {
    setDiagBusy(profile.id);
    try {
      setDiagnostics(
        await invoke<ProfileDiagnostics>("diagnose_profile", { id: profile.id })
      );
    } catch (err) {
      setError(String(err));
    } finally {
      setDiagBusy(null);
    }
  };

  const onDelete = (profile: Profile) => {
    if (!window.confirm(`Delete profile "${profile.name}"?`)) return;
    withBusy(profile.id, () => invoke("delete_profile", { id: profile.id }));
  };

  const openNew = () => {
    setFormError(null);
    setEditing({
      id: newProfileId(),
      name: "",
      backend: "wireGuard",
      configPath: "",
      interfaceName: "",
      routes: [],
      xraySource: "json",
      vlessUrl: "",
      xraySocksPort: null,
      domainPolicies: [],
      isNew: true,
    });
  };

  const openEdit = (profile: Profile) => {
    setFormError(null);
    setEditing({
      id: profile.id,
      name: profile.name,
      backend: profile.backend,
      configPath: profile.configPath,
      interfaceName: profile.interfaceName,
      routes: profile.routes.map((r) => ({ ...r })),
      xraySource: "json",
      vlessUrl: "",
      xraySocksPort: profile.xraySocksPort,
      domainPolicies: profile.domainPolicies.map((p) => ({
        domains: [...p.domains],
        target: p.target,
      })),
      isNew: false,
    });
  };

  const browseConfig = async () => {
    if (!editing) return;
    try {
      const selected = await open({
        multiple: false,
        directory: false,
        filters: [
          {
            name: `${BACKEND_LABELS[editing.backend]} config`,
            extensions: BACKEND_EXTENSIONS[editing.backend],
          },
        ],
      });
      if (typeof selected === "string") {
        setEditing({ ...editing, configPath: selected });
      }
    } catch (err) {
      setFormError(String(err));
    }
  };

  const updateDomainRule = (index: number, patch: Partial<DomainPolicy>) => {
    if (!editing) return;
    setEditing({
      ...editing,
      domainPolicies: editing.domainPolicies.map((p, i) =>
        i === index ? { ...p, ...patch } : p
      ),
    });
  };

  const updateRoute = (index: number, patch: Partial<PolicyRoute>) => {
    if (!editing) return;
    setEditing({
      ...editing,
      routes: editing.routes.map((r, i) => (i === index ? { ...r, ...patch } : r)),
    });
  };

  const save = async () => {
    if (!editing) return;
    for (const route of editing.routes) {
      if (!route.destination.trim()) {
        setFormError("Route destination cannot be blank.");
        return;
      }
    }
    if (editing.routes.length > 0 && !editing.interfaceName.trim()) {
      setFormError("Target interface is required when policy routes are set.");
      return;
    }
    const isXray = editing.backend === "xray";
    const isVlessImport = isXray && editing.isNew && editing.xraySource === "vless";
    const domainPolicies = editing.domainPolicies.map((p) => ({
      domains: p.domains.map((d) => d.trim()).filter((d) => d.length > 0),
      target: p.target,
    }));
    if (isXray) {
      for (const policy of domainPolicies) {
        if (policy.domains.length === 0) {
          setFormError("Each domain rule must list at least one domain.");
          return;
        }
      }
    }
    if (isVlessImport) {
      if (!editing.vlessUrl.trim()) {
        setFormError("VLESS URL is required.");
        return;
      }
      if (
        editing.xraySocksPort !== null &&
        (!Number.isInteger(editing.xraySocksPort) ||
          editing.xraySocksPort < 1 ||
          editing.xraySocksPort > 65535)
      ) {
        setFormError("SOCKS port must be an integer between 1 and 65535.");
        return;
      }
    }
    const payload: Profile = {
      id: editing.id,
      name: editing.name.trim(),
      backend: editing.backend,
      configPath: editing.configPath.trim(),
      interfaceName: editing.interfaceName.trim(),
      routes: editing.routes.map((r) => ({
        destination: r.destination.trim(),
        metric: clampMetric(r.metric),
      })),
      autoConnect: false,
      domainPolicies: isXray ? domainPolicies : [],
      xraySocksPort: !isXray
        ? null
        : isVlessImport
          ? editing.xraySocksPort
          : editing.isNew
            ? null
            : editing.xraySocksPort,
    };
    setSaving(true);
    try {
      const updated = isVlessImport
        ? await invoke<Profile[]>("save_vless_profile", {
            profile: payload,
            vlessUrl: editing.vlessUrl.trim(),
          })
        : await invoke<Profile[]>("save_profile", { profile: payload });
      setProfiles(updated);
      setEditing(null);
      setFormError(null);
      setError(null);
      await refreshAll();
      try {
        const inspection = await invoke<ProfileInspection>(
          "inspect_profile_by_id",
          { id: editing.id }
        );
        const notes = [
          ...inspection.analysis.warnings,
          ...inspection.conflicts.map((c) => c.message),
        ];
        setSaveNotice(
          notes.length > 0
            ? { profileName: payload.name || editing.id, inspection }
            : null
        );
      } catch (err) {
        setError(`Profile was saved, but static analysis failed: ${String(err)}`);
        setSaveNotice(null);
      }
    } catch (err) {
      setFormError(String(err));
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <p>Loading profiles...</p>;

  const targetable = interfaces.filter((i) => i.category !== "filter");

  return (
    <section>
      <div className="profiles-toolbar">
        <h2>VPN Profiles</h2>
        <span className="profiles-note">
          WireGuard, OpenVPN, interface changes, and policy routes require administrator privileges.
        </span>
        <button className="profile-new-btn" onClick={openNew}>
          New profile
        </button>
      </div>

      {error && <p className="error">{error}</p>}

      {runtimeNotice && (
        <div className="runtime-notice">
          <span>{runtimeNotice}</span>
          <button type="button" onClick={() => setRuntimeNotice(null)}>
            Dismiss
          </button>
        </div>
      )}

      {saveNotice && (
        <div className="save-notice">
          <div className="diagnostics-head">
            <span>
              Saved "{saveNotice.profileName}" — review notes
            </span>
            <button type="button" onClick={() => setSaveNotice(null)}>
              Dismiss
            </button>
          </div>
          <ul className="save-notice-list">
            {saveNotice.inspection.analysis.warnings.map((w, i) => (
              <li key={`w${i}`}>{w}</li>
            ))}
            {saveNotice.inspection.conflicts.map((c, i) => (
              <li key={`c${i}`}>{c.message}</li>
            ))}
          </ul>
        </div>
      )}

      {diagnostics && (
        <div className="diagnostics-panel">
          <div className="diagnostics-head">
            <span>
              Diagnostics —{" "}
              {profiles.find((p) => p.id === diagnostics.profileId)?.name ??
                diagnostics.profileId}
            </span>
            <button type="button" onClick={() => setDiagnostics(null)}>
              Close
            </button>
          </div>
          <ul className="diagnostics-list">
            {diagnostics.checks.map((check, i) => (
              <li key={i}>
                <span className={`badge diag-${check.level}`}>
                  {check.level}
                </span>
                <span className="diag-name">{check.name}</span>
                <span className="diag-message">{check.message}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {editing && (
        <div className="profile-form">
          <h3>{editing.isNew ? "New profile" : "Edit profile"}</h3>
          {formError && <p className="error">{formError}</p>}
          <label>
            Name
            <input
              type="text"
              value={editing.name}
              onChange={(e) => setEditing({ ...editing, name: e.target.value })}
              placeholder="Work VPN"
            />
          </label>
          <label>
            Backend
            <select
              className="filter-select"
              value={editing.backend}
              onChange={(e) => {
                const backend = e.target.value as TunnelBackend;
                setEditing({
                  ...editing,
                  backend,
                  configPath: "",
                  domainPolicies: backend === "xray" ? editing.domainPolicies : [],
                  xraySource: "json",
                  xraySocksPort:
                    backend === "xray"
                      ? editing.isNew
                        ? null
                        : (editing.xraySocksPort ?? 10808)
                      : null,
                });
              }}
            >
              <option value="wireGuard">WireGuard</option>
              <option value="openVpn">OpenVPN</option>
              <option value="xray">Xray/VLESS</option>
            </select>
          </label>
          {editing.backend === "xray" && editing.isNew && (
            <label>
              Config source
              <select
                className="filter-select"
                value={editing.xraySource}
                onChange={(e) =>
                  setEditing({
                    ...editing,
                    xraySource: e.target.value as "json" | "vless",
                  })
                }
              >
                <option value="json">Existing Xray JSON</option>
                <option value="vless">Import vless:// URL</option>
              </select>
            </label>
          )}
          {editing.backend === "xray" &&
          editing.isNew &&
          editing.xraySource === "vless" ? (
            <>
              <label>
                VLESS URL
                <input
                  type="password"
                  value={editing.vlessUrl}
                  onChange={(e) =>
                    setEditing({ ...editing, vlessUrl: e.target.value })
                  }
                  placeholder="vless://uuid@host:port?…"
                  autoComplete="off"
                />
              </label>
              <span className="profile-help">
                SOCKS5 port will be assigned automatically when the profile is
                saved.
              </span>
            </>
          ) : (
            <label>
              Config file
              <div className="profile-config-row">
                <input
                  type="text"
                  value={editing.configPath}
                  onChange={(e) =>
                    setEditing({ ...editing, configPath: e.target.value })
                  }
                  placeholder={
                    editing.backend === "wireGuard"
                      ? "C:\\path\\tunnel.conf"
                      : editing.backend === "openVpn"
                        ? "C:\\path\\client.ovpn"
                        : "C:\\path\\config.json"
                  }
                />
                <button type="button" onClick={browseConfig}>
                  Browse…
                </button>
              </div>
            </label>
          )}
          {editing.backend === "xray" &&
            !editing.isNew &&
            editing.xraySocksPort !== null && (
              <div className="interface-row">
                <span className="row-label">SOCKS5</span>
                <span className="row-value mono">
                  127.0.0.1:{editing.xraySocksPort}
                </span>
              </div>
            )}
          <label>
            Target interface (required for policy routes)
            <input
              type="text"
              list="profile-target-interfaces"
              value={editing.interfaceName}
              onChange={(e) =>
                setEditing({ ...editing, interfaceName: e.target.value })
              }
              placeholder="Interface friendly name"
            />
            <datalist id="profile-target-interfaces">
              {targetable.map((i) => (
                <option key={i.ifIndex} value={i.friendlyName} label={i.description || i.name} />
              ))}
            </datalist>
          </label>
          <div className="profile-routes">
            <div className="profile-routes-head">
              <span>Policy routes</span>
              <button
                type="button"
                onClick={() =>
                  setEditing({
                    ...editing,
                    routes: [...editing.routes, { destination: "10.0.0.0/24", metric: 5 }],
                  })
                }
              >
                Add route
              </button>
            </div>
            {editing.routes.length === 0 && (
              <span className="profile-routes-empty">
                No routes — tunnel uses its own routing.
              </span>
            )}
            {editing.routes.map((route, index) => (
              <div className="profile-route-row" key={index}>
                <input
                  type="text"
                  value={route.destination}
                  onChange={(e) => updateRoute(index, { destination: e.target.value })}
                  placeholder="10.0.0.0/24"
                />
                <input
                  type="number"
                  min={0}
                  max={9999}
                  value={route.metric}
                  onChange={(e) =>
                    updateRoute(index, { metric: clampMetric(e.target.valueAsNumber) })
                  }
                />
                <button
                  type="button"
                  onClick={() =>
                    setEditing({
                      ...editing,
                      routes: editing.routes.filter((_, i) => i !== index),
                    })
                  }
                >
                  Remove
                </button>
              </div>
            ))}
          </div>
          {editing.backend === "xray" && (
            <div className="profile-routes">
              <div className="profile-routes-head">
                <span>Domain routing</span>
                <button
                  type="button"
                  onClick={() =>
                    setEditing({
                      ...editing,
                      domainPolicies: [
                        ...editing.domainPolicies,
                        { domains: [""], target: "proxy" },
                      ],
                    })
                  }
                >
                  Add domain rule
                </button>
              </div>
              {editing.domainPolicies.length === 0 && (
                <span className="profile-routes-empty">
                  No domain rules — all traffic uses the proxy.
                </span>
              )}
              {editing.domainPolicies.map((policy, index) => (
                <div className="profile-route-row" key={index}>
                  <input
                    type="text"
                    value={policy.domains.join(",")}
                    onChange={(e) =>
                      updateDomainRule(index, {
                        domains: e.target.value.split(","),
                      })
                    }
                    placeholder="domain:example.com, full:api.example.com"
                  />
                  <select
                    className="filter-select"
                    value={policy.target}
                    onChange={(e) =>
                      updateDomainRule(index, {
                        target: e.target.value as DomainRouteTarget,
                      })
                    }
                  >
                    <option value="proxy">Through proxy</option>
                    <option value="direct">Direct</option>
                  </select>
                  <button
                    type="button"
                    onClick={() =>
                      setEditing({
                        ...editing,
                        domainPolicies: editing.domainPolicies.filter(
                          (_, i) => i !== index
                        ),
                      })
                    }
                  >
                    Remove
                  </button>
                </div>
              ))}
            </div>
          )}
          <div className="profile-form-actions">
            <button type="button" onClick={() => setEditing(null)} disabled={saving}>
              Cancel
            </button>
            <button type="button" className="profile-save-btn" onClick={save} disabled={saving}>
              Save
            </button>
          </div>
        </div>
      )}

      {profiles.length === 0 ? (
        <p className="empty-state">No profiles yet. Create one to get started.</p>
      ) : (
        <div className="profile-grid">
          {profiles.map((profile) => {
            const status = statusFor(profile.id);
            const isBusy = busy.has(profile.id);
            const inspection = inspections[profile.id];
            return (
              <div key={profile.id} className="interface-card profile-card">
                <div className="interface-header">
                  <div className="interface-title">
                    <span className="interface-name">{profile.name}</span>
                  </div>
                  <div className="badge-group">
                    <span className="badge badge-physical">
                      {BACKEND_LABELS[profile.backend]}
                    </span>
                    {inspection?.managedConfig === true && (
                      <span className="badge badge-managed">Managed config</span>
                    )}
                    {inspection?.managedConfig === false && (
                      <span className="badge badge-external">
                        External config — resave to import
                      </span>
                    )}
                    <span className={`state-badge state-${status.state}`}>
                      {status.state}
                    </span>
                  </div>
                </div>
                {status.state === "failed" && status.message && (
                  <p className="profile-status-msg">{status.message}</p>
                )}
                <div className="interface-row">
                  <span className="row-label">Config</span>
                  <span className="row-value mono">{profile.configPath}</span>
                </div>
                <div className="interface-row">
                  <span className="row-label">Interface</span>
                  <span className="row-value">{profile.interfaceName}</span>
                </div>
                {profile.backend === "xray" && profile.xraySocksPort !== null && (
                  <div className="interface-row">
                    <span className="row-label">SOCKS5</span>
                    <span className="row-value mono">
                      127.0.0.1:{profile.xraySocksPort}
                    </span>
                  </div>
                )}
                {profile.backend === "xray" &&
                  (profile.domainPolicies.length === 0 ? (
                    <div className="interface-row">
                      <span className="row-label">Domain rules</span>
                      <span className="row-value">None</span>
                    </div>
                  ) : (
                    <div className="interface-section">
                      <span className="section-label">
                        Domain rules ({profile.domainPolicies.length})
                      </span>
                      <ul className="profile-route-list">
                        {profile.domainPolicies.map((policy, i) => (
                          <li key={i}>
                            <span className="mono">
                              {policy.domains.join(", ")}
                            </span>
                            <span className="family-tag">
                              {DOMAIN_TARGET_LABELS[policy.target]}
                            </span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  ))}
                {profile.routes.length === 0 ? (
                  <div className="interface-row">
                    <span className="row-label">Routes</span>
                    <span className="row-value">None</span>
                  </div>
                ) : (
                  <div className="interface-section">
                    <span className="section-label">
                      Routes ({profile.routes.length})
                    </span>
                    <ul className="profile-route-list">
                      {profile.routes.map((route, i) => (
                        <li key={i}>
                          <span className="mono">{route.destination}</span>
                          <span className="family-tag">metric {route.metric}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                <div className="profile-actions">
                  <button onClick={() => openEdit(profile)} disabled={isBusy}>
                    Edit
                  </button>
                  <button
                    onClick={() => onDiagnose(profile)}
                    disabled={isBusy || diagBusy === profile.id}
                  >
                    {diagBusy === profile.id ? "Diagnosing…" : "Diagnostics"}
                  </button>
                  <button onClick={() => onDelete(profile)} disabled={isBusy}>
                    Delete
                  </button>
                  {status.state === "running" ? (
                    <button
                      className="profile-disconnect-btn"
                      onClick={() => onDisconnect(profile)}
                      disabled={isBusy}
                    >
                      Disconnect
                    </button>
                  ) : (
                    <button
                      className="profile-connect-btn"
                      onClick={() => onConnect(profile)}
                      disabled={isBusy}
                    >
                      Connect
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
