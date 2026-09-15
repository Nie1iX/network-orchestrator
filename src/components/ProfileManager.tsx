import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { confirm } from "@tauri-apps/plugin-dialog";
import { ensureElevation } from "../elevation";
import { backendIcon, ChevronIcon } from "../icons";
import AddConnectionMenu from "./AddConnectionMenu";
import DiagnosticsModal from "./DiagnosticsModal";
import ImportModal from "./ImportModal";
import Modal from "./Modal";
import Page from "./Page";
import Skeleton from "./ui/Skeleton";
import ToggleSwitch from "./ui/ToggleSwitch";
import OverflowMenu from "./ui/OverflowMenu";
import ProfileFormModal, {
  editFormState,
  newFormState,
  type ProfileFormState,
} from "./ProfileFormModal";
import {
  BatchImportResult,
  DomainRouteTarget,
  NetworkInterface,
  Profile,
  ProfileDiagnostics,
  ProfileInspection,
  SubscriptionEndpointInfo,
  TunnelBackend,
  TunnelStatus,
} from "../types";

const BACKEND_LABELS: Record<TunnelBackend, string> = {
  none: "Static routes",
  wireGuard: "WireGuard",
  openVpn: "OpenVPN",
  xray: "Xray/VLESS",
};

const DOMAIN_TARGET_LABELS: Record<DomainRouteTarget, string> = {
  proxy: "Through proxy",
  direct: "Direct",
};

function requiresElevation(profile: Profile): boolean {
  return (
    profile.backend === "wireGuard" ||
    profile.backend === "openVpn" ||
    profile.routes.length > 0
  );
}

function formatRate(bytesPerSec: number): string {
  if (bytesPerSec < 1024) return `${bytesPerSec.toFixed(0)} B/s`;
  if (bytesPerSec < 1024 * 1024) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
  return `${(bytesPerSec / (1024 * 1024)).toFixed(1)} MB/s`;
}

const COLLAPSED_GROUPS_KEY = "netmanager.connections.collapsedGroups";

function loadCollapsedGroups(): Set<TunnelBackend> {
  try {
    const raw = localStorage.getItem(COLLAPSED_GROUPS_KEY);
    if (!raw) return new Set();
    return new Set(JSON.parse(raw) as TunnelBackend[]);
  } catch {
    return new Set();
  }
}

const SNIPPETS_KEY = "netmanager.connections.snippets";

interface ConnectionSnippet {
  id: string;
  name: string;
  profileIds: string[];
}

function newSnippetId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function loadSnippets(): ConnectionSnippet[] {
  try {
    const raw = localStorage.getItem(SNIPPETS_KEY);
    if (!raw) return [];
    return JSON.parse(raw) as ConnectionSnippet[];
  } catch {
    return [];
  }
}

function sameIds(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const setA = new Set(a);
  return b.every((id) => setA.has(id));
}

function ConnectionCardSkeleton() {
  return (
    <div className="connection-card">
      <div className="connection-card-main">
        <Skeleton width="36px" height="36px" radius="50%" />
        <div className="connection-card-info">
          <Skeleton width="140px" height="0.95rem" />
          <Skeleton width="90px" height="0.78rem" />
        </div>
        <Skeleton width="40px" height="24px" radius="999px" />
        <Skeleton width="32px" height="32px" radius="8px" />
      </div>
    </div>
  );
}

export default function ProfileManager() {
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [statuses, setStatuses] = useState<TunnelStatus[]>([]);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<Set<string>>(new Set());
  const [editing, setEditing] = useState<ProfileFormState | null>(null);
  const [formOpen, setFormOpen] = useState(false);
  const [inspections, setInspections] = useState<
    Record<string, ProfileInspection>
  >({});
  const [saveNotice, setSaveNotice] = useState<{
    profileName: string;
    inspection: ProfileInspection;
  } | null>(null);
  const [diagnostics, setDiagnostics] = useState<ProfileDiagnostics | null>(
    null,
  );
  const [diagOpen, setDiagOpen] = useState(false);
  const [diagBusy, setDiagBusy] = useState<string | null>(null);
  const [runtimeNotice, setRuntimeNotice] = useState<string | null>(null);
  const [importErrors, setImportErrors] = useState<string[] | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [endpoints, setEndpoints] = useState<
    Record<string, SubscriptionEndpointInfo[]>
  >({});
  const [switching, setSwitching] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [collapsedGroups, setCollapsedGroups] = useState<Set<TunnelBackend>>(
    loadCollapsedGroups,
  );
  const [search, setSearch] = useState("");
  const [addMenuOpen, setAddMenuOpen] = useState(false);
  const [snippets, setSnippets] = useState<ConnectionSnippet[]>(loadSnippets);
  const [activeSnippetId, setActiveSnippetId] = useState<string | null>(null);
  const [saveModalOpen, setSaveModalOpen] = useState(false);
  const [newSnippetName, setNewSnippetName] = useState("");
  const [throughput, setThroughput] = useState<
    Record<number, { rxRate: number; txRate: number }>
  >({});
  const prevStats = useRef<Record<number, { rx: number; tx: number; time: number }>>({});

  useEffect(() => {
    try {
      localStorage.setItem(
        COLLAPSED_GROUPS_KEY,
        JSON.stringify([...collapsedGroups]),
      );
    } catch {
      // ignore storage errors (e.g. storage disabled)
    }
  }, [collapsedGroups]);

  useEffect(() => {
    try {
      localStorage.setItem(SNIPPETS_KEY, JSON.stringify(snippets));
    } catch {
      // ignore storage errors (e.g. storage disabled)
    }
  }, [snippets]);

  useEffect(() => {
    const poll = async () => {
      try {
        const data = await invoke<NetworkInterface[]>("get_interfaces");
        setInterfaces(data);
        const now = Date.now();
        const next: Record<number, { rxRate: number; txRate: number }> = {};
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

  const rateFor = (profile: Profile) => {
    const iface = interfaces.find(
      (i) => i.name === profile.interfaceName || i.friendlyName === profile.interfaceName,
    );
    if (!iface) return null;
    return throughput[iface.ifIndex] ?? null;
  };

  const toggleGroupCollapsed = (backend: TunnelBackend) =>
    setCollapsedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(backend)) next.delete(backend);
      else next.add(backend);
      return next;
    });

  const toggleExpanded = (id: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const statusFor = useCallback(
    (id: string): TunnelStatus =>
      statuses.find((s) => s.profileId === id) ?? {
        profileId: id,
        state: "stopped",
        message: null,
      },
    [statuses],
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
          Object.fromEntries(
            inspectionData.map((i) => [i.analysis.profileId, i]),
          ),
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

  useEffect(() => {
    const subProfiles = profiles.filter((p) => p.subscription !== null);
    if (subProfiles.length === 0) {
      if (Object.keys(endpoints).length > 0) setEndpoints({});
      return;
    }
    const subKey = subProfiles.map((p) => p.id).join(",");
    if (Object.keys(endpoints).sort().join(",") === subKey) return;
    let cancelled = false;
    (async () => {
      const next: Record<string, SubscriptionEndpointInfo[]> = {};
      for (const p of subProfiles) {
        try {
          next[p.id] = await invoke<SubscriptionEndpointInfo[]>(
            "get_subscription_endpoints",
            { profileId: p.id },
          );
        } catch {
          // ignore — sidecar may be missing or unreadable
        }
      }
      if (!cancelled) setEndpoints(next);
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profiles]);

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
    withBusy(profile.id, () =>
      invoke("disconnect_profile", { id: profile.id }),
    );
  };

  const onDiagnose = async (profile: Profile) => {
    setDiagBusy(profile.id);
    try {
      const result = await invoke<ProfileDiagnostics>("diagnose_profile", {
        id: profile.id,
      });
      setDiagnostics(result);
      setDiagOpen(true);
    } catch (err) {
      setError(String(err));
    } finally {
      setDiagBusy(null);
    }
  };

  const onDelete = async (profile: Profile) => {
    const ok = await confirm(`Delete profile "${profile.name}"?`, {
      title: "Delete profile",
      kind: "warning",
    });
    if (!ok) return;
    withBusy(profile.id, () =>
      invoke("delete_profile", { id: profile.id }),
    );
  };

  const onSwitchEndpoint = async (profile: Profile, index: number) => {
    setSwitching(profile.id);
    try {
      const updated = await invoke<Profile[]>("switch_subscription_endpoint", {
        profileId: profile.id,
        endpointIndex: index,
      });
      setProfiles(updated);
      const next: Record<string, SubscriptionEndpointInfo[]> = {};
      for (const p of updated.filter((p) => p.subscription !== null)) {
        try {
          next[p.id] = await invoke<SubscriptionEndpointInfo[]>(
            "get_subscription_endpoints",
            { profileId: p.id },
          );
        } catch {
          // ignore
        }
      }
      setEndpoints(next);
    } catch (err) {
      setError(String(err));
    } finally {
      setSwitching(null);
    }
  };

  const applySnippet = (snippet: ConnectionSnippet) => {
    const targetIds = new Set(snippet.profileIds);
    for (const profile of profiles) {
      const running = statusFor(profile.id).state === "running";
      if (targetIds.has(profile.id) && !running) {
        onConnect(profile);
      } else if (!targetIds.has(profile.id) && running) {
        onDisconnect(profile);
      }
    }
    setActiveSnippetId(snippet.id);
  };

  const deleteSnippet = (id: string) => {
    setSnippets((prev) => prev.filter((s) => s.id !== id));
    setActiveSnippetId((prev) => (prev === id ? null : prev));
  };

  const openSaveModal = () => {
    setNewSnippetName("");
    setSaveModalOpen(true);
  };

  const overwriteActiveSnippet = () => {
    if (!activeSnippetId) return;
    const profileIds = runningProfiles.map((p) => p.id);
    setSnippets((prev) =>
      prev.map((s) => (s.id === activeSnippetId ? { ...s, profileIds } : s)),
    );
    setSaveModalOpen(false);
  };

  const createSnippet = () => {
    const name = newSnippetName.trim();
    if (!name) return;
    const profileIds = runningProfiles.map((p) => p.id);
    const id = newSnippetId();
    setSnippets((prev) => [...prev, { id, name, profileIds }]);
    setActiveSnippetId(id);
    setSaveModalOpen(false);
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

  const openEdit = (profile: Profile) => {
    setEditing(editFormState(profile));
    setFormOpen(true);
  };

  const onFormSaved = (
    updated: Profile[],
    inspection: ProfileInspection | null,
  ) => {
    setProfiles(updated);
    setFormOpen(false);
    setEditing(null);
    setError(null);
    void refreshAll();
    if (inspection && editing) {
      const notes = [
        ...inspection.analysis.warnings,
        ...inspection.conflicts.map((c) => c.message),
      ];
      setSaveNotice(
        notes.length > 0
          ? {
              profileName: editing.name || editing.id,
              inspection,
            }
          : null,
      );
    }
  };

  const onImported = (result: BatchImportResult) => {
    setProfiles(result.profiles);
    setImportOpen(false);
    void refreshAll();
    if (result.errors.length > 0) {
      setImportErrors(result.errors.map((e) => `${e.path}: ${e.error}`));
    }
  };

  if (loading) {
    return (
      <Page width="narrow">
        <section>
          <div className="profiles-toolbar">
            <h2>Connections</h2>
          </div>
          <div className="connection-list">
            <ConnectionCardSkeleton />
            <ConnectionCardSkeleton />
            <ConnectionCardSkeleton />
          </div>
        </section>
      </Page>
    );
  }

  const runningProfiles = profiles.filter(
    (p) => statusFor(p.id).state === "running",
  );

  const activeSnippet = snippets.find((s) => s.id === activeSnippetId) ?? null;
  const isActiveSnippetDirty =
    activeSnippet !== null &&
    !sameIds(
      activeSnippet.profileIds,
      runningProfiles.map((p) => p.id),
    );

  const lowerSearch = search.trim().toLowerCase();
  const filteredProfiles = lowerSearch
    ? profiles.filter(
        (p) =>
          p.name.toLowerCase().includes(lowerSearch) ||
          p.interfaceName.toLowerCase().includes(lowerSearch),
      )
    : profiles;

  const groups: { backend: TunnelBackend; items: Profile[] }[] = (
    ["wireGuard", "openVpn", "xray", "none"] as TunnelBackend[]
  )
    .map((backend) => ({
      backend,
      items: filteredProfiles.filter((p) => p.backend === backend),
    }))
    .filter((g) => g.items.length > 0);

  return (
    <Page width="narrow">
    <section>
      <div className="profiles-toolbar">
        <h2>Connections</h2>
        <button className="profile-new-btn" onClick={() => setAddMenuOpen(true)}>
          + Add connection
        </button>
        <button
          className="profile-import-btn"
          onClick={() => setImportOpen(true)}
        >
          Import…
        </button>
      </div>
      <p className="profiles-note">
        WireGuard, OpenVPN, interface changes, and policy routes require
        administrator privileges. Several connections can run at once.
      </p>

      {profiles.length > 0 && (
        <div className="snippets-bar">
          <span className="snippets-label">Snippets</span>
          <div className="snippets-chips">
            {snippets.map((snippet) => {
              const isActive = snippet.id === activeSnippetId;
              const isDirty = isActive && isActiveSnippetDirty;
              return (
                <div
                  key={snippet.id}
                  className={`snippet-chip ${isDirty ? "dirty" : isActive ? "active" : ""}`}
                >
                  <button
                    type="button"
                    className="snippet-chip-apply"
                    onClick={() => applySnippet(snippet)}
                    title={
                      isDirty
                        ? "Connections have changed since this snippet was saved"
                        : `Switch to exactly these ${snippet.profileIds.length} connection${
                            snippet.profileIds.length === 1 ? "" : "s"
                          }`
                    }
                  >
                    {snippet.name}
                  </button>
                  <button
                    type="button"
                    className="snippet-chip-delete"
                    onClick={() => deleteSnippet(snippet.id)}
                    title="Delete snippet"
                  >
                    ×
                  </button>
                </div>
              );
            })}
            <button
              type="button"
              className="snippet-chip-add"
              onClick={openSaveModal}
              disabled={runningProfiles.length === 0}
              title={
                runningProfiles.length === 0
                  ? "Connect something first"
                  : "Save the currently running connections as a snippet"
              }
            >
              + Save current
            </button>
          </div>
        </div>
      )}

      {profiles.length > 0 && (
        <input
          className="filter-search connections-search"
          type="text"
          placeholder="Search connections…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      )}

      {importErrors && (
        <div className="save-notice">
          <div className="diagnostics-head">
            <span>Import finished with errors</span>
            <button type="button" onClick={() => setImportErrors(null)}>
              Dismiss
            </button>
          </div>
          <ul className="save-notice-list">
            {importErrors.map((e, i) => (
              <li key={i}>{e}</li>
            ))}
          </ul>
        </div>
      )}

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
            <span>Saved "{saveNotice.profileName}" — review notes</span>
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

      {profiles.length === 0 ? (
        <p className="empty-state">No profiles yet. Create one to get started.</p>
      ) : filteredProfiles.length === 0 ? (
        <p className="empty-state">No connections match "{search}".</p>
      ) : (
        groups.map((group) => {
          const isCollapsed = collapsedGroups.has(group.backend);
          return (
          <div key={group.backend} className="profile-group">
            <button
              type="button"
              className="profile-group-header"
              onClick={() => toggleGroupCollapsed(group.backend)}
              aria-expanded={!isCollapsed}
            >
              <ChevronIcon size={13} collapsed={isCollapsed} />
              {backendIcon(group.backend, 18)}
              <span className="profile-group-title">
                {BACKEND_LABELS[group.backend]}
              </span>
              <span className="profile-group-count">
                {group.items.length}
              </span>
            </button>
            {!isCollapsed && (
            <div className="connection-list">
              {group.items.map((profile) => {
                const status = statusFor(profile.id);
                const isBusy = busy.has(profile.id);
                const inspection = inspections[profile.id];
                const isExpanded = expanded.has(profile.id);
                const detailCount =
                  profile.routes.length + profile.domainPolicies.length;
                const rate = status.state === "running" ? rateFor(profile) : null;
                return (
                  <div
                    key={profile.id}
                    className={`connection-card ${
                      status.state === "running" ? "state-active" : ""
                    } ${status.state === "failed" ? "state-failed" : ""}`}
                  >
                    <div className="connection-card-main">
                      <span className={`backend-avatar backend-avatar-${profile.backend}`}>
                        {backendIcon(profile.backend, 18)}
                      </span>
                      <div className="connection-card-info">
                        <div className="connection-card-name-row">
                          <span className="connection-card-name">{profile.name}</span>
                          {inspection?.managedConfig === true && (
                            <span className="badge badge-managed">Managed</span>
                          )}
                          {profile.useSystemProxy && (
                            <span className="badge badge-managed">Proxy</span>
                          )}
                          {inspection?.managedConfig === false && (
                            <span className="badge badge-external">External</span>
                          )}
                        </div>
                        <span className="connection-card-meta">
                          {status.state === "failed" && status.message
                            ? status.message
                            : rate
                              ? `↓ ${formatRate(rate.rxRate)} · ↑ ${formatRate(rate.txRate)}`
                              : profile.interfaceName || "No target interface"}
                        </span>
                      </div>
                      <ToggleSwitch
                        checked={status.state === "running"}
                        onChange={() =>
                          status.state === "running"
                            ? onDisconnect(profile)
                            : onConnect(profile)
                        }
                        disabled={isBusy}
                        busy={isBusy}
                        title={status.state === "running" ? "Disconnect" : "Connect"}
                      />
                      <OverflowMenu
                        title="Profile actions"
                        items={[
                          { label: "Edit", onClick: () => openEdit(profile), disabled: isBusy },
                          {
                            label: diagBusy === profile.id ? "Running diagnostics…" : "Diagnostics",
                            onClick: () => onDiagnose(profile),
                            disabled: isBusy || diagBusy === profile.id,
                          },
                          {
                            label: "Delete",
                            onClick: () => onDelete(profile),
                            disabled: isBusy,
                            danger: true,
                          },
                        ]}
                      />
                    </div>

                    {profile.backend === "xray" && profile.xraySocksPort !== null && (
                      <div className="interface-row">
                        <span className="row-label">SOCKS5</span>
                        <span className="row-value mono">
                          127.0.0.1:{profile.xraySocksPort}
                        </span>
                      </div>
                    )}
                    {profile.subscription && endpoints[profile.id] && (
                      <div className="interface-row">
                        <span className="row-label">Endpoint</span>
                        <span className="row-value">
                          <select
                            value={
                              endpoints[profile.id].findIndex(
                                (e) => e.active,
                              )
                            }
                            onChange={(e) =>
                              onSwitchEndpoint(
                                profile,
                                Number(e.target.value),
                              )
                            }
                            disabled={
                              switching === profile.id ||
                              isBusy ||
                              status.state === "running"
                            }
                          >
                            {endpoints[profile.id].map((ep, i) => (
                              <option key={i} value={i}>
                                {ep.name}
                              </option>
                            ))}
                          </select>
                          {switching === profile.id && " switching…"}
                        </span>
                      </div>
                    )}
                    {profile.useSystemProxy && (
                      <div className="interface-row">
                        <span className="row-label">Proxy bypass</span>
                        <span className="row-value mono">
                          {profile.proxyBypass.join("; ") || "none"}
                        </span>
                      </div>
                    )}

                    {detailCount > 0 && (
                      <div className="connection-card-details">
                        <button
                          type="button"
                          className="connection-detail-toggle"
                          onClick={() => toggleExpanded(profile.id)}
                        >
                          <ChevronIcon size={13} collapsed={!isExpanded} />
                          {profile.routes.length > 0 &&
                            `${profile.routes.length} route${profile.routes.length === 1 ? "" : "s"}`}
                          {profile.routes.length > 0 && profile.domainPolicies.length > 0 && " · "}
                          {profile.domainPolicies.length > 0 &&
                            `${profile.domainPolicies.length} domain rule${profile.domainPolicies.length === 1 ? "" : "s"}`}
                        </button>
                        {isExpanded && (
                          <>
                            {profile.domainPolicies.length > 0 && (
                              <div className="interface-section">
                                <span className="section-label">Domain rules</span>
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
                            )}
                            {profile.routes.length > 0 && (
                              <div className="interface-section">
                                <span className="section-label">Routes</span>
                                <ul className="profile-route-list">
                                  {profile.routes.map((route, i) => (
                                    <li key={i}>
                                      <span className="mono">
                                        {route.destination}
                                      </span>
                                      <span className="family-tag">
                                        metric {route.metric}
                                      </span>
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            )}
                          </>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
            )}
          </div>
          );
        })
      )}

      <ProfileFormModal
        open={formOpen}
        editing={editing}
        interfaces={interfaces}
        onClose={() => {
          setFormOpen(false);
          setEditing(null);
        }}
        onSaved={onFormSaved}
        onError={(message) => setError(message)}
      />

      <ImportModal
        open={importOpen}
        onClose={() => setImportOpen(false)}
        onImported={onImported}
        onError={(message) => setError(message)}
      />

      <DiagnosticsModal
        open={diagOpen}
        diagnostics={diagnostics}
        profiles={profiles}
        onClose={() => {
          setDiagOpen(false);
          setDiagnostics(null);
        }}
      />

      <AddConnectionMenu
        open={addMenuOpen}
        onClose={() => setAddMenuOpen(false)}
        onChooseImport={handleChooseImport}
        onChooseBackend={handleChooseBackend}
      />

      <Modal
        open={saveModalOpen}
        title="Save snippet"
        onClose={() => setSaveModalOpen(false)}
        maxWidth="420px"
        footer={
          <>
            <button type="button" onClick={() => setSaveModalOpen(false)}>
              Cancel
            </button>
            <button
              type="button"
              className="profile-save-btn"
              onClick={createSnippet}
              disabled={!newSnippetName.trim()}
            >
              Save as new
            </button>
          </>
        }
      >
        <div className="interface-section">
          <span className="section-label">
            Will include {runningProfiles.length} connection
            {runningProfiles.length === 1 ? "" : "s"}
          </span>
          <ul className="profile-route-list">
            {runningProfiles.map((p) => (
              <li key={p.id}>{p.name}</li>
            ))}
          </ul>
        </div>

        {activeSnippet && isActiveSnippetDirty && (
          <button
            type="button"
            className="snippet-overwrite-btn"
            onClick={overwriteActiveSnippet}
          >
            Update "{activeSnippet.name}" with these connections
          </button>
        )}

        <label>
          {activeSnippet ? "Or save as a new snippet" : "Name"}
          <input
            type="text"
            value={newSnippetName}
            onChange={(e) => setNewSnippetName(e.target.value)}
            placeholder="Work"
            autoFocus
          />
        </label>
      </Modal>

    </section>
    </Page>
  );
}
