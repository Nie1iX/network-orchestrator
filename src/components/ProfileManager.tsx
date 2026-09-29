import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { confirm } from "@tauri-apps/plugin-dialog";
import { ensureElevation } from "../elevation";
import { usePlatformCapabilities } from "../platform";
import {
  backendIcon,
  ChevronIcon,
  CloseIcon,
  GripVerticalIcon,
  PlusIcon,
} from "../icons";
import AddConnectionMenu from "./AddConnectionMenu";
import DiagnosticsModal from "./DiagnosticsModal";
import ImportModal from "./ImportModal";
import Modal from "./Modal";
import Page from "./Page";
import Skeleton from "./ui/Skeleton";
import ToggleSwitch from "./ui/ToggleSwitch";
import OverflowMenu from "./ui/OverflowMenu";
import RateText from "./ui/RateText";
import { useToast } from "./ui/Toast";
import { formatBytes } from "../format";
import ProfileFormModal, {
  editFormState,
  newFormState,
  type ProfileFormState,
} from "./ProfileFormModal";
import {
  AlwaysOnKind,
  AlwaysOnListResult,
  AlwaysOnSetResult,
  BatchImportResult,
  DomainPolicy,
  DomainRouteTarget,
  NetworkInterface,
  Profile,
  ProfileDiagnostics,
  ProfileInspection,
  SubscriptionEndpointInfo,
  SubscriptionDelayResult,
  SubscriptionRefreshResult,
  TunnelBackend,
  TunnelState,
  TunnelStatus,
} from "../types";

const BACKEND_LABELS: Record<TunnelBackend, string> = {
  none: "Static routes",
  wireGuard: "WireGuard",
  openVpn: "OpenVPN",
  xray: "Xray",
};

interface AutoConnectResult {
  failedCount: number;
  startupFailed: boolean;
}

const DOMAIN_TARGET_LABELS: Record<DomainRouteTarget, string> = {
  block: "Block",
  proxy: "Proxy",
  direct: "Direct",
};

/** Counts real selectors; `#` comment lines are stored in `domains` for
 * round-trip through the editor but are not rules. */
function countPolicyRules(
  policies: DomainPolicy[],
  target?: DomainRouteTarget,
): number {
  return policies
    .filter((p) => target === undefined || p.target === target)
    .flatMap((p) => p.domains)
    .filter((d) => !d.trimStart().startsWith("#")).length;
}

function requiresElevation(profile: Profile): boolean {
  return (
    profile.backend === "wireGuard" ||
    profile.backend === "openVpn" ||
    profile.routes.length > 0
  );
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

interface ProfileGroup {
  backend: TunnelBackend;
  items: Profile[];
}

/** Applies a new order of one backend group to the flat profile list —
 * mirrors `ProfileStore::reorder` for optimistic updates. */
function applyGroupOrder(
  profiles: Profile[],
  backend: TunnelBackend,
  orderedIds: string[],
): Profile[] {
  const byId = new Map(
    profiles.filter((p) => p.backend === backend).map((p) => [p.id, p]),
  );
  const ordered = orderedIds
    .map((id) => byId.get(id))
    .filter((p): p is Profile => p !== undefined);
  let i = 0;
  return profiles.map((p) =>
    p.backend === backend && i < ordered.length ? ordered[i++] : p,
  );
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
  const caps = usePlatformCapabilities();
  const toast = useToast();
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [statuses, setStatuses] = useState<TunnelStatus[]>([]);
  const [alwaysOn, setAlwaysOn] = useState<AlwaysOnListResult | null>(null);
  const [resumingAlwaysOn, setResumingAlwaysOn] = useState(false);
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
  const [importErrors, setImportErrors] = useState<string[] | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [endpoints, setEndpoints] = useState<
    Record<string, SubscriptionEndpointInfo[]>
  >({});
  const [switching, setSwitching] = useState<string | null>(null);
  const [refreshingSubscription, setRefreshingSubscription] = useState<string | null>(null);
  const [settingRefreshInterval, setSettingRefreshInterval] = useState<string | null>(null);
  const [openVpnCredentialProfile, setOpenVpnCredentialProfile] = useState<Profile | null>(null);
  const [openVpnUsername, setOpenVpnUsername] = useState("");
  const [openVpnPassword, setOpenVpnPassword] = useState("");
  const [openVpnKeyPassphrase, setOpenVpnKeyPassphrase] = useState("");
  const [rememberOpenVpnCredentials, setRememberOpenVpnCredentials] = useState(false);
  const [openVpnCredentialError, setOpenVpnCredentialError] = useState<string | null>(null);
  const [openVpnCredentialBusy, setOpenVpnCredentialBusy] = useState(false);
  const [measuringDelay, setMeasuringDelay] = useState<string | null>(null);
  const [delayResults, setDelayResults] = useState<
    Record<string, { index: number; result: SubscriptionDelayResult }>
  >({});
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
  const prevTunnelStates = useRef<Record<string, TunnelState>>({});
  const [dragState, setDragState] = useState<{
    backend: TunnelBackend;
    profileId: string;
  } | null>(null);
  const [dropTarget, setDropTarget] = useState<{
    profileId: string;
    before: boolean;
  } | null>(null);

  useEffect(() => {
    let active = true;
    let stopListening: (() => void) | null = null;
    const showResult = (result: AutoConnectResult | null) => {
      if (!active || !result) return;
      if (result.startupFailed) {
        toast(
          "error",
          "Auto-connect could not start. Check Network daemon in Settings and profile Diagnostics.",
        );
      } else if (result.failedCount > 0) {
        toast(
          "error",
          `${result.failedCount} profile(s) could not connect automatically. Check Diagnostics and retry Connect manually.`,
        );
      }
    };
    void (async () => {
      try {
        const stop = await listen<AutoConnectResult>(
          "auto-connect-result",
          (event) => showResult(event.payload),
        );
        if (!active) {
          stop();
          return;
        }
        stopListening = stop;
        showResult(await invoke<AutoConnectResult | null>("get_auto_connect_result"));
      } catch {
        // The profile list remains usable if the startup result is unavailable.
      }
    })();
    return () => {
      active = false;
      stopListening?.();
    };
  }, []);

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
    try {
      setAlwaysOn(await invoke<AlwaysOnListResult>("get_always_on_profiles"));
    } catch {
      // Keep the last known enrollment and pause state until the daemon returns.
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
        setAlwaysOn(await invoke<AlwaysOnListResult>("get_always_on_profiles"));
      } catch {
        setAlwaysOn(null);
      }
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
      return profileData;
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
    const onRouteChanged = () => {
      void (async () => {
        const updated = await refreshAll();
        if (!updated) return;
        const next: Record<string, SubscriptionEndpointInfo[]> = {};
        for (const profile of updated.filter((profile) => profile.subscription !== null)) {
          try {
            next[profile.id] = await invoke<SubscriptionEndpointInfo[]>(
              "get_subscription_endpoints",
              { profileId: profile.id },
            );
          } catch {
            // Keep the profile visible if its sidecar is temporarily unavailable.
          }
        }
        setEndpoints(next);
      })();
    };
    window.addEventListener("route-changed", onRouteChanged);
    return () => window.removeEventListener("route-changed", onRouteChanged);
  }, [refreshAll]);

  useEffect(() => {
    const interval = setInterval(refreshStatuses, 2000);
    return () => clearInterval(interval);
  }, [refreshStatuses]);

  useEffect(() => {
    const prev = prevTunnelStates.current;
    const next: Record<string, TunnelState> = {};
    for (const status of statuses) {
      next[status.profileId] = status.state;
      const before = prev[status.profileId];
      if (before !== undefined && before !== "failed" && status.state === "failed") {
        const name =
          profiles.find((profile) => profile.id === status.profileId)?.name ??
          "Profile";
        toast(
          "error",
          status.message
            ? `${name} failed to connect: ${status.message}`
            : `${name} failed to connect. Run Diagnostics for details.`,
        );
      }
    }
    prevTunnelStates.current = next;
  }, [statuses, profiles]);

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

  const commitReorder = async (backend: TunnelBackend, orderedIds: string[]) => {
    const previous = profiles;
    setProfiles(applyGroupOrder(previous, backend, orderedIds));
    try {
      setProfiles(
        await invoke<Profile[]>("reorder_profiles", { backend, orderedIds }),
      );
    } catch (err) {
      setProfiles(previous);
      toast("error", String(err));
    }
  };

  const moveProfileInGroup = (items: Profile[], profileId: string, delta: number) => {
    const index = items.findIndex((p) => p.id === profileId);
    const swap = index + delta;
    if (index < 0 || swap < 0 || swap >= items.length) return;
    const ids = items.map((p) => p.id);
    [ids[index], ids[swap]] = [ids[swap], ids[index]];
    void commitReorder(items[index].backend, ids);
  };

  const onCardDragStart = (
    event: React.DragEvent<HTMLElement>,
    profile: Profile,
  ) => {
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", profile.id);
    // A compact name pill as the drag ghost: snapshotting the whole card
    // renders oversized on HiDPI/scaled webviews.
    const preview = document.createElement("div");
    preview.className = "connection-drag-preview";
    preview.textContent = profile.name;
    document.body.appendChild(preview);
    event.dataTransfer.setDragImage(preview, 12, 12);
    requestAnimationFrame(() => preview.remove());
    setDragState({ backend: profile.backend, profileId: profile.id });
    setDropTarget(null);
  };

  const onCardDragEnd = () => {
    setDragState(null);
    setDropTarget(null);
  };

  const pointerInUpperHalf = (event: React.DragEvent<HTMLElement>): boolean => {
    const rect = event.currentTarget.getBoundingClientRect();
    return event.clientY < rect.top + rect.height / 2;
  };

  const onCardDragOver = (
    event: React.DragEvent<HTMLElement>,
    group: ProfileGroup,
    target: Profile,
  ) => {
    if (!dragState) return;
    if (dragState.backend !== group.backend || dragState.profileId === target.id) {
      setDropTarget(null);
      return;
    }
    event.preventDefault();
    event.dataTransfer.dropEffect = "move";
    const before = pointerInUpperHalf(event);
    setDropTarget((prev) =>
      prev && prev.profileId === target.id && prev.before === before
        ? prev
        : { profileId: target.id, before },
    );
  };

  const onCardDrop = (
    event: React.DragEvent<HTMLElement>,
    group: ProfileGroup,
    target: Profile,
  ) => {
    if (
      !dragState ||
      dragState.backend !== group.backend ||
      dragState.profileId === target.id
    ) {
      return;
    }
    event.preventDefault();
    const ids = group.items
      .map((p) => p.id)
      .filter((id) => id !== dragState.profileId);
    const at = ids.indexOf(target.id);
    ids.splice(pointerInUpperHalf(event) ? at : at + 1, 0, dragState.profileId);
    setDragState(null);
    setDropTarget(null);
    if (ids.join(",") !== group.items.map((p) => p.id).join(",")) {
      void commitReorder(group.backend, ids);
    }
  };

  const onListDragLeave = (event: React.DragEvent<HTMLElement>) => {
    if (!event.currentTarget.contains(event.relatedTarget as Node | null)) {
      setDropTarget(null);
    }
  };

  const withBusy = async (
    id: string,
    action: () => Promise<unknown>,
    onError?: (err: unknown) => void,
  ) => {
    setBusy((prev) => new Set(prev).add(id));
    try {
      await action();
      await refreshAll();
    } catch (err) {
      if (onError) onError(err);
      else setError(String(err));
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
        toast("error", String(err));
        return;
      }
    }
    withBusy(profile.id, async () => {
      const status = await invoke<TunnelStatus>("connect_profile", {
        id: profile.id,
      });
      if (status.state === "failed") {
        toast(
          "error",
          status.message ??
            `${profile.name} failed to connect. Run Diagnostics for details.`,
        );
      } else if (status.message) {
        toast("info", status.message);
      }
    }, (err) => {
      if (caps?.os === "linux" && profile.backend === "openVpn" && String(err) === "OpenVPN credentials required") {
        setOpenVpnCredentialProfile(profile);
        setOpenVpnCredentialError(null);
      } else {
        toast("error", String(err));
      }
    });
  };

  const closeOpenVpnCredentials = () => {
    if (openVpnCredentialBusy) return;
    setOpenVpnCredentialProfile(null);
    setOpenVpnUsername("");
    setOpenVpnPassword("");
    setOpenVpnKeyPassphrase("");
    setRememberOpenVpnCredentials(false);
    setOpenVpnCredentialError(null);
  };

  const submitOpenVpnCredentials = async () => {
    if (!openVpnCredentialProfile) return;
    if (openVpnPassword && !openVpnUsername) {
      setOpenVpnCredentialError("Enter a username with the password.");
      return;
    }
    if (!openVpnUsername && !openVpnKeyPassphrase) {
      setOpenVpnCredentialError("Enter the credentials required by this profile.");
      return;
    }
    setOpenVpnCredentialBusy(true);
    setOpenVpnCredentialError(null);
    try {
      const status = await invoke<TunnelStatus>("connect_openvpn_with_credentials", {
        id: openVpnCredentialProfile.id,
        credentials: {
          ...(openVpnUsername ? { authUserPass: { username: openVpnUsername, password: openVpnPassword } } : {}),
          ...(openVpnKeyPassphrase ? { privateKeyPassphrase: openVpnKeyPassphrase } : {}),
        },
        remember: rememberOpenVpnCredentials,
      });
      if (status.message) toast("info", status.message);
      setOpenVpnCredentialProfile(null);
      setOpenVpnUsername("");
      setOpenVpnPassword("");
      setOpenVpnKeyPassphrase("");
      setRememberOpenVpnCredentials(false);
      await refreshAll();
    } catch (err) {
      setOpenVpnCredentialError(`OpenVPN connection failed: ${String(err)}`);
    } finally {
      setOpenVpnCredentialBusy(false);
    }
  };

  const onDisconnect = async (profile: Profile) => {
    if (requiresElevation(profile)) {
      try {
        if (!(await ensureElevation(`Disconnecting ${profile.name}`))) return;
      } catch (err) {
        toast("error", String(err));
        return;
      }
    }
    withBusy(profile.id, () =>
      invoke("disconnect_profile", { id: profile.id }),
      (err) => toast("error", String(err)),
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
    if (alwaysOn?.profiles.some((item) => item.profileId === profile.id)) {
      setError("Disable always-on before deleting this profile.");
      return;
    }
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
      setDelayResults((current) => {
        const updated = { ...current };
        delete updated[profile.id];
        return updated;
      });
    } catch (err) {
      setError(String(err));
    } finally {
      setSwitching(null);
    }
  };

  const onRefreshSubscription = async (profile: Profile) => {
    setRefreshingSubscription(profile.id);
    try {
      const result = await invoke<SubscriptionRefreshResult>("refresh_subscription", {
        id: profile.id,
      });
      await refreshAll();
      const updated = await invoke<SubscriptionEndpointInfo[]>(
        "get_subscription_endpoints",
        { profileId: profile.id },
      );
      setEndpoints((current) => ({ ...current, [profile.id]: updated }));
      setDelayResults((current) => {
        const next = { ...current };
        delete next[profile.id];
        return next;
      });
      const details = [
        `Subscription refreshed: ${result.endpointCount} endpoint${result.endpointCount === 1 ? "" : "s"}.`,
      ];
      if (result.skippedCount > 0) details.push(`${result.skippedCount} skipped.`);
      if (result.fallbackUsed) details.push("Selected endpoint disappeared; first endpoint selected.");
      if (result.cleanupFailed) details.push("Previous config cleanup failed.");
      toast("info", details.join(" "));
    } catch (err) {
      setError(String(err));
    } finally {
      setRefreshingSubscription(null);
    }
  };

  const onSetRefreshInterval = async (profile: Profile, minutes: number | null) => {
    setSettingRefreshInterval(profile.id);
    try {
      const updated = await invoke<Profile[]>("set_subscription_refresh_interval", {
        profileId: profile.id,
        refreshIntervalMinutes: minutes,
      });
      setProfiles(updated);
    } catch {
      setError("Cannot update subscription refresh interval.");
    } finally {
      setSettingRefreshInterval(null);
    }
  };

  const onMeasureDelay = async (profile: Profile) => {
    const index =
      endpoints[profile.id]?.findIndex((endpoint) => endpoint.active) ?? -1;
    if (index < 0) return;
    setMeasuringDelay(profile.id);
    try {
      const result = await invoke<SubscriptionDelayResult>(
        "measure_subscription_endpoint_delay",
        { profileId: profile.id, endpointIndex: index },
      );
      setDelayResults((current) => ({
        ...current,
        [profile.id]: { index, result },
      }));
    } catch {
      setDelayResults((current) => ({
        ...current,
        [profile.id]: {
          index,
          result: { delayMs: null, error: "Delay check failed" },
        },
      }));
    } finally {
      setMeasuringDelay(null);
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
    setEditing(newFormState(backend, caps?.os));
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
    if (alwaysOn?.profiles.some((item) => item.profileId === profile.id)) {
      setError("Disable always-on before editing this profile.");
      return;
    }
    setEditing(editFormState(profile));
    setFormOpen(true);
  };

  const onToggleAlwaysOn = async (profile: Profile, kind: AlwaysOnKind, enrolled: boolean) => {
    if (!enrolled && kind === "wireGuard") {
      const approved = await confirm(
        "Always-on stores a copy of this WireGuard config, including its private key, in root-only system state. It can connect before you sign in. Enable it?",
        { title: "Enable always-on WireGuard", kind: "warning" },
      );
      if (!approved) return;
    }
    await withBusy(profile.id, async () => {
      if (enrolled) {
        await invoke("remove_always_on_profile", { kind, profileId: profile.id });
      } else {
        const result = await invoke<AlwaysOnSetResult>("set_always_on_profile", { id: profile.id });
        if (!result.active) toast("info", "Always-on saved. Resume always-on to activate it.");
      }
    });
  };

  const onResumeAlwaysOn = async () => {
    setResumingAlwaysOn(true);
    try {
      await invoke("resume_always_on");
      await refreshAll();
    } catch (err) {
      setError(String(err));
    } finally {
      setResumingAlwaysOn(false);
    }
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
    // A running Xray TUN profile picks up its new rules in place; the daemon
    // rejects reload when kernel-level fields changed, and a manual reconnect
    // stays as the fallback.
    if (
      editing &&
      !editing.isNew &&
      editing.backend === "xray" &&
      editing.xrayMode === "tun" &&
      statusFor(editing.id).state === "running"
    ) {
      invoke<TunnelStatus>("reload_xray_profile", { id: editing.id })
        .then((status) => {
          setStatuses((current) => [
            ...current.filter((entry) => entry.profileId !== status.profileId),
            status,
          ]);
          toast(
            status.message ? "info" : "success",
            status.message ?? `Reloaded ${editing.name || editing.id}`,
          );
        })
        .catch((err) =>
          toast("info", `Reconnect the profile to apply changes (${String(err)})`),
        );
    }
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

  const groups: ProfileGroup[] = (
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
        <button
          className="profile-new-btn btn-primary btn-with-icon"
          onClick={() => setAddMenuOpen(true)}
        >
          <PlusIcon size={14} /> Add connection
        </button>
        <button
          className="btn-with-icon"
          onClick={() => setImportOpen(true)}
        >
          Import…
        </button>
      </div>
      <p className="profiles-note">
        WireGuard, OpenVPN, interface changes, and policy routes require
        administrator privileges. Several connections can run at once.
      </p>

      {caps?.os === "linux" && (
        <p className="profiles-note">
          Always-on before sign-in is available for WireGuard and static routes.
          OpenVPN and Xray are not supported.
        </p>
      )}

      {caps?.os === "linux" && alwaysOn?.paused && (
        <div className="runtime-notice" role="status">
          <span>Always-on is paused after Disconnect all.</span>
          <button type="button" onClick={onResumeAlwaysOn} disabled={resumingAlwaysOn}>
            {resumingAlwaysOn ? "Resuming…" : "Resume always-on"}
          </button>
        </div>
      )}

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
                    <CloseIcon size={12} />
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
              <PlusIcon size={12} /> Save current
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
          const canReorder = !lowerSearch && group.items.length > 1;
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
            <div className="connection-list" onDragLeave={onListDragLeave}>
              {group.items.map((profile, index) => {
                const status = statusFor(profile.id);
                const isBusy = busy.has(profile.id);
                const alwaysOnKind: AlwaysOnKind | null =
                  profile.backend === "wireGuard" ? "wireGuard" :
                  profile.backend === "none" ? "staticRoutes" : null;
                const alwaysOnEntry = alwaysOn?.profiles.find(
                  (item) => item.profileId === profile.id && item.kind === alwaysOnKind,
                );
                const canEnableAlwaysOn = alwaysOnKind !== null &&
                  alwaysOn?.supportedKinds.includes(alwaysOnKind) &&
                  (alwaysOnKind === "wireGuard" ||
                    (profile.interfaceName.length > 0 && profile.routes.length > 0));
                const inspection = inspections[profile.id];
                const isExpanded = expanded.has(profile.id);
                const ruleCount = countPolicyRules(profile.domainPolicies);
                const detailCount = profile.routes.length + ruleCount;
                const rate = status.state === "running" ? rateFor(profile) : null;
                return (
                  <div
                    key={profile.id}
                    className={`connection-card ${
                      status.state === "running" ? "state-active" : ""
                    } ${status.state === "failed" ? "state-failed" : ""} ${
                      dragState?.profileId === profile.id ? "drag-source" : ""
                    } ${
                      dropTarget?.profileId === profile.id
                        ? dropTarget.before
                          ? "drop-before"
                          : "drop-after"
                        : ""
                    }`}
                    onDragOver={(event) => onCardDragOver(event, group, profile)}
                    onDrop={(event) => onCardDrop(event, group, profile)}
                  >
                    <div className="connection-card-main">
                      <span
                        className={`connection-drag-handle${
                          canReorder ? "" : " disabled"
                        }`}
                        draggable={canReorder}
                        onDragStart={(event) => onCardDragStart(event, profile)}
                        onDragEnd={onCardDragEnd}
                        title={canReorder ? "Drag to reorder" : undefined}
                      >
                        <GripVerticalIcon size={15} />
                      </span>
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
                          {alwaysOnEntry && (
                            <span className="badge badge-managed">
                              {alwaysOnEntry.enabled
                                ? alwaysOn?.paused ? "Always-on paused" : "Always-on"
                                : "Always-on cleanup pending"}
                            </span>
                          )}
                          {inspection?.managedConfig === false && (
                            <span className="badge badge-external">External</span>
                          )}
                        </div>
                        <span
                          className="connection-card-meta"
                          title={
                            status.state === "failed" && status.message
                              ? status.message
                              : undefined
                          }
                        >
                          {status.state === "failed" && status.message ? (
                            status.message
                          ) : rate ? (
                            <RateText rx={rate.rxRate} tx={rate.txRate} live />
                          ) : (
                            profile.interfaceName || "No target interface"
                          )}
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
                            label: "Move up",
                            onClick: () => moveProfileInGroup(group.items, profile.id, -1),
                            disabled: isBusy || !canReorder || index === 0,
                          },
                          {
                            label: "Move down",
                            onClick: () => moveProfileInGroup(group.items, profile.id, 1),
                            disabled: isBusy || !canReorder || index === group.items.length - 1,
                          },
                          ...(caps?.os === "linux" && alwaysOnKind && (alwaysOnEntry || canEnableAlwaysOn) ? [{
                            label: alwaysOnEntry ? "Disable always-on" : "Enable always-on before sign-in",
                            onClick: () => onToggleAlwaysOn(profile, alwaysOnKind, Boolean(alwaysOnEntry)),
                            disabled: isBusy,
                          }] : []),
                          ...(caps?.os === "linux" && profile.backend === "openVpn" ? [{
                            label: "Credentials…",
                            onClick: () => {
                              setOpenVpnCredentialProfile(profile);
                              setOpenVpnCredentialError(null);
                            },
                            disabled: isBusy,
                          }] : []),
                          ...(profile.subscription && endpoints[profile.id] ? [
                            {
                              label: refreshingSubscription === profile.id ? "Refreshing…" : "Refresh subscription",
                              onClick: () => onRefreshSubscription(profile),
                              disabled:
                                refreshingSubscription === profile.id ||
                                switching === profile.id ||
                                isBusy ||
                                status.state === "running",
                            },
                            {
                              label: measuringDelay === profile.id ? "Testing…" : "Test delay",
                              onClick: () => onMeasureDelay(profile),
                              disabled:
                                measuringDelay === profile.id ||
                                switching === profile.id ||
                                refreshingSubscription === profile.id ||
                                isBusy,
                            },
                          ] : []),
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

                    {profile.backend === "xray" &&
                      profile.xrayMode === "socks" &&
                      profile.xraySocksPort !== null && (
                        <div className="interface-row">
                          <span className="row-label">SOCKS5</span>
                          <span className="row-value mono">
                            127.0.0.1:{profile.xraySocksPort}
                          </span>
                        </div>
                      )}
                    {profile.backend === "xray" &&
                      profile.xrayMode === "socks" &&
                      profile.xrayHttpPort !== null && (
                        <div className="interface-row">
                          <span className="row-label">HTTP CONNECT</span>
                          <span className="row-value mono">
                            127.0.0.1:{profile.xrayHttpPort}
                          </span>
                        </div>
                      )}
                    {profile.subscription && endpoints[profile.id] && (
                      <div className="interface-row">
                        <span className="row-label">Endpoint</span>
                        <span className="row-value endpoint-row">
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
                              refreshingSubscription === profile.id ||
                              isBusy ||
                              status.state === "running"
                            }
                            title={
                              status.state === "running"
                                ? "Disconnect to switch endpoints"
                                : undefined
                            }
                          >
                            {endpoints[profile.id].map((ep, i) => (
                              <option key={i} value={i}>
                                {ep.name}
                              </option>
                            ))}
                          </select>
                          {switching === profile.id && (
                            <span className="endpoint-note">switching…</span>
                          )}
                          {delayResults[profile.id]?.index ===
                            endpoints[profile.id].findIndex((e) => e.active) && (
                              <span className="badge badge-managed">
                                {delayResults[profile.id].result.delayMs !== null
                                  ? `${delayResults[profile.id].result.delayMs} ms`
                                  : delayResults[profile.id].result.error}
                              </span>
                            )}
                        </span>
                      </div>
                    )}
                    {profile.subscription && (
                      <div className="interface-row">
                        <span className="row-label">Auto-refresh</span>
                        <span className="row-value">
                          <select
                            value={profile.subscription.refreshIntervalMinutes ?? ""}
                            onChange={(event) => onSetRefreshInterval(profile, event.target.value ? Number(event.target.value) : null)}
                            disabled={settingRefreshInterval === profile.id || isBusy}
                          >
                            <option value="">Off</option>
                            <option value="15">Every 15 minutes</option>
                            <option value="60">Every hour</option>
                            <option value="360">Every 6 hours</option>
                          </select>
                        </span>
                      </div>
                    )}

                    {(detailCount > 0 ||
                      profile.subscription !== null ||
                      (profile.backend === "xray" && profile.privateLanDirect) ||
                      profile.useSystemProxy) && (
                      <div className="connection-card-details">
                        <button
                          type="button"
                          className="connection-detail-toggle"
                          onClick={() => toggleExpanded(profile.id)}
                          aria-expanded={isExpanded}
                        >
                          <ChevronIcon size={13} collapsed={!isExpanded} />
                          {detailCount > 0 ? (
                            <>
                              {profile.routes.length > 0 &&
                                `${profile.routes.length} route${profile.routes.length === 1 ? "" : "s"}`}
                              {profile.routes.length > 0 && ruleCount > 0 && " · "}
                              {ruleCount > 0 &&
                                `${ruleCount} routing rule${ruleCount === 1 ? "" : "s"}`}
                            </>
                          ) : (
                            "Details"
                          )}
                        </button>
                        {isExpanded && (
                          <>
                            {profile.subscription?.userInfo && (
                              <div className="interface-row">
                                <span className="row-label">Traffic</span>
                                <span className="row-value">
                                  {formatBytes(profile.subscription.userInfo.uploadBytes + profile.subscription.userInfo.downloadBytes)} used
                                  {profile.subscription.userInfo.totalBytes !== null
                                    ? ` / ${formatBytes(profile.subscription.userInfo.totalBytes)}`
                                    : " / unlimited"}
                                </span>
                              </div>
                            )}
                            {profile.subscription?.userInfo?.expiresAtUnix != null && (
                              <div className="interface-row">
                                <span className="row-label">Expires</span>
                                <span className="row-value">
                                  {new Date(profile.subscription.userInfo.expiresAtUnix * 1000).toLocaleDateString()}
                                </span>
                              </div>
                            )}
                            {profile.subscription && profile.subscription.lastRefreshAtUnix !== null && (
                              <div className="interface-row">
                                <span className="row-label">Last checked</span>
                                <span className="row-value">
                                  {new Date(profile.subscription.lastRefreshAtUnix * 1000).toLocaleString()}
                                </span>
                              </div>
                            )}
                            {profile.subscription?.lastRefreshError && (
                              <div className="interface-row">
                                <span className="row-label">Refresh</span>
                                <span className="row-value">{profile.subscription.lastRefreshError}</span>
                              </div>
                            )}
                            {profile.backend === "xray" && profile.privateLanDirect && (
                              <div className="interface-row">
                                <span className="row-label">Private/LAN IPs</span>
                                <span className="row-value">Direct after custom rules</span>
                              </div>
                            )}
                            {profile.useSystemProxy && (
                              <div className="interface-row">
                                <span className="row-label">Proxy bypass</span>
                                <span className="row-value mono">
                                  {profile.proxyBypass.join("; ") ||
                                    "LAN/localhost defaults"}
                                </span>
                              </div>
                            )}
                            {ruleCount > 0 && (
                              <div className="interface-row">
                                <span className="row-label">Domain/IP rules</span>
                                <span className="row-value">
                                  {(["block", "proxy", "direct"] as const)
                                    .map((target) => ({
                                      target,
                                      count: countPolicyRules(
                                        profile.domainPolicies,
                                        target,
                                      ),
                                    }))
                                    .filter((entry) => entry.count > 0)
                                    .map(
                                      (entry) =>
                                        `${DOMAIN_TARGET_LABELS[entry.target]} ${entry.count}`,
                                    )
                                    .join(" · ")}
                                </span>
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
        open={openVpnCredentialProfile !== null}
        title="OpenVPN credentials"
        onClose={closeOpenVpnCredentials}
        maxWidth="420px"
        footer={
          <>
            <button type="button" onClick={closeOpenVpnCredentials} disabled={openVpnCredentialBusy}>
              Cancel
            </button>
            <button type="button" className="btn-primary" onClick={submitOpenVpnCredentials} disabled={openVpnCredentialBusy}>
              {openVpnCredentialBusy ? "Connecting…" : "Connect"}
            </button>
          </>
        }
      >
        <form className="profile-form" onSubmit={(event) => { event.preventDefault(); void submitOpenVpnCredentials(); }}>
          <label>
            Username
            <input type="text" autoComplete="username" value={openVpnUsername} onChange={(event) => setOpenVpnUsername(event.target.value)} />
          </label>
          <label>
            Password
            <input type="password" autoComplete="current-password" value={openVpnPassword} onChange={(event) => setOpenVpnPassword(event.target.value)} />
          </label>
          <label>
            Private key passphrase (if required)
            <input type="password" autoComplete="off" value={openVpnKeyPassphrase} onChange={(event) => setOpenVpnKeyPassphrase(event.target.value)} />
          </label>
          <label className="profile-proxy-toggle">
            <input type="checkbox" checked={rememberOpenVpnCredentials} onChange={(event) => setRememberOpenVpnCredentials(event.target.checked)} />
            Remember on this device
          </label>
          <span className="profile-help">Stored in the system keyring (GNOME Keyring or KWallet). Without a keyring, kept only until the app exits.</span>
          {openVpnCredentialError && <p className="error" role="alert">{openVpnCredentialError}</p>}
        </form>
      </Modal>

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
              className="btn-primary"
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
