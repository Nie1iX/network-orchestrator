import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { confirm } from "@tauri-apps/plugin-dialog";
import { ensureElevation, requiresElevation } from "../elevation";
import { usePlatformCapabilities } from "../platform";
import { useProfileListMode } from "../prefs";
import { pluralize, useT } from "../i18n";
import { BACKEND_LABEL_KEYS } from "../i18n/labels";
import {
  backendIcon,
  ChevronIcon,
  InfoIcon,
  PlusIcon,
  TailscaleIcon,
} from "../icons";
import AddConnectionMenu from "./AddConnectionMenu";
import DiagnosticsModal from "./DiagnosticsModal";
import ImportModal from "./ImportModal";
import Modal from "./Modal";
import Page from "./Page";
import ProfileDetail from "./profiles/ProfileDetail";
import ProfileRow from "./profiles/ProfileRow";
import SetsBar from "./profiles/SetsBar";
import {
  ConnectionSnippet,
  loadSnippets,
  newSnippetId,
  sameIds,
  storeSnippets,
} from "./profiles/sets";
import Skeleton from "./ui/Skeleton";
import TailscalePanel from "./TailscalePanel";
import ToggleSwitch from "./ui/ToggleSwitch";
import { useToast } from "./ui/Toast";
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
  NetworkInterface,
  Profile,
  ProfileDiagnostics,
  ProfileInspection,
  SubscriptionEndpointInfo,
  SubscriptionDelayResult,
  SubscriptionRefreshResult,
  TailscaleStatusResult,
  TunnelBackend,
  TunnelStatus,
} from "../types";

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

function ProfileRowSkeleton() {
  return (
    <div className="profile-row">
      <Skeleton width="30px" height="30px" radius="50%" />
      <div className="profile-row-info">
        <Skeleton width="140px" height="0.9rem" />
        <Skeleton width="90px" height="0.75rem" />
      </div>
      <Skeleton width="40px" height="24px" radius="999px" />
    </div>
  );
}

export default function ProfileManager() {
  const caps = usePlatformCapabilities();
  const toast = useToast();
  const t = useT();
  const listMode = useProfileListMode();
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
  const [measuringEndpoints, setMeasuringEndpoints] = useState<Set<string>>(
    new Set(),
  );
  const [measuringAll, setMeasuringAll] = useState<Set<string>>(new Set());
  const [delayResults, setDelayResults] = useState<
    Record<string, Record<number, SubscriptionDelayResult>>
  >({});
  const [selectedId, setSelectedId] = useState<string | null>(null);
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
  const [dragState, setDragState] = useState<{
    backend: TunnelBackend;
    profileId: string;
  } | null>(null);
  const [dropTarget, setDropTarget] = useState<{
    profileId: string;
    before: boolean;
  } | null>(null);
  const [tailscale, setTailscale] = useState<TailscaleStatusResult | null>(null);
  const [tailscaleBusy, setTailscaleBusy] = useState(false);
  const [serviceSelected, setServiceSelected] = useState(false);

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
    storeSnippets(snippets);
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

  const refreshTailscale = useCallback(async () => {
    if (caps?.os !== "linux") return;
    try {
      setTailscale(
        await invoke<TailscaleStatusResult>("tailscale_status"),
      );
    } catch {
      setTailscale(null);
    }
  }, [caps?.os]);

  useEffect(() => {
    void refreshTailscale();
    const onChanged = () => void refreshTailscale();
    window.addEventListener("route-changed", onChanged);
    const interval = setInterval(() => void refreshTailscale(), 15000);
    return () => {
      window.removeEventListener("route-changed", onChanged);
      clearInterval(interval);
    };
  }, [refreshTailscale]);

  const onToggleTailscale = async () => {
    if (!tailscale?.available) return;
    const running = tailscale.backendState === "Running";
    setTailscaleBusy(true);
    try {
      setTailscale(
        await invoke<TailscaleStatusResult>("tailscale_set_running", {
          running: !running,
        }),
      );
    } catch (err) {
      toast("error", String(err));
    } finally {
      setTailscaleBusy(false);
    }
  };

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
      if (!cancelled) {
        setEndpoints(next);
        measureActiveEndpoints(next);
      }
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
        if (!(await ensureElevation(t("profiles.connecting", { name: profile.name })))) return;
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
            t("profiles.connectFailedDiag", { name: profile.name }),
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
      setOpenVpnCredentialError(t("ovpn.errUserPass"));
      return;
    }
    if (!openVpnUsername && !openVpnKeyPassphrase) {
      setOpenVpnCredentialError(t("ovpn.errCreds"));
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
      setOpenVpnCredentialError(
        t("ovpn.errFailed", { err: String(err) }),
      );
    } finally {
      setOpenVpnCredentialBusy(false);
    }
  };

  const onDisconnect = async (profile: Profile) => {
    if (requiresElevation(profile)) {
      try {
        if (!(await ensureElevation(t("profiles.disconnecting", { name: profile.name })))) return;
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
      setError(t("profiles.disableAlwaysOnDelete"));
      return;
    }
    const ok = await confirm(t("profiles.deleteConfirm", { name: profile.name }), {
      title: t("profiles.deleteTitle"),
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
        t("profiles.subRefreshed", {
          n: result.endpointCount,
          unit: pluralize(
            result.endpointCount,
            ["эндпоинт", "эндпоинта", "эндпоинтов"],
            ["endpoint", "endpoints"],
          ),
        }),
      ];
      if (result.skippedCount > 0) details.push(t("profiles.subSkipped", { n: result.skippedCount }));
      if (result.fallbackUsed) details.push(t("profiles.subFallback"));
      if (result.cleanupFailed) details.push(t("profiles.subCleanupFailed"));
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
      setError(t("profiles.refreshIntervalFailed"));
    } finally {
      setSettingRefreshInterval(null);
    }
  };

  const onMeasureEndpoint = async (profile: Profile, index: number) => {
    const key = `${profile.id}:${index}`;
    setMeasuringEndpoints((prev) => new Set(prev).add(key));
    try {
      const result = await invoke<SubscriptionDelayResult>(
        "measure_subscription_endpoint_delay",
        { profileId: profile.id, endpointIndex: index },
      );
      setDelayResults((current) => ({
        ...current,
        [profile.id]: { ...(current[profile.id] ?? {}), [index]: result },
      }));
    } catch {
      setDelayResults((current) => ({
        ...current,
        [profile.id]: {
          ...(current[profile.id] ?? {}),
          [index]: { delayMs: null, error: t("profiles.delayCheckFailed") },
        },
      }));
    } finally {
      setMeasuringEndpoints((prev) => {
        const next = new Set(prev);
        next.delete(key);
        return next;
      });
    }
  };

  const onMeasureAllEndpoints = async (profile: Profile) => {
    const list = endpoints[profile.id] ?? [];
    if (list.length === 0) return;
    setMeasuringAll((prev) => new Set(prev).add(profile.id));
    try {
      const CHUNK = 4;
      for (let i = 0; i < list.length; i += CHUNK) {
        await Promise.all(
          list
            .slice(i, i + CHUNK)
            .map((_, k) => onMeasureEndpoint(profile, i + k)),
        );
      }
    } finally {
      setMeasuringAll((prev) => {
        const next = new Set(prev);
        next.delete(profile.id);
        return next;
      });
    }
  };

  const measureActiveEndpoints = (
    endpointMap: Record<string, SubscriptionEndpointInfo[]>,
  ) => {
    for (const p of profiles) {
      if (!p.subscription) continue;
      const list = endpointMap[p.id];
      const index = list?.findIndex((e) => e.active) ?? -1;
      if (index < 0) continue;
      void onMeasureEndpoint(p, index);
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
      setError(t("profiles.disableAlwaysOnEdit"));
      return;
    }
    setEditing(editFormState(profile));
    setFormOpen(true);
  };

  const onToggleAlwaysOn = async (profile: Profile, kind: AlwaysOnKind, enrolled: boolean) => {
    if (!enrolled && kind === "wireGuard") {
      const approved = await confirm(
        t("profiles.alwaysOnConfirm"),
        { title: t("profiles.alwaysOnTitle"), kind: "warning" },
      );
      if (!approved) return;
    }
    await withBusy(profile.id, async () => {
      if (enrolled) {
        await invoke("remove_always_on_profile", { kind, profileId: profile.id });
      } else {
        const result = await invoke<AlwaysOnSetResult>("set_always_on_profile", { id: profile.id });
        if (!result.active) toast("info", t("profiles.alwaysOnSaved"));
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
            status.message ??
              t("profiles.reloaded", { name: editing.name || editing.id }),
          );
        })
        .catch((err) =>
          toast("info", t("profiles.reloadReconnect", { err: String(err) })),
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
      <Page width="full">
        <div className="profiles-toolbar">
          <h2>{t("profiles.title")}</h2>
        </div>
        <div className="profiles-layout">
          <div className="profiles-list-pane">
            <ProfileRowSkeleton />
            <ProfileRowSkeleton />
            <ProfileRowSkeleton />
          </div>
          <div className="profiles-detail-pane" />
        </div>
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

  const failedCount = profiles.filter(
    (p) => statusFor(p.id).state === "failed",
  ).length;

  const selected =
    (selectedId ? profiles.find((p) => p.id === selectedId) : undefined) ??
    runningProfiles[0] ??
    filteredProfiles[0] ??
    profiles[0] ??
    null;

  const tsRunning =
    tailscale !== null &&
    tailscale.available &&
    tailscale.backendState === "Running";
  const tsNeedsLogin = tailscale?.backendState === "NeedsLogin";
  const tsMeta = !tailscale?.available
    ? t("ts.unavailable")
    : tailscale.selfIps.length > 0
      ? tailscale.selfIps.join(", ")
      : tailscale.backendState;

  const selGroup = selected
    ? groups.find((g) => g.backend === selected.backend)
    : undefined;
  const selIndex =
    selGroup && selected
      ? selGroup.items.findIndex((p) => p.id === selected.id)
      : -1;
  const canMove = Boolean(
    listMode === "grouped" &&
    !lowerSearch &&
    selGroup &&
    selIndex >= 0 &&
    selGroup.items.length > 1,
  );

  const stateRank = (state: TunnelStatus["state"]) =>
    state === "running" ? 0 : state === "failed" ? 1 : 2;
  const flatList =
    listMode === "flat"
      ? [...filteredProfiles].sort(
          (a, b) =>
            stateRank(statusFor(a.id).state) -
              stateRank(statusFor(b.id).state) ||
            a.name.localeCompare(b.name),
        )
      : [];

  const renderProfileRow = (
    profile: Profile,
    group: ProfileGroup | null,
    canReorder: boolean,
  ) => {
    const status = statusFor(profile.id);
    const isBusy = busy.has(profile.id);
    const rate = status.state === "running" ? rateFor(profile) : null;
    const endpointList = endpoints[profile.id];
    const activeEndpointIdx =
      endpointList?.findIndex((e) => e.active) ?? -1;
    const delayRes =
      activeEndpointIdx >= 0
        ? delayResults[profile.id]?.[activeEndpointIdx]
        : undefined;
    return (
      <ProfileRow
        key={profile.id}
        profile={profile}
        status={status}
        rate={rate}
        delayText={
          !profile.subscription
            ? null
            : activeEndpointIdx >= 0 &&
                measuringEndpoints.has(
                  `${profile.id}:${activeEndpointIdx}`,
                )
              ? "…"
              : delayRes
                ? delayRes.delayMs !== null
                  ? `${delayRes.delayMs} ms`
                  : "err"
                : "—"
        }
        isBusy={isBusy}
        selected={selected?.id === profile.id}
        dragging={dragState?.profileId === profile.id}
        dropBefore={
          dropTarget?.profileId === profile.id && dropTarget.before
        }
        dropAfter={
          dropTarget?.profileId === profile.id && !dropTarget.before
        }
        canReorder={canReorder}
        onSelect={() => {
          setServiceSelected(false);
          setSelectedId(profile.id);
        }}
        onToggle={() =>
          status.state === "running"
            ? void onDisconnect(profile)
            : void onConnect(profile)
        }
        onDragStart={(event) => onCardDragStart(event, profile)}
        onDragEnd={onCardDragEnd}
        onDragOver={(event) =>
          group && onCardDragOver(event, group, profile)
        }
        onDrop={(event) => group && onCardDrop(event, group, profile)}
      />
    );
  };

  return (
    <Page width="full">
      <div className="profiles-toolbar">
        <h2>{t("profiles.title")}</h2>
        <span className="profiles-status">
          <span
            className={`status-dot ${
              runningProfiles.length > 0 ? "state-running" : "state-stopped"
            }`}
          />
          {t("profiles.runningSummary", {
            running: runningProfiles.length,
            total: profiles.length,
          })}
          {failedCount > 0 && (
            <span className="profiles-status-failed">
              {" "}
              · {t("profiles.failedSuffix", { n: failedCount })}
            </span>
          )}
        </span>
        <span
          className="profiles-info"
          role="note"
          title={
            t("profiles.infoElev") +
            (caps?.os === "linux"
              ? `\n\n${t("profiles.infoAlwaysOn")}`
              : "")
          }
        >
          <InfoIcon size={15} />
        </span>
        {profiles.some((p) => p.subscription !== null) && (
          <button
            type="button"
            className="btn-sm"
            onClick={() => measureActiveEndpoints(endpoints)}
            disabled={measuringEndpoints.size > 0}
            title={t("profiles.testDelaysTitle")}
          >
            {measuringEndpoints.size > 0 ? t("profiles.testing") : t("profiles.testDelays")}
          </button>
        )}
        <button
          className="profile-new-btn btn-primary btn-with-icon"
          onClick={() => setAddMenuOpen(true)}
        >
          <PlusIcon size={14} /> {t("profiles.add")}
        </button>
        <button
          className="btn-with-icon"
          onClick={() => setImportOpen(true)}
        >
          {t("profiles.import")}
        </button>
      </div>
      {caps?.os === "linux" && alwaysOn?.paused && (
        <div className="runtime-notice" role="status">
          <span>{t("profiles.alwaysOnPaused")}</span>
          <button type="button" onClick={onResumeAlwaysOn} disabled={resumingAlwaysOn}>
            {resumingAlwaysOn ? t("profiles.resuming") : t("profiles.resume")}
          </button>
        </div>
      )}

      {importErrors && (
        <div className="save-notice">
          <div className="diagnostics-head">
            <span>{t("profiles.importErrors")}</span>
            <button type="button" onClick={() => setImportErrors(null)}>
              {t("common.dismiss")}
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
            <span>{t("profiles.savedNotice", { name: saveNotice.profileName })}</span>
            <button type="button" onClick={() => setSaveNotice(null)}>
              {t("common.dismiss")}
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

      <div className="profiles-layout">
        <div className="profiles-list-pane">
          {profiles.length > 0 && (
            <SetsBar
              snippets={snippets}
              activeSnippetId={activeSnippetId}
              activeDirty={isActiveSnippetDirty}
              runningCount={runningProfiles.length}
              onApply={applySnippet}
              onDelete={deleteSnippet}
              onUpdateActive={overwriteActiveSnippet}
              onSaveNew={openSaveModal}
            />
          )}

      {profiles.length > 0 && (
        <input
          className="filter-search connections-search"
          type="text"
          placeholder={t("profiles.searchPh")}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      )}

      {profiles.length === 0 ? (
        <p className="empty-state">{t("profiles.empty")}</p>
      ) : filteredProfiles.length === 0 ? (
        <p className="empty-state">{t("profiles.noMatch", { query: search })}</p>
      ) : listMode === "flat" ? (
        <div className="profile-rows">
          {flatList.map((profile) => renderProfileRow(profile, null, false))}
        </div>
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
                {t(BACKEND_LABEL_KEYS[group.backend])}
              </span>
              <span className="profile-group-count">
                {group.items.length}
              </span>
            </button>
            {!isCollapsed && (
            <div className="profile-rows" onDragLeave={onListDragLeave}>
              {group.items.map((profile) =>
                renderProfileRow(profile, group, canReorder),
              )}
            </div>
            )}
          </div>
          );
        })
      )}

      {tailscale !== null && (
        <div className="profile-group">
          <div className="profile-group-label">{t("profiles.services")}</div>
          <div className="profile-rows">
            <div
              role="button"
              tabIndex={0}
              className={`profile-row${serviceSelected ? " selected" : ""}`}
              onClick={() => setServiceSelected(true)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  setServiceSelected(true);
                }
              }}
            >
              <span
                className={`status-dot state-${
                  tsRunning
                    ? "running"
                    : tailscale.available
                      ? "stopped"
                      : "unknown"
                }`}
              />
              <span className="backend-avatar backend-avatar-service">
                <TailscaleIcon size={18} />
              </span>
              <div className="profile-row-info">
                <span className="profile-row-name">Tailscale</span>
                <span className="profile-row-meta">{tsMeta}</span>
              </div>
              <ToggleSwitch
                checked={tsRunning}
                onChange={() => void onToggleTailscale()}
                disabled={
                  !tailscale.available || tsNeedsLogin || tailscaleBusy
                }
                busy={tailscaleBusy}
                title={
                  !tailscale.available
                    ? t("ts.notInstalled")
                    : tsNeedsLogin
                      ? t("ts.loginFirst")
                      : tsRunning
                        ? t("ts.down")
                        : t("ts.up")
                }
              />
            </div>
          </div>
        </div>
      )}
        </div>

        <div className="profiles-detail-pane">
          {serviceSelected && tailscale ? (
            <TailscalePanel
              status={tailscale}
              busy={tailscaleBusy}
              onToggle={() => void onToggleTailscale()}
            />
          ) : selected ? (
            <ProfileDetail
              profile={selected}
              status={statusFor(selected.id)}
              rate={
                statusFor(selected.id).state === "running"
                  ? rateFor(selected)
                  : null
              }
              isBusy={busy.has(selected.id)}
              backendLabel={t(BACKEND_LABEL_KEYS[selected.backend])}
              managedConfig={inspections[selected.id]?.managedConfig}
              alwaysOn={alwaysOn}
              os={caps?.os}
              endpoints={endpoints[selected.id]}
              delayResults={delayResults[selected.id]}
              measuringEndpoints={measuringEndpoints}
              measuringAll={measuringAll.has(selected.id)}
              switching={switching === selected.id}
              refreshingSubscription={
                refreshingSubscription === selected.id
              }
              settingRefreshInterval={settingRefreshInterval === selected.id}
              diagBusy={diagBusy === selected.id}
              canMoveUp={canMove && selIndex > 0}
              canMoveDown={
                canMove && selIndex < (selGroup?.items.length ?? 0) - 1
              }
              onConnect={() => void onConnect(selected)}
              onDisconnect={() => void onDisconnect(selected)}
              onEdit={() => openEdit(selected)}
              onMoveUp={() =>
                selGroup &&
                moveProfileInGroup(selGroup.items, selected.id, -1)
              }
              onMoveDown={() =>
                selGroup &&
                moveProfileInGroup(selGroup.items, selected.id, 1)
              }
              onToggleAlwaysOn={(kind, enrolled) =>
                onToggleAlwaysOn(selected, kind, enrolled)
              }
              onCredentials={() => {
                setOpenVpnCredentialProfile(selected);
                setOpenVpnCredentialError(null);
              }}
              onRefreshSubscription={() =>
                void onRefreshSubscription(selected)
              }
              onDiagnose={() => void onDiagnose(selected)}
              onDelete={() => void onDelete(selected)}
              onSwitchEndpoint={(index) =>
                void onSwitchEndpoint(selected, index)
              }
              onMeasureAllEndpoints={() =>
                void onMeasureAllEndpoints(selected)
              }
              onSetRefreshInterval={(minutes) =>
                void onSetRefreshInterval(selected, minutes)
              }
            />
          ) : (
            <div className="profile-detail-empty">
              {profiles.length === 0
                ? t("profiles.detailEmptyNone")
                : t("profiles.detailEmpty")}
            </div>
          )}
        </div>
      </div>

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
        title={t("ovpn.title")}
        onClose={closeOpenVpnCredentials}
        maxWidth="420px"
        footer={
          <>
            <button type="button" onClick={closeOpenVpnCredentials} disabled={openVpnCredentialBusy}>
              {t("common.cancel")}
            </button>
            <button type="button" className="btn-primary" onClick={submitOpenVpnCredentials} disabled={openVpnCredentialBusy}>
              {openVpnCredentialBusy ? t("common.connecting") : t("common.connect")}
            </button>
          </>
        }
      >
        <form className="profile-form" onSubmit={(event) => { event.preventDefault(); void submitOpenVpnCredentials(); }}>
          <label>
            {t("ovpn.username")}
            <input type="text" autoComplete="username" value={openVpnUsername} onChange={(event) => setOpenVpnUsername(event.target.value)} />
          </label>
          <label>
            {t("ovpn.password")}
            <input type="password" autoComplete="current-password" value={openVpnPassword} onChange={(event) => setOpenVpnPassword(event.target.value)} />
          </label>
          <label>
            {t("ovpn.keyPass")}
            <input type="password" autoComplete="off" value={openVpnKeyPassphrase} onChange={(event) => setOpenVpnKeyPassphrase(event.target.value)} />
          </label>
          <label className="profile-proxy-toggle">
            <input type="checkbox" checked={rememberOpenVpnCredentials} onChange={(event) => setRememberOpenVpnCredentials(event.target.checked)} />
            {t("ovpn.remember")}
          </label>
          <span className="profile-help">{t("ovpn.keyringHelp")}</span>
          {openVpnCredentialError && <p className="error" role="alert">{openVpnCredentialError}</p>}
        </form>
      </Modal>

      <Modal
        open={saveModalOpen}
        title={t("sets.modalTitle")}
        onClose={() => setSaveModalOpen(false)}
        maxWidth="420px"
        footer={
          <>
            <button type="button" onClick={() => setSaveModalOpen(false)}>
              {t("common.cancel")}
            </button>
            <button
              type="button"
              className="btn-primary"
              onClick={createSnippet}
              disabled={!newSnippetName.trim()}
            >
              {t("sets.saveAsNew")}
            </button>
          </>
        }
      >
        <div className="interface-section">
          <span className="section-label">
            {t("sets.willInclude", {
              n: runningProfiles.length,
              unit: pluralize(
                runningProfiles.length,
                ["подключение", "подключения", "подключений"],
                ["connection", "connections"],
              ),
            })}
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
            {t("sets.updateWith", { name: activeSnippet.name })}
          </button>
        )}

        <label>
          {activeSnippet ? t("sets.orSaveNew") : t("sets.name")}
          <input
            type="text"
            value={newSnippetName}
            onChange={(e) => setNewSnippetName(e.target.value)}
            placeholder={t("sets.namePh")}
            autoFocus
          />
        </label>
      </Modal>
    </Page>
  );
}
