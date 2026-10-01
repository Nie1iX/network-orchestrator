import { useEffect, useState } from "react";

export type ProfileListMode = "grouped" | "flat";

const PROFILE_LIST_MODE_KEY = "netmanager.profiles.listMode";
const PREFS_EVENT = "ui-prefs-changed";

export function getProfileListMode(): ProfileListMode {
  try {
    return localStorage.getItem(PROFILE_LIST_MODE_KEY) === "flat"
      ? "flat"
      : "grouped";
  } catch {
    return "grouped";
  }
}

export function setProfileListMode(mode: ProfileListMode): void {
  try {
    localStorage.setItem(PROFILE_LIST_MODE_KEY, mode);
  } catch {
    // ignore storage errors (e.g. storage disabled)
  }
  window.dispatchEvent(new CustomEvent(PREFS_EVENT));
}

export function useProfileListMode(): ProfileListMode {
  const [mode, setMode] = useState<ProfileListMode>(getProfileListMode);
  useEffect(() => {
    const handler = () => setMode(getProfileListMode());
    window.addEventListener(PREFS_EVENT, handler);
    return () => window.removeEventListener(PREFS_EVENT, handler);
  }, []);
  return mode;
}

const ROUTES_HIDE_IPV6_KEY = "netmanager.routes.hideIpv6";
const ROUTES_INCLUDE_STOPPED_KEY = "netmanager.routes.includeStopped";

export interface RoutesPrefs {
  hideIpv6: boolean;
  includeStopped: boolean;
}

export function getRoutesPrefs(): RoutesPrefs {
  try {
    return {
      hideIpv6: localStorage.getItem(ROUTES_HIDE_IPV6_KEY) === "1",
      includeStopped:
        localStorage.getItem(ROUTES_INCLUDE_STOPPED_KEY) === "1",
    };
  } catch {
    return { hideIpv6: false, includeStopped: false };
  }
}

export function setRoutesPrefs(patch: Partial<RoutesPrefs>): void {
  try {
    const next = { ...getRoutesPrefs(), ...patch };
    localStorage.setItem(ROUTES_HIDE_IPV6_KEY, next.hideIpv6 ? "1" : "0");
    localStorage.setItem(
      ROUTES_INCLUDE_STOPPED_KEY,
      next.includeStopped ? "1" : "0",
    );
  } catch {
    // ignore storage errors (e.g. storage disabled)
  }
  window.dispatchEvent(new CustomEvent(PREFS_EVENT));
}

export function useRoutesPrefs(): RoutesPrefs {
  const [prefs, setPrefs] = useState<RoutesPrefs>(getRoutesPrefs);
  useEffect(() => {
    const handler = () => setPrefs(getRoutesPrefs());
    window.addEventListener(PREFS_EVENT, handler);
    return () => window.removeEventListener(PREFS_EVENT, handler);
  }, []);
  return prefs;
}
