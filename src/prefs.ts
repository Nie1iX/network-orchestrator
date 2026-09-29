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
