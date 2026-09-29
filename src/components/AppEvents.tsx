import { useEffect, useRef } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useToast } from "./ui/Toast";
import {
  AutoConnectResult,
  Profile,
  TunnelState,
  TunnelStatus,
} from "../types";

/**
 * Global runtime notifications: startup auto-connect results and tunnels
 * that transition into the failed state — surfaced as toasts regardless of
 * which tab is active.
 */
export default function AppEvents() {
  const toast = useToast();
  const prevStates = useRef<Record<string, TunnelState>>({});

  useEffect(() => {
    if (!isTauri()) return;
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
        showResult(
          await invoke<AutoConnectResult | null>("get_auto_connect_result"),
        );
      } catch {
        // The app remains usable if the startup result is unavailable.
      }
    })();
    return () => {
      active = false;
      stopListening?.();
    };
  }, [toast]);

  useEffect(() => {
    if (!isTauri()) return;
    const poll = async () => {
      let statuses: TunnelStatus[];
      try {
        statuses = await invoke<TunnelStatus[]>("get_tunnel_statuses");
      } catch {
        return;
      }
      const prev = prevStates.current;
      const next: Record<string, TunnelState> = {};
      const newlyFailed: TunnelStatus[] = [];
      for (const status of statuses) {
        next[status.profileId] = status.state;
        if (
          prev[status.profileId] !== undefined &&
          prev[status.profileId] !== "failed" &&
          status.state === "failed"
        ) {
          newlyFailed.push(status);
        }
      }
      prevStates.current = next;
      if (newlyFailed.length === 0) return;
      let profiles: Profile[] = [];
      try {
        profiles = await invoke<Profile[]>("get_profiles");
      } catch {
        // Names are cosmetic — fall back to a generic label.
      }
      for (const status of newlyFailed) {
        const name =
          profiles.find((p) => p.id === status.profileId)?.name ?? "Profile";
        toast(
          "error",
          status.message
            ? `${name} failed to connect: ${status.message}`
            : `${name} failed to connect. Run Diagnostics for details.`,
        );
      }
    };
    void poll();
    const interval = setInterval(() => void poll(), 2000);
    return () => clearInterval(interval);
  }, [toast]);

  return null;
}
