import { useCallback, useEffect, useState } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { confirm, message } from "@tauri-apps/plugin-dialog";
import AppEvents from "./components/AppEvents";
import CondRules from "./components/CondRules";
import InterfaceList from "./components/InterfaceList";
import Logs from "./components/Logs";
import Monitor from "./components/Monitor";
import NavRail, { type Tab } from "./components/NavRail";
import ProfileManager from "./components/ProfileManager";
import RecoveryPrompt from "./components/RecoveryPrompt";
import RouteView from "./components/RouteView";
import Settings from "./components/Settings";
import StatusBar from "./components/StatusBar";
import { ToastProvider } from "./components/ui/Toast";
import { TailscaleStatusResult, TunnelStatus } from "./types";
import { t, tr } from "./i18n";
import type { NetworkEditorState } from "./profileEditing";
import { applyAppearance, readAppearance } from "./theme";
import "./App.css";

function App() {
  const [tab, setTab] = useState<Tab>("profiles");
  const [activeCount, setActiveCount] = useState(0);
  const [schemeFocus, setSchemeFocus] = useState<string | null>(null);
  const [networkEditorState, setNetworkEditorState] = useState<NetworkEditorState>({ dirty: false, busy: false });
  const changeTab = async (next: Tab) => {
    if (next === tab) return;
    if (networkEditorState.busy) { await message(tr("Wait for the current operation to finish.")); return; }
    if (networkEditorState.dirty && !await confirm(tr("Discard unsaved profile changes?"), { kind: "warning" })) return;
    setNetworkEditorState({ dirty: false, busy: false });
    if (next === "routes") setSchemeFocus(null);
    setTab(next);
  };
  useEffect(() => {
    if (!networkEditorState.dirty) return;
    const preventLoss = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ""; };
    window.addEventListener("beforeunload", preventLoss);
    return () => window.removeEventListener("beforeunload", preventLoss);
  }, [networkEditorState.dirty]);

  useEffect(() => {
    applyAppearance(readAppearance());
  }, []);

  useEffect(() => {
    if (!isTauri()) return;
    const unlisten = listen("route-changed", () => {
      window.dispatchEvent(new CustomEvent("route-changed"));
    });
    const unlistenShutdown = listen<string>("shutdown-failed", (event) => {
      void message(event.payload, {
        title: t("app.shutdownFailed"),
        kind: "error",
      });
    });
    return () => {
      unlisten.then((fn) => fn());
      unlistenShutdown.then((fn) => fn());
    };
  }, []);

  const pollActiveCount = useCallback(async () => {
    if (!isTauri()) return;
    try {
      const statuses = await invoke<TunnelStatus[]>("get_tunnel_statuses");
      let count = statuses.filter((s) => s.state === "running").length;
      try {
        const tailscale =
          await invoke<TailscaleStatusResult>("tailscale_status");
        if (tailscale.available && tailscale.backendState === "Running") {
          count += 1;
        }
      } catch {
        // Tailscale is absent on non-Linux builds or without a daemon.
      }
      setActiveCount(count);
    } catch {
      // keep last known count on poll failure
    }
  }, []);

  useEffect(() => {
    pollActiveCount();
    const interval = setInterval(pollActiveCount, 2000);
    return () => clearInterval(interval);
  }, [pollActiveCount]);

  return (
    <ToastProvider>
      <AppEvents />
      <div className="app-shell">
        <div className="app-layout">
          <NavRail tab={tab} setTab={(next) => { void changeTab(next); }} activeCount={activeCount} />
          <main className="content">
            {tab === "profiles" && <ProfileManager onOpenScheme={(id) => { setSchemeFocus(id); setTab("routes"); }} />}
            {tab === "monitor" && <Monitor />}
            {tab === "routes" && <RouteView focusProfileId={schemeFocus} onFocusProfile={setSchemeFocus} onEditorState={setNetworkEditorState} />}
            {tab === "conditions" && <CondRules />}
            {tab === "network" && <InterfaceList />}
            {tab === "logs" && <Logs />}
            {tab === "settings" && <Settings />}
          </main>
          <RecoveryPrompt />
        </div>
        <StatusBar activeCount={activeCount} />
      </div>
    </ToastProvider>
  );
}

export default App;
