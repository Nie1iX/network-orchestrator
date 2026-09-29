import { useCallback, useEffect, useState } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { message } from "@tauri-apps/plugin-dialog";
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
import { ToastProvider } from "./components/ui/Toast";
import { TunnelStatus } from "./types";
import "./App.css";

function App() {
  const [tab, setTab] = useState<Tab>("profiles");
  const [activeCount, setActiveCount] = useState(0);

  useEffect(() => {
    if (!isTauri()) return;
    const unlisten = listen("route-changed", () => {
      window.dispatchEvent(new CustomEvent("route-changed"));
    });
    const unlistenShutdown = listen<string>("shutdown-failed", (event) => {
      void message(event.payload, {
        title: "Could not shut down safely",
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
      setActiveCount(statuses.filter((s) => s.state === "running").length);
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
      <div className="app-layout">
        <NavRail tab={tab} setTab={setTab} activeCount={activeCount} />
        <main className="content">
          {tab === "profiles" && <ProfileManager />}
          {tab === "monitor" && <Monitor />}
          {tab === "routes" && <RouteView />}
          {tab === "conditions" && <CondRules />}
          {tab === "network" && <InterfaceList />}
          {tab === "logs" && <Logs />}
          {tab === "settings" && <Settings />}
        </main>
        <RecoveryPrompt />
      </div>
    </ToastProvider>
  );
}

export default App;
