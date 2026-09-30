import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { message } from "@tauri-apps/plugin-dialog";
import Home from "./components/Home";
import InterfaceList from "./components/InterfaceList";
import NavRail, { type Tab } from "./components/NavRail";
import ProfileManager from "./components/ProfileManager";
import RecoveryPrompt from "./components/RecoveryPrompt";
import RouteView from "./components/RouteView";
import Settings from "./components/Settings";
import { TunnelStatus } from "./types";
import "./App.css";
import { applyAppearance, readAppearance } from "./theme";

function App() {
  useEffect(() => { applyAppearance(readAppearance()); }, []);
  const [tab, setTab] = useState<Tab>("home");
  const [activeCount, setActiveCount] = useState(0);

  useEffect(() => {
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
    <div className="app-layout">
      <NavRail tab={tab} setTab={setTab} activeCount={activeCount} />
      <main className="content">
        {tab === "home" && <Home onNavigate={setTab} />}
        {tab === "connections" && <ProfileManager />}
        {tab === "network" && <InterfaceList />}
        {tab === "routes" && <RouteView />}
        {tab === "settings" && <Settings />}
      </main>
      <RecoveryPrompt />
    </div>
  );
}

export default App;
