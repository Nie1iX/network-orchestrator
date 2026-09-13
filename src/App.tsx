import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { message } from "@tauri-apps/plugin-dialog";
import InterfaceList from "./components/InterfaceList";
import ProfileManager from "./components/ProfileManager";
import RecoveryPrompt from "./components/RecoveryPrompt";
import RouteTable from "./components/RouteTable";
import RouteLookup from "./components/RouteLookup";
import { NetworkIcon, ProfileIcon, RouteIcon, ChevronIcon } from "./icons";
import "./App.css";

type Tab = "interfaces" | "profiles" | "routes";

function App() {
  const [tab, setTab] = useState<Tab>("interfaces");
  const [collapsed, setCollapsed] = useState(false);

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

  return (
    <div className="app-layout">
      <nav className={`sidebar ${collapsed ? "collapsed" : ""}`}>
        <div className="sidebar-header">
          <NetworkIcon size={24} />
          <span className="label">Network Explorer</span>
          <button
            className="sidebar-toggle"
            onClick={() => setCollapsed(!collapsed)}
            title={collapsed ? "Expand" : "Collapse"}
          >
            <ChevronIcon size={16} collapsed={collapsed} />
          </button>
        </div>
        <ul className="nav-items">
          <li>
            <button
              className={`nav-item ${tab === "interfaces" ? "active" : ""}`}
              onClick={() => setTab("interfaces")}
              title="Interfaces"
            >
              <NetworkIcon size={16} />
              <span className="label">Interfaces</span>
            </button>
          </li>
          <li>
            <button
              className={`nav-item ${tab === "profiles" ? "active" : ""}`}
              onClick={() => setTab("profiles")}
              title="Profiles"
            >
              <ProfileIcon size={16} />
              <span className="label">Profiles</span>
            </button>
          </li>
          <li>
            <button
              className={`nav-item ${tab === "routes" ? "active" : ""}`}
              onClick={() => setTab("routes")}
              title="Routes"
            >
              <RouteIcon size={16} />
              <span className="label">Routes</span>
            </button>
          </li>
        </ul>
      </nav>
      <main className="content">
        {tab === "interfaces" && <InterfaceList />}
        {tab === "profiles" && <ProfileManager />}
        {tab === "routes" && (
          <>
            <RouteLookup />
            <RouteTable />
          </>
        )}
      </main>
      <RecoveryPrompt />
    </div>
  );
}

export default App;
