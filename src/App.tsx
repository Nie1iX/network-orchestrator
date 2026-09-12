import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import InterfaceList from "./components/InterfaceList";
import RouteTable from "./components/RouteTable";
import RouteLookup from "./components/RouteLookup";
import { NetworkIcon, RouteIcon, ChevronIcon } from "./icons";
import "./App.css";

type Tab = "interfaces" | "routes";

function App() {
  const [tab, setTab] = useState<Tab>("interfaces");
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    const unlisten = listen("route-changed", () => {
      window.dispatchEvent(new CustomEvent("route-changed"));
    });
    return () => {
      unlisten.then((fn) => fn());
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
        {tab === "routes" && (
          <>
            <RouteLookup />
            <RouteTable />
          </>
        )}
      </main>
    </div>
  );
}

export default App;
