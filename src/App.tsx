import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import InterfaceList from "./components/InterfaceList";
import RouteTable from "./components/RouteTable";
import RouteLookup from "./components/RouteLookup";
import "./App.css";

type Tab = "interfaces" | "routes";

function App() {
  const [tab, setTab] = useState<Tab>("interfaces");

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
      <nav className="sidebar">
        <div className="sidebar-header">Network Explorer</div>
        <ul className="nav-items">
          <li>
            <button
              className={`nav-item ${tab === "interfaces" ? "active" : ""}`}
              onClick={() => setTab("interfaces")}
            >
              Interfaces
            </button>
          </li>
          <li>
            <button
              className={`nav-item ${tab === "routes" ? "active" : ""}`}
              onClick={() => setTab("routes")}
            >
              Routes
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
