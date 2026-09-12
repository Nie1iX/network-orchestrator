import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import RouteLookup from "./components/RouteLookup";
import InterfaceList from "./components/InterfaceList";
import RouteTable from "./components/RouteTable";
import "./App.css";

function App() {
  useEffect(() => {
    const unlisten = listen("route-changed", () => {
      window.dispatchEvent(new CustomEvent("route-changed"));
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  return (
    <main className="container">
      <h1>Network Explorer</h1>
      <RouteLookup />
      <InterfaceList />
      <RouteTable />
    </main>
  );
}

export default App;
