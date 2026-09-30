import { tr } from "../i18n";
import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { RouteEntry } from "../types";

export default function RouteTable() {
  const [routes, setRoutes] = useState<RouteEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchRoutes = async () => {
    try {
      setError(null);
      const data = await invoke<RouteEntry[]>("get_routes");
      setRoutes(data);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRoutes();
  }, []);

  useEffect(() => {
    const handler = () => fetchRoutes();
    window.addEventListener("route-changed", handler);
    return () => window.removeEventListener("route-changed", handler);
  }, []);

  if (loading) return <p>{tr("Loading routes...")}</p>;
  if (error) return <p className="error">{tr("Error loading routes: ")}{tr(error)}</p>;

  return (
    <section>
      <h2>{tr("Routes")}</h2>
      {routes.length === 0 ? (
        <p>{tr("No routes found.")}</p>
      ) : (
        <table className="route-table">
          <thead>
            <tr>
              <th>{tr("Destination")}</th>
              <th>{tr("Prefix")}</th>
              <th>{tr("Gateway")}</th>
              <th>{tr("Interface")}</th>
              <th>{tr("Metric")}</th>
            </tr>
          </thead>
          <tbody>
            {routes.map((route, i) => (
              <tr key={i}>
                <td>{route.destination}</td>
                <td>/{route.prefixLen}</td>
                <td>{route.gateway ?? "—"}</td>
                <td>{route.interfaceName}</td>
                <td>{route.metric}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
