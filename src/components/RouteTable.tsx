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

  if (loading) return <p>Loading routes...</p>;
  if (error) return <p className="error">Error loading routes: {error}</p>;

  return (
    <section>
      <h2>Routes</h2>
      {routes.length === 0 ? (
        <p>No routes found.</p>
      ) : (
        <table className="route-table">
          <thead>
            <tr>
              <th>Destination</th>
              <th>Prefix</th>
              <th>Gateway</th>
              <th>Interface</th>
              <th>Metric</th>
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
