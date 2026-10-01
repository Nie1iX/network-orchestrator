import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { RouteEntry } from "../types";
import { useT } from "../i18n";

export default function RouteTable({ hideIpv6 }: { hideIpv6: boolean }) {
  const t = useT();
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

  if (loading) return <p>{t("routes.loading")}</p>;
  if (error) return <p className="error">{t("routes.loadError", { err: error })}</p>;

  const visible = routes.filter(
    (r) => !hideIpv6 || !r.destination.includes(":"),
  );

  return (
    <section>
      {visible.length === 0 ? (
        <p>{t("routes.none")}</p>
      ) : (
        <table className="route-table">
          <thead>
            <tr>
              <th>{t("routes.destination")}</th>
              <th>{t("routes.prefix")}</th>
              <th>{t("routes.gateway")}</th>
              <th>{t("routes.interfaceCol")}</th>
              <th className="num">{t("routes.metricCol")}</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((route, i) => (
              <tr key={i}>
                <td className="mono">{route.destination}</td>
                <td className="num">/{route.prefixLen}</td>
                <td className="mono">{route.gateway ?? "—"}</td>
                <td>{route.interfaceName}</td>
                <td className="num">{route.metric}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
