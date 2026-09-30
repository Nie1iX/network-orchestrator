import { tr } from "../i18n";
import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { confirm, open } from "@tauri-apps/plugin-dialog";
import {
  BackendAvailability,
  BackendExecutableSource,
  BackendInstallProgress,
  ManagedXrayOffer,
  TunnelBackend,
} from "../types";
import { usePlatformCapabilities } from "../platform";

const BACKEND_LABELS: Record<TunnelBackend, string> = {
  none: "Static routes",
  wireGuard: "WireGuard",
  openVpn: "OpenVPN",
  xray: "Xray",
};

const SOURCE_LABELS: Record<BackendExecutableSource, string> = {
  autoDetected: "Auto-detected",
  configured: "Configured",
  managed: "Managed",
};

const MIB = 1024 * 1024;

function progressText(progress: BackendInstallProgress): string {
  const mib = progress.downloaded / MIB;
  if (progress.total && progress.total > 0) {
    const percent = Math.round((progress.downloaded / progress.total) * 100);
    return `${progress.stage} — ${percent}% (${mib.toFixed(1)} / ${(progress.total / MIB).toFixed(1)} MiB)`;
  }
  return `${progress.stage} — ${mib.toFixed(1)} MiB`;
}

export default function BackendStatus() {
  const [items, setItems] = useState<BackendAvailability[]>([]);
  const caps = usePlatformCapabilities();
  const [offer, setOffer] = useState<ManagedXrayOffer | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [progress, setProgress] = useState<BackendInstallProgress | null>(null);
  const [cancelling, setCancelling] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [availability, managedOffer] = await Promise.all([
        invoke<BackendAvailability[]>("get_backend_availability"),
        invoke<ManagedXrayOffer>("get_managed_xray_offer"),
      ]);
      setItems(availability);
      setOffer(managedOffer);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    const unlisten = listen<BackendInstallProgress>(
      "backend-install-progress",
      (event) => {
        if (event.payload.backend === "xray") {
          setProgress(event.payload);
        }
      }
    );
    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  const run = useCallback(
    async (key: string, action: () => Promise<void>) => {
      setBusy(key);
      setError(null);
      try {
        await action();
        await load();
      } catch (err) {
        setError(String(err));
      } finally {
        setBusy(null);
      }
    },
    [load]
  );

  const chooseExecutable = (item: BackendAvailability) =>
    run(`choose-${item.backend}`, async () => {
      const selected = await open({
        multiple: false,
        directory: false,
        filters: [
          {
            name: tr("{backend} executable", { backend: BACKEND_LABELS[item.backend] }),
            extensions: caps?.executableExtensions ?? [],
          },
        ].filter((filter) => filter.extensions.length > 0),
      });
      if (typeof selected === "string") {
        await invoke("set_backend_executable", {
          backend: item.backend,
          path: selected,
        });
      }
    });

  const resetExecutable = (item: BackendAvailability) =>
    run(`reset-${item.backend}`, () =>
      invoke("reset_backend_executable", { backend: item.backend })
    );

  const installManaged = () =>
    run("install-xray", async () => {
      if (!offer) return;
      const approved = await confirm(
        tr("Install managed Xray {version}?\n\nThe archive will be downloaded from:\n{sourceUrl}\n\nSHA-256: {sha256}\n\nFiles are verified and stored under the application data directory. Managed installations are never updated automatically.", {
          version: offer.version, sourceUrl: offer.sourceUrl, sha256: offer.sha256,
        }),
        { title: tr("Install managed Xray"), kind: "info" }
      );
      if (!approved) return;
      setProgress(null);
      setCancelling(false);
      await invoke("install_managed_xray");
    });

  const removeManaged = () =>
    run("remove-xray", async () => {
      const approved = await confirm(
        tr("Remove the managed Xray installation? Managed files will be deleted. Your profiles and configs are not affected."),
        { title: tr("Remove managed Xray"), kind: "warning" }
      );
      if (!approved) return;
      await invoke("remove_managed_xray");
    });

  const cancelInstall = async () => {
    setCancelling(true);
    try {
      await invoke("cancel_managed_xray_install");
    } catch (err) {
      setError(String(err));
      setCancelling(false);
    }
  };

  return (
    <div className="backend-status">
      <div className="backend-status-head">
        <span className="section-label">{tr("Backend prerequisites")}</span>
        <button type="button" onClick={load} disabled={loading || busy !== null}>
          {loading ? tr("Checking…") : tr("Refresh")}
        </button>
      </div>
      {error && <p className="error">{tr(error)}</p>}
      {items.map((item) => (
        <div key={item.backend} className="backend-status-row">
          <span className="backend-name">{tr(BACKEND_LABELS[item.backend])}</span>
          <span
            className={`badge ${item.available ? "badge-managed" : "badge-external"}`}
          >
            {item.available ? tr("Available") : tr("Missing")}
          </span>
          {item.source && (
            <span className={`badge badge-source-${item.source.toLowerCase()}`}>
              {tr(SOURCE_LABELS[item.source])}
            </span>
          )}
          {item.version && (
            <span className="badge badge-version">{item.version}</span>
          )}
          <span className="row-value mono backend-detail">
            {item.path ?? item.message}
            {!item.available && item.path ? ` — ${item.message}` : ""}
          </span>
          <span className="backend-actions">
            {!(caps?.os === "linux" && (item.backend === "wireGuard" || item.backend === "openVpn")) && (
              <button
                type="button"
                disabled={busy !== null || item.source === "managed"}
                onClick={() => chooseExecutable(item)}
              >
                {tr("Choose existing…")}</button>
            )}
            {item.source === "configured" && (
              <button
                type="button"
                disabled={busy !== null}
                onClick={() => resetExecutable(item)}
              >
                {tr("Reset to auto-detect")}</button>
            )}
            {item.backend === "xray" &&
              item.source !== "managed" &&
              offer &&
              caps?.managedXrayInstall && (
              <button
                type="button"
                disabled={busy !== null}
                onClick={installManaged}
              >
                {tr("Install managed ")}{offer.version}
              </button>
            )}
            {item.backend === "xray" && item.source === "managed" && (
              <button
                type="button"
                disabled={busy !== null}
                onClick={removeManaged}
              >
                {tr("Remove managed")}</button>
            )}
          </span>
        </div>
      ))}
      {busy === "install-xray" && progress && (
        <div className="backend-install-progress">
          <span className="row-value">{progressText(progress)}</span>
          <button type="button" onClick={cancelInstall} disabled={cancelling}>
            {cancelling ? tr("Cancelling…") : tr("Cancel")}
          </button>
        </div>
      )}
    </div>
  );
}
