import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { confirm, open } from "@tauri-apps/plugin-dialog";
import {
  BackendAvailability,
  BackendInstallProgress,
  ManagedXrayOffer,
} from "../types";
import { usePlatformCapabilities } from "../platform";
import { useT } from "../i18n";
import { BACKEND_LABEL_KEYS, SOURCE_LABEL_KEYS } from "../i18n/labels";

const MIB = 1024 * 1024;

function progressText(progress: BackendInstallProgress): string {
  const mib = progress.downloaded / MIB;
  if (progress.total && progress.total > 0) {
    const percent = Math.round((progress.downloaded / progress.total) * 100);
    return `${progress.stage} — ${percent}% (${mib.toFixed(1)} / ${(progress.total / MIB).toFixed(1)} MiB)`;
  }
  return `${progress.stage} — ${mib.toFixed(1)} MiB`;
}

function installProgressPercent(progress: BackendInstallProgress): number {
  if (!progress.total || progress.total <= 0) return 0;
  return Math.min(100, Math.round((progress.downloaded / progress.total) * 100));
}

export default function BackendStatus() {
  const t = useT();
  const [items, setItems] = useState<BackendAvailability[]>([]);
  const caps = usePlatformCapabilities();
  const [offer, setOffer] = useState<ManagedXrayOffer | null>(null);
  const [mihomoOffer, setMihomoOffer] = useState<ManagedXrayOffer | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [progress, setProgress] = useState<BackendInstallProgress | null>(null);
  const [cancelling, setCancelling] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [availability, managedOffer, mihomoManagedOffer] = await Promise.all([
        invoke<BackendAvailability[]>("get_backend_availability"),
        invoke<ManagedXrayOffer>("get_managed_xray_offer"),
        caps?.managedMihomoInstall
          ? invoke<ManagedXrayOffer>("get_managed_mihomo_offer")
          : Promise.resolve(null),
      ]);
      setItems(availability);
      setOffer(managedOffer);
      setMihomoOffer(mihomoManagedOffer);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, [caps?.managedMihomoInstall]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    const unlisten = listen<BackendInstallProgress>(
      "backend-install-progress",
      (event) => {
        if (event.payload.backend === "xray" || event.payload.backend === "mihomo") {
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
            name: `${t(BACKEND_LABEL_KEYS[item.backend])} executable`,
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
        t("backend.installConfirm", {
          version: offer.version,
          url: offer.sourceUrl,
          sha256: offer.sha256,
        }),
        { title: t("backend.installTitle"), kind: "info" }
      );
      if (!approved) return;
      setProgress(null);
      setCancelling(false);
      await invoke("install_managed_xray");
    });

  const removeManaged = () =>
    run("remove-xray", async () => {
      const approved = await confirm(
        t("backend.removeConfirm"),
        { title: t("backend.removeTitle"), kind: "warning" }
      );
      if (!approved) return;
      await invoke("remove_managed_xray");
    });
  const installMihomo = () =>
    run("install-mihomo", async () => {
      if (!mihomoOffer) return;
      const approved = await confirm(
        t("backend.installConfirm", {
          version: mihomoOffer.version,
          url: mihomoOffer.sourceUrl,
          sha256: mihomoOffer.sha256,
        }),
        { title: t("backend.installTitle"), kind: "info" }
      );
      if (!approved) return;
      setProgress(null);
      setCancelling(false);
      await invoke("install_managed_mihomo");
    });

  const removeMihomo = () =>
    run("remove-mihomo", async () => {
      const approved = await confirm(
        t("backend.removeConfirm"),
        { title: t("backend.removeTitle"), kind: "warning" }
      );
      if (!approved) return;
      await invoke("remove_managed_mihomo");
    });

  const cancelInstall = async () => {
    setCancelling(true);
    try {
      await invoke(
        busy === "install-mihomo"
          ? "cancel_managed_mihomo_install"
          : "cancel_managed_xray_install"
      );
    } catch (err) {
      setError(String(err));
      setCancelling(false);
    }
  };

  return (
    <div className="backend-status">
      <div className="backend-status-head">
        <span className="section-label">{t("backend.prerequisites")}</span>
        <button type="button" className="btn-sm" onClick={load} disabled={loading || busy !== null}>
          {loading ? t("backend.checking") : t("common.refresh")}
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      {items.map((item) => (
        <div key={item.backend} className="backend-status-row">
          <span className="backend-name">{t(BACKEND_LABEL_KEYS[item.backend])}</span>
          <span
            className={`badge ${item.available ? "badge-managed" : "badge-external"}`}
          >
            {item.available ? t("backend.available") : t("backend.missing")}
          </span>
          {item.source && (
            <span className={`badge badge-source-${item.source.toLowerCase()}`}>
              {t(SOURCE_LABEL_KEYS[item.source])}
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
            {item.backend !== "mihomo" && !(caps?.os === "linux" && (item.backend === "wireGuard" || item.backend === "openVpn")) && (
              <button
                type="button"
                className="btn-sm"
                disabled={busy !== null || item.source === "managed"}
                onClick={() => chooseExecutable(item)}
              >
                {t("backend.chooseExisting")}
              </button>
            )}
            {item.source === "configured" && (
              <button
                type="button"
                className="btn-sm"
                disabled={busy !== null}
                onClick={() => resetExecutable(item)}
              >
                {t("backend.resetAuto")}
              </button>
            )}
            {item.backend === "xray" &&
              item.source !== "managed" &&
              offer &&
              caps?.managedXrayInstall && (
              <button
                type="button"
                className="btn-sm"
                disabled={busy !== null}
                onClick={installManaged}
              >
                {t("backend.installManaged", { version: offer.version })}
              </button>
            )}
            {item.backend === "xray" && item.source === "managed" && (
              <button
                type="button"
                className="btn-sm"
                disabled={busy !== null}
                onClick={removeManaged}
              >
                {t("backend.removeManaged")}
              </button>
            )}
            {item.backend === "mihomo" && (
              caps?.managedMihomoInstall ? (
                item.source === "managed" ? (
                  <button
                    type="button"
                    className="btn-sm"
                    disabled={busy !== null}
                    onClick={removeMihomo}
                  >
                    {t("Remove Mihomo")}
                  </button>
                ) : (
                  <button
                    type="button"
                    className="btn-sm"
                    disabled={busy !== null || !mihomoOffer}
                    onClick={installMihomo}
                  >
                    {mihomoOffer
                      ? t("Install Mihomo")
                      : t("Managed Mihomo is supported on Linux x86-64 only.")}
                  </button>
                )
              ) : (
                <span className="row-value">{t("Managed Mihomo is supported on Linux x86-64 only.")}</span>
              )
            )}
          </span>
        </div>
      ))}
      {(busy === "install-xray" || busy === "install-mihomo") && progress && (
        <div className="backend-install-progress">
          <div className="progress">
            <div
              className="progress-fill"
              style={{ width: `${installProgressPercent(progress)}%` }}
            />
          </div>
          <div className="backend-install-row">
            <span className="row-value">{progressText(progress)}</span>
            <button type="button" className="btn-sm" onClick={cancelInstall} disabled={cancelling}>
              {cancelling ? t("common.cancelling") : t("common.cancel")}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
