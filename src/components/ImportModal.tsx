import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import Modal from "./Modal";
import { ensureElevation } from "../elevation";
import { BatchImportResult } from "../types";
import { usePlatformCapabilities } from "../platform";

type ImportTab = "files" | "subscription" | "wireguard";

interface ImportModalProps {
  open: boolean;
  onClose: () => void;
  onImported: (result: BatchImportResult) => void;
  onError: (message: string) => void;
}

export default function ImportModal({
  open,
  onClose,
  onImported,
  onError,
}: ImportModalProps) {
  const [tab, setTab] = useState<ImportTab>("files");
  const caps = usePlatformCapabilities();
  const [busy, setBusy] = useState(false);
  const [subUrl, setSubUrl] = useState("");
  const [subHwid, setSubHwid] = useState("");
  const [subRefreshMinutes, setSubRefreshMinutes] = useState<number | null>(null);

  const onImportFiles = async () => {
    setBusy(true);
    try {
      const selected = await openDialog({
        multiple: true,
        directory: false,
        filters: [
          {
            name: "Tunnel configs",
            extensions: ["conf", "dpapi", "ovpn", "json"],
          },
        ],
      });
      const paths = Array.isArray(selected)
        ? selected
        : selected
          ? [selected]
          : [];
      if (paths.length === 0) return;
      const result = await invoke<BatchImportResult>("import_configs_batch", {
        paths,
        defaultBackend: null,
      });
      onImported(result);
      onClose();
    } catch (err) {
      onError(String(err));
    } finally {
      setBusy(false);
    }
  };

  const onImportSubscription = async () => {
    if (!subUrl.trim()) return;
    setBusy(true);
    try {
      const result = await invoke<BatchImportResult>("import_subscription", {
        url: subUrl.trim(),
        hwid: subHwid.trim(),
        refreshIntervalMinutes: subRefreshMinutes,
      });
      onImported(result);
      setSubUrl("");
      setSubHwid("");
      setSubRefreshMinutes(null);
      onClose();
    } catch (err) {
      onError(String(err));
    } finally {
      setBusy(false);
    }
  };

  const onImportWireGuardStandard = async () => {
    setBusy(true);
    try {
      if (!(await ensureElevation("Importing WireGuard configs"))) {
        return;
      }
      const paths = await invoke<string[]>("discover_wireguard_configs");
      if (paths.length === 0) {
        onError("No WireGuard configs found in the standard location");
        return;
      }
      const result = await invoke<BatchImportResult>("import_configs_batch", {
        paths,
        defaultBackend: "wireGuard",
      });
      onImported(result);
      onClose();
    } catch (err) {
      onError(String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      title="Import configurations"
      onClose={onClose}
      maxWidth="520px"
    >
      <div className="modal-tabs">
        <button
          type="button"
          className={`modal-tab ${tab === "files" ? "active" : ""}`}
          onClick={() => setTab("files")}
        >
          Files
        </button>
        <button
          type="button"
          className={`modal-tab ${tab === "subscription" ? "active" : ""}`}
          onClick={() => setTab("subscription")}
        >
          Subscription
        </button>
        {caps?.wireguardStandardImport && (
          <button
            type="button"
            className={`modal-tab ${tab === "wireguard" ? "active" : ""}`}
            onClick={() => setTab("wireguard")}
          >
            WireGuard (standard)
          </button>
        )}
      </div>

      {tab === "files" && (
        <div className="modal-tab-body">
          <p className="profile-help">
            Select one or more WireGuard (.conf/.conf.dpapi), OpenVPN (.ovpn),
            or Xray (.json) config files. Backend is detected from extension.
          </p>
          <button
            type="button"
            className="btn-primary"
            onClick={onImportFiles}
            disabled={busy}
          >
            {busy ? "Importing…" : "Browse files…"}
          </button>
        </div>
      )}

      {tab === "subscription" && (
        <div className="modal-tab-body">
          <p className="profile-help">
            Import a subscription URL. Supported vless:// and hysteria2://
            endpoints are grouped into a profile with an endpoint selector.
          </p>
          <label>
            Subscription URL
            <input
              type="text"
              value={subUrl}
              onChange={(e) => setSubUrl(e.target.value)}
              placeholder="https://example.com/sub"
            />
          </label>
          <label>
            HWID (X-HWID header, optional)
            <input
              type="password"
              value={subHwid}
              onChange={(e) => setSubHwid(e.target.value)}
              placeholder="device-hwid"
            />
          </label>
          <label>
            Automatic refresh
            <select
              value={subRefreshMinutes ?? ""}
              onChange={(event) => setSubRefreshMinutes(event.target.value ? Number(event.target.value) : null)}
            >
              <option value="">Off</option>
              <option value="15">Every 15 minutes</option>
              <option value="60">Every hour</option>
              <option value="360">Every 6 hours</option>
            </select>
          </label>
          <button
            type="button"
            className="btn-primary"
            onClick={onImportSubscription}
            disabled={busy || !subUrl.trim()}
          >
            {busy ? "Fetching…" : "Fetch subscription"}
          </button>
        </div>
      )}

      {tab === "wireguard" && caps?.wireguardStandardImport && (
        <div className="modal-tab-body">
          <p className="profile-help">
            Import all WireGuard configs from the standard Windows location
            (C:\Program Files\WireGuard\Data\Configurations). Requires
            administrator privileges to read encrypted .conf.dpapi files.
          </p>
          <button
            type="button"
            className="btn-primary"
            onClick={onImportWireGuardStandard}
            disabled={busy}
          >
            {busy ? "Importing…" : "Import WireGuard (standard)"}
          </button>
        </div>
      )}
    </Modal>
  );
}
