import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import Modal from "./Modal";
import { ensureElevation } from "../elevation";
import { BatchImportResult } from "../types";
import { usePlatformCapabilities } from "../platform";
import { tr, useT } from "../i18n";

type ImportTab = "files" | "link" | "subscription" | "wireguard";

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
  const [shareLink, setShareLink] = useState("");
  const [linkName, setLinkName] = useState("");
  const [linkError, setLinkError] = useState<string | null>(null);
  const [subUrl, setSubUrl] = useState("");
  const [subHwid, setSubHwid] = useState("");
  const [subRefreshMinutes, setSubRefreshMinutes] = useState<number | null>(null);
  const t = useT();

  const onImportLink = async () => {
    if (busy || !shareLink.trim()) return;
    setBusy(true);
    setLinkError(null);
    try {
      const result = await invoke<BatchImportResult>("import_share_link", {
        link: shareLink.trim(), name: linkName.trim(),
      });
      onImported(result);
      setShareLink("");
      setLinkName("");
      onClose();
    } catch (err) {
      setLinkError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const onImportFiles = async () => {
    setBusy(true);
    try {
      const selected = await openDialog({
        multiple: true,
        directory: false,
        filters: [
          {
            name: t("import.filesFilter"),
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
      if (!(await ensureElevation(t("elev.actImportWg")))) {
        return;
      }
      const paths = await invoke<string[]>("discover_wireguard_configs");
      if (paths.length === 0) {
        onError(t("import.noWgConfigs"));
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
      title={t("import.title")}
      onClose={onClose}
      maxWidth="520px"
    >
      <div className="modal-tabs">
        <button
          type="button"
          className={`modal-tab ${tab === "files" ? "active" : ""}`}
          onClick={() => setTab("files")}
        >
          {t("import.tabFiles")}
        </button>
        <button
          type="button"
          className={`modal-tab ${tab === "link" ? "active" : ""}`}
          onClick={() => setTab("link")}
          disabled={busy}
        >
          {tr("Link")}
        </button>
        <button
          type="button"
          className={`modal-tab ${tab === "subscription" ? "active" : ""}`}
          onClick={() => setTab("subscription")}
        >
          {t("import.tabSub")}
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

      {tab === "link" && (
        <form className="modal-tab-body" onSubmit={(event) => { event.preventDefault(); void onImportLink(); }}>
          <p className="profile-help">{tr("Paste a vless://, hysteria2:// or hy2:// share link. Import saves a connection without starting a VPN.")}</p>
          <label>
            {tr("Share link")}
            <input
              type="password"
              value={shareLink}
              onChange={(event) => { setShareLink(event.target.value); setLinkError(null); }}
              placeholder={tr("vless:// or hysteria2://…")}
              autoComplete="off"
              spellCheck={false}
              maxLength={65536}
              disabled={busy}
            />
          </label>
          <label>
            {tr("Connection name (optional)")}
            <input type="text" value={linkName} onChange={(event) => setLinkName(event.target.value)}
              placeholder={tr("Use the name from the link")} disabled={busy} />
          </label>
          {linkError && <p role="alert" className="error">{tr(linkError)}</p>}
          <button type="submit" className="profile-import-btn" disabled={busy || !shareLink.trim()}>
            {busy ? tr("Importing…") : tr("Import link")}
          </button>
        </form>
      )}

      {tab === "files" && (
        <div className="modal-tab-body">
          <p className="profile-help">
            {t("import.filesHelp")}
          </p>
          <button
            type="button"
            className="btn-primary"
            onClick={onImportFiles}
            disabled={busy}
          >
            {busy ? t("import.importing") : t("import.browse")}
          </button>
        </div>
      )}

      {tab === "subscription" && (
        <div className="modal-tab-body">
          <p className="profile-help">
            {t("import.subHelp")}
          </p>
          <label>
            {t("import.subUrl")}
            <input
              type="text"
              value={subUrl}
              onChange={(e) => setSubUrl(e.target.value)}
              placeholder="https://example.com/sub"
            />
          </label>
          <label>
            {t("import.hwid")}
            <input
              type="password"
              value={subHwid}
              onChange={(e) => setSubHwid(e.target.value)}
              placeholder="device-hwid"
            />
          </label>
          <label>
            {t("import.autoRefresh")}
            <select
              value={subRefreshMinutes ?? ""}
              onChange={(event) => setSubRefreshMinutes(event.target.value ? Number(event.target.value) : null)}
            >
              <option value="">{t("common.off")}</option>
              <option value="15">{t("detail.every15")}</option>
              <option value="60">{t("detail.everyHour")}</option>
              <option value="360">{t("detail.every6h")}</option>
            </select>
          </label>
          <button
            type="button"
            className="btn-primary"
            onClick={onImportSubscription}
            disabled={busy || !subUrl.trim()}
          >
            {busy ? t("import.fetching") : t("import.fetch")}
          </button>
        </div>
      )}

      {tab === "wireguard" && caps?.wireguardStandardImport && (
        <div className="modal-tab-body">
          <p className="profile-help">
            {t("import.wgHelp")}
          </p>
          <button
            type="button"
            className="btn-primary"
            onClick={onImportWireGuardStandard}
            disabled={busy}
          >
            {busy ? t("import.importing") : t("import.wgImport")}
          </button>
        </div>
      )}
    </Modal>
  );
}
