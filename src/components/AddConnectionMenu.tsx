import Modal from "./Modal";
import { backendIcon, ImportIcon } from "../icons";
import { TunnelBackend } from "../types";
import { TranslationKey, useT } from "../i18n";

const BACKEND_OPTIONS: { backend: TunnelBackend; titleKey: TranslationKey; descKey: TranslationKey }[] = [
  {
    backend: "wireGuard",
    titleKey: "backend.wireGuard",
    descKey: "add.wireguardDesc",
  },
  {
    backend: "openVpn",
    titleKey: "backend.openVpn",
    descKey: "add.openvpnDesc",
  },
  {
    backend: "xray",
    titleKey: "backend.xray",
    descKey: "add.xrayDesc",
  },
  {
    backend: "none",
    titleKey: "backend.none",
    descKey: "add.staticDesc",
  },
];

interface AddConnectionMenuProps {
  open: boolean;
  onClose: () => void;
  onChooseImport: () => void;
  onChooseBackend: (backend: TunnelBackend) => void;
  /** Orchestrator mode: only route-only profiles may be created — no
   * managed backends and no config import. */
  allowManaged?: boolean;
}

export default function AddConnectionMenu({
  open,
  onClose,
  onChooseImport,
  onChooseBackend,
  allowManaged = true,
}: AddConnectionMenuProps) {
  const t = useT();
  const options = allowManaged
    ? BACKEND_OPTIONS
    : BACKEND_OPTIONS.filter((opt) => opt.backend === "none");
  return (
    <Modal open={open} title={t("add.title")} onClose={onClose} maxWidth="480px">
      <div className="add-connection-list">
        {allowManaged && (
        <button
          type="button"
          className="add-connection-option"
          onClick={onChooseImport}
        >
          <span className="add-connection-icon">
            <ImportIcon size={18} />
          </span>
          <span className="add-connection-text">
            <span className="add-connection-title">
              {t("add.importTitle")}
            </span>
            <span className="add-connection-desc">
              {t("add.importDesc")}
            </span>
          </span>
        </button>
        )}
        {options.map((opt) => (
          <button
            key={opt.backend}
            type="button"
            className="add-connection-option"
            onClick={() => onChooseBackend(opt.backend)}
          >
            <span className="add-connection-icon">
              {backendIcon(opt.backend, 18)}
            </span>
            <span className="add-connection-text">
              <span className="add-connection-title">{t(opt.titleKey)}</span>
              <span className="add-connection-desc">{t(opt.descKey)}</span>
            </span>
          </button>
        ))}
      </div>
    </Modal>
  );
}
