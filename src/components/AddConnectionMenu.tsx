import { tr } from "../i18n";
import Modal from "./Modal";
import { backendIcon, ImportIcon } from "../icons";
import { TunnelBackend } from "../types";

const BACKEND_OPTIONS: { backend: TunnelBackend; title: string; desc: string }[] = [
  {
    backend: "wireGuard",
    title: "WireGuard",
    desc: "Enter tunnel keys, or open an existing .conf file.",
  },
  {
    backend: "openVpn",
    title: "OpenVPN",
    desc: "Use an existing .ovpn client config.",
  },
  {
    backend: "xray",
    title: "Xray",
    desc: "Import a vless:// or hysteria2:// link, or an Xray JSON config.",
  },
  {
    backend: "none",
    title: "Static routes",
    desc: "Route traffic through an existing interface, no tunnel.",
  },
];

interface AddConnectionMenuProps {
  open: boolean;
  onClose: () => void;
  onChooseImport: () => void;
  onChooseBackend: (backend: TunnelBackend) => void;
}

export default function AddConnectionMenu({
  open,
  onClose,
  onChooseImport,
  onChooseBackend,
}: AddConnectionMenuProps) {
  return (
    <Modal open={open} title={tr("Add a connection")} onClose={onClose} maxWidth="480px">
      <div className="add-connection-list">
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
              {tr("Paste a link or import a file")}</span>
            <span className="add-connection-desc">
              {tr("Subscription URL, share link, or a config file")}</span>
          </span>
        </button>
        {BACKEND_OPTIONS.map((opt) => (
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
              <span className="add-connection-title">{tr(opt.title)}</span>
              <span className="add-connection-desc">{tr(opt.desc)}</span>
            </span>
          </button>
        ))}
      </div>
    </Modal>
  );
}
