import Modal from "./Modal";
import { Profile, ProfileDiagnostics } from "../types";
import { useT } from "../i18n";

interface DiagnosticsModalProps {
  open: boolean;
  diagnostics: ProfileDiagnostics | null;
  profiles: Profile[];
  onClose: () => void;
}

export default function DiagnosticsModal({
  open,
  diagnostics,
  profiles,
  onClose,
}: DiagnosticsModalProps) {
  const t = useT();
  if (!diagnostics) return null;
  const name =
    profiles.find((p) => p.id === diagnostics.profileId)?.name ??
    diagnostics.profileId;
  return (
    <Modal
      open={open}
      title={t("diag.title", { name })}
      onClose={onClose}
      maxWidth="640px"
    >
      <ul className="diagnostics-list">
        {diagnostics.checks.map((check, i) => (
          <li key={i}>
            <span className={`badge diag-${check.level}`}>{check.level}</span>
            <span className="diag-name">{check.name}</span>
            <span className="diag-message">{check.message}</span>
          </li>
        ))}
      </ul>
    </Modal>
  );
}
