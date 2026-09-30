import { tr } from "../../i18n";
interface ToggleSwitchProps {
  checked: boolean;
  onChange: () => void;
  disabled?: boolean;
  busy?: boolean;
  title?: string;
}

export default function ToggleSwitch({
  checked,
  onChange,
  disabled,
  busy,
  title,
}: ToggleSwitchProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      className={`toggle-switch ${checked ? "on" : "off"} ${busy ? "busy" : ""}`}
      onClick={onChange}
      disabled={disabled || busy}
      title={title === undefined ? undefined : tr(title)}
    >
      <span className="toggle-switch-thumb" />
    </button>
  );
}
