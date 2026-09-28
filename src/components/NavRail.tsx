import { HomeIcon, ProfileIcon, NetworkIcon, RouteIcon, SettingsIcon } from "../icons";

export type Tab = "home" | "connections" | "network" | "routes" | "settings";

interface NavItem {
  id: Tab;
  label: string;
  icon: React.ReactElement;
}

const PRIMARY: NavItem[] = [
  { id: "home", label: "Home", icon: <HomeIcon size={20} /> },
  { id: "connections", label: "Connections", icon: <ProfileIcon size={20} /> },
];

const ADVANCED: NavItem[] = [
  { id: "network", label: "Network", icon: <NetworkIcon size={20} /> },
  { id: "routes", label: "Routes", icon: <RouteIcon size={20} /> },
];

interface NavRailProps {
  tab: Tab;
  setTab: (tab: Tab) => void;
  activeCount: number;
}

function RailButton({
  item,
  active,
  onClick,
  badge,
}: {
  item: NavItem;
  active: boolean;
  onClick: () => void;
  badge?: number;
}) {
  return (
    <button
      type="button"
      className={`rail-item ${active ? "active" : ""}`}
      onClick={onClick}
      title={item.label}
    >
      {item.icon}
      {badge !== undefined && badge > 0 && (
        <span className="rail-badge">{badge > 9 ? "9+" : badge}</span>
      )}
      <span className="rail-tooltip">{item.label}</span>
    </button>
  );
}

export default function NavRail({ tab, setTab, activeCount }: NavRailProps) {
  return (
    <nav className="rail">
      <div className="rail-brand" title="Network Orchestrator">
        <NetworkIcon size={20} />
      </div>
      <div className="rail-group">
        {PRIMARY.map((item) => (
          <RailButton
            key={item.id}
            item={item}
            active={tab === item.id}
            onClick={() => setTab(item.id)}
            badge={item.id === "connections" ? activeCount : undefined}
          />
        ))}
      </div>
      <div className="rail-divider" />
      <div className="rail-group rail-group-muted">
        {ADVANCED.map((item) => (
          <RailButton
            key={item.id}
            item={item}
            active={tab === item.id}
            onClick={() => setTab(item.id)}
          />
        ))}
      </div>
      <div className="rail-spacer" />
      <div className="rail-group">
        <RailButton
          item={{ id: "settings", label: "Settings", icon: <SettingsIcon size={20} /> }}
          active={tab === "settings"}
          onClick={() => setTab("settings")}
        />
      </div>
    </nav>
  );
}
