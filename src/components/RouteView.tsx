import { tr } from "../i18n";
import { useState } from "react";
import Page from "./Page";
import RouteOverview from "./RouteOverview";
import RouteByInterface from "./RouteByInterface";
import RouteFlow from "./RouteFlow";
import RouteMap from "./RouteMap";
import RouteTable from "./RouteTable";
import RouteLookup from "./RouteLookup";

type RouteTab =
  | "overview"
  | "interfaces"
  | "flow"
  | "tree"
  | "table"
  | "lookup";

const TABS: { id: RouteTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "interfaces", label: "By interface" },
  { id: "flow", label: "Traffic flow" },
  { id: "tree", label: "Tree" },
  { id: "table", label: "Raw table" },
  { id: "lookup", label: "Lookup" },
];

export default function RouteView() {
  const [tab, setTab] = useState<RouteTab>("overview");

  return (
    <Page width="wide">
      <section>
        <h2>{tr("Routes")}</h2>
        <div className="route-tabs">
          {TABS.map((t) => (
            <button
              key={t.id}
              className={`route-tab ${tab === t.id ? "active" : ""}`}
              onClick={() => setTab(t.id)}
            >
              {tr(t.label)}
            </button>
          ))}
        </div>
        <div className="route-tab-content">
          {tab === "overview" && <RouteOverview />}
          {tab === "interfaces" && <RouteByInterface />}
          {tab === "flow" && <RouteFlow />}
          {tab === "tree" && <RouteMap />}
          {tab === "table" && <RouteTable />}
          {tab === "lookup" && <RouteLookup />}
        </div>
      </section>
    </Page>
  );
}
