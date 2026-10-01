import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { RouteMap as RouteMapData } from "../types";
import {
  flowNeutral,
  flowNeutralFaint,
  flowText,
  flowTextDim,
  ownerColors,
  ownerFallback,
  useTheme,
} from "../palette";
import { useT } from "../i18n";

// Simple Sankey-style flow: Profile → Interface → Destination prefix group.
// Rendered as horizontal bands with SVG paths, no external library.

interface FlowNode {
  id: string;
  label: string;
  type: "profile" | "interface" | "dest";
  value: number;
  color: string;
}

interface FlowLink {
  source: number;
  target: number;
  value: number;
  color: string;
}

function destGroup(dest: string): string {
  if (dest === "0.0.0.0/0") return "0.0.0.0/0 (default)";
  if (dest === "::/0") return "::/0 (default)";
  const parts = dest.split(".");
  if (parts.length >= 2) return `${parts[0]}.${parts[1]}.0.0/16`;
  return dest;
}

export default function RouteFlow({ hideIpv6 }: { hideIpv6: boolean }) {
  const t = useT();
  const theme = useTheme();
  const [map, setMap] = useState<RouteMapData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetch = async () => {
    try {
      setError(null);
      const data = await invoke<RouteMapData>("get_route_map", { includeInactive: true });
      setMap(data);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetch();
    const handler = () => fetch();
    window.addEventListener("route-changed", handler);
    return () => window.removeEventListener("route-changed", handler);
  }, []);

  const { nodes, links } = useMemo(() => {
    if (!map) return { nodes: [] as FlowNode[], links: [] as FlowLink[] };

    const active = map.predicted.filter(
      (r) => r.active && !(hideIpv6 && r.destination.includes(":")),
    );
    const owners = [...new Set(active.map((r) => r.ownerName))];
    const colorMap = new Map<string, string>();
    const colors = ownerColors(theme);
    owners.forEach((o, i) => colorMap.set(o, colors[i % colors.length]));

    // Build 3 columns: profiles → interfaces → dest groups
    const profileNodes = new Map<string, number>();
    const ifaceNodes = new Map<string, number>();
    const destNodes = new Map<string, number>();
    const nodeList: FlowNode[] = [];

    // Links: profile → interface
    const p2iLinks: FlowLink[] = [];
    // Links: interface → dest
    const i2dLinks: FlowLink[] = [];

    for (const r of active) {
      const pKey = r.ownerName;
      const iKey = r.interfaceName ?? "auto";
      const dKey = destGroup(r.destination);

      if (!profileNodes.has(pKey)) {
        profileNodes.set(pKey, nodeList.length);
        nodeList.push({
          id: pKey,
          label: pKey,
          type: "profile",
          value: 0,
          color: colorMap.get(pKey) ?? ownerFallback(theme),
        });
      }
      nodeList[profileNodes.get(pKey)!].value++;

      if (!ifaceNodes.has(iKey)) {
        ifaceNodes.set(iKey, nodeList.length);
        nodeList.push({
          id: iKey,
          label: iKey,
          type: "interface",
          value: 0,
          color: flowNeutral(theme),
        });
      }
      nodeList[ifaceNodes.get(iKey)!].value++;

      if (!destNodes.has(dKey)) {
        destNodes.set(dKey, nodeList.length);
        nodeList.push({
          id: dKey,
          label: dKey,
          type: "dest",
          value: 0,
          color: flowNeutralFaint(theme),
        });
      }
      nodeList[destNodes.get(dKey)!].value++;

      // profile → interface link
      const pIdx = profileNodes.get(pKey)!;
      const iIdx = ifaceNodes.get(iKey)!;
      const existingPI = p2iLinks.find((l) => l.source === pIdx && l.target === iIdx);
      if (existingPI) {
        existingPI.value++;
      } else {
        p2iLinks.push({
          source: pIdx,
          target: iIdx,
          value: 1,
          color: colorMap.get(pKey) ?? ownerFallback(theme),
        });
      }

      // interface → dest link
      const dIdx = destNodes.get(dKey)!;
      const existingID = i2dLinks.find((l) => l.source === iIdx && l.target === dIdx);
      if (existingID) {
        existingID.value++;
      } else {
        i2dLinks.push({
          source: iIdx,
          target: dIdx,
          value: 1,
          color: flowNeutral(theme),
        });
      }
    }

    return { nodes: nodeList, links: [...p2iLinks, ...i2dLinks] };
  }, [map, theme, hideIpv6]);

  if (loading) return <p>{t("routes.loadingFlow")}</p>;
  if (error) return <p className="error">{t("common.error", { err: error })}</p>;
  if (!map) return null;

  if (nodes.length === 0) {
    return <p className="empty-state">{t("routes.noActiveRoutes")}</p>;
  }

  // Layout: 3 columns
  const colWidth = 180;
  const colGap = 120;
  const totalWidth = colWidth * 3 + colGap * 2;
  const nodeHeight = 28;
  const nodeGap = 8;
  const padding = 20;

  const profiles = nodes.filter((n) => n.type === "profile");
  const ifaces = nodes.filter((n) => n.type === "interface");
  const dests = nodes.filter((n) => n.type === "dest");

  const layoutColumn = (items: FlowNode[], col: number) => {
    let y = padding;
    return items.map((n) => {
      const node = {
        ...n,
        x: col * (colWidth + colGap) + padding,
        y,
        h: nodeHeight,
        w: colWidth - padding * 2,
      };
      y += nodeHeight + nodeGap;
      return node;
    });
  };

  const profileLayout = layoutColumn(profiles, 0);
  const ifaceLayout = layoutColumn(ifaces, 1);
  const destLayout = layoutColumn(dests, 2);

  const allLayout = [...profileLayout, ...ifaceLayout, ...destLayout];
  const totalHeight = Math.max(
    allLayout.reduce((max, n) => Math.max(max, n.y + n.h), 0) + padding,
    200,
  );

  // Map node index to layout position
  const nodePos = new Map<number, { x: number; y: number; h: number; w: number }>();
  allLayout.forEach((n) => {
    const idx = nodes.findIndex((nn) => nn.id === n.id && nn.type === n.type);
    if (idx >= 0) {
      nodePos.set(idx, { x: n.x, y: n.y, h: n.h, w: colWidth - padding * 2 });
    }
  });

  return (
    <div className="route-flow">
      <p className="flow-hint">
        {t("routes.flowHint")}: <strong>{t("routes.profile")}</strong> →{" "}
        <strong>{t("routes.interface")}</strong> →{" "}
        <strong>{t("routes.destinationWord")}</strong>.{" "}
        {t("routes.onlyActive")}
      </p>
      <div className="flow-container">
        <svg width={totalWidth} height={totalHeight} className="flow-svg">
          {/* Links */}
          {links.map((link, i) => {
            const src = nodePos.get(link.source);
            const tgt = nodePos.get(link.target);
            if (!src || !tgt) return null;
            const x1 = src.x + src.w;
            const x2 = tgt.x;
            const y1 = src.y + src.h / 2;
            const y2 = tgt.y + tgt.h / 2;
            const mx = (x1 + x2) / 2;
            const path = `M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`;
            return (
              <path
                key={i}
                d={path}
                fill="none"
                stroke={link.color}
                strokeWidth={Math.max(1, Math.min(link.value * 2, 8))}
                opacity={0.4}
              />
            );
          })}
          {/* Nodes */}
          {allLayout.map((n, i) => (
            <g key={i}>
              <rect
                x={n.x}
                y={n.y}
                width={n.w}
                height={n.h}
                rx={6}
                fill={n.color}
                opacity={n.type === "profile" ? 0.9 : 0.6}
              />
              <text
                x={n.x + n.w / 2}
                y={n.y + n.h / 2 + 4}
                textAnchor="middle"
                fill={flowText(theme)}
                fontSize={11}
                fontWeight={n.type === "profile" ? 600 : 400}
              >
                {n.label.length > 22 ? n.label.slice(0, 20) + "…" : n.label}
              </text>
              <text
                x={n.x + n.w - 6}
                y={n.y + n.h / 2 + 4}
                textAnchor="end"
                fill={flowTextDim(theme)}
                fontSize={9}
              >
                {n.value}
              </text>
            </g>
          ))}
        </svg>
      </div>
    </div>
  );
}
