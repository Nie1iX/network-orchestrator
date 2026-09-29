import { backendIcon } from "../../icons";
import { formatBytes } from "../../format";
import {
  AlwaysOnKind,
  AlwaysOnListResult,
  DomainPolicy,
  DomainRouteTarget,
  Profile,
  SubscriptionDelayResult,
  SubscriptionEndpointInfo,
  TunnelStatus,
} from "../../types";
import OverflowMenu from "../ui/OverflowMenu";
import RateText from "../ui/RateText";
import ToggleSwitch from "../ui/ToggleSwitch";

export const DOMAIN_TARGET_LABELS: Record<DomainRouteTarget, string> = {
  block: "Block",
  proxy: "Proxy",
  direct: "Direct",
};

/** Counts real selectors; `#` comment lines are stored in `domains` for
 * round-trip through the editor but are not rules. */
function countPolicyRules(
  policies: DomainPolicy[],
  target?: DomainRouteTarget,
): number {
  return policies
    .filter((p) => target === undefined || p.target === target)
    .flatMap((p) => p.domains)
    .filter((d) => !d.trimStart().startsWith("#")).length;
}

interface ProfileDetailProps {
  profile: Profile;
  status: TunnelStatus;
  rate: { rxRate: number; txRate: number } | null;
  isBusy: boolean;
  backendLabel: string;
  managedConfig: boolean | undefined;
  alwaysOn: AlwaysOnListResult | null;
  os: string | undefined;
  endpoints: SubscriptionEndpointInfo[] | undefined;
  delayResults: Record<number, SubscriptionDelayResult> | undefined;
  measuringEndpoints: Set<string>;
  measuringAll: boolean;
  switching: boolean;
  refreshingSubscription: boolean;
  settingRefreshInterval: boolean;
  diagBusy: boolean;
  canMoveUp: boolean;
  canMoveDown: boolean;
  onConnect: () => void;
  onDisconnect: () => void;
  onEdit: () => void;
  onMoveUp: () => void;
  onMoveDown: () => void;
  onToggleAlwaysOn: (kind: AlwaysOnKind, enrolled: boolean) => void;
  onCredentials: () => void;
  onRefreshSubscription: () => void;
  onDiagnose: () => void;
  onDelete: () => void;
  onSwitchEndpoint: (index: number) => void;
  onMeasureAllEndpoints: () => void;
  onSetRefreshInterval: (minutes: number | null) => void;
}

export default function ProfileDetail({
  profile,
  status,
  rate,
  isBusy,
  backendLabel,
  managedConfig,
  alwaysOn,
  os,
  endpoints,
  delayResults,
  measuringEndpoints,
  measuringAll,
  switching,
  refreshingSubscription,
  settingRefreshInterval,
  diagBusy,
  canMoveUp,
  canMoveDown,
  onConnect,
  onDisconnect,
  onEdit,
  onMoveUp,
  onMoveDown,
  onToggleAlwaysOn,
  onCredentials,
  onRefreshSubscription,
  onDiagnose,
  onDelete,
  onSwitchEndpoint,
  onMeasureAllEndpoints,
  onSetRefreshInterval,
}: ProfileDetailProps) {
  const alwaysOnKind: AlwaysOnKind | null =
    profile.backend === "wireGuard"
      ? "wireGuard"
      : profile.backend === "none"
        ? "staticRoutes"
        : null;
  const alwaysOnEntry = alwaysOn?.profiles.find(
    (item) => item.profileId === profile.id && item.kind === alwaysOnKind,
  );
  const canEnableAlwaysOn =
    alwaysOnKind !== null &&
    alwaysOn?.supportedKinds.includes(alwaysOnKind) === true &&
    (alwaysOnKind === "wireGuard" ||
      (profile.interfaceName.length > 0 && profile.routes.length > 0));
  const ruleCount = countPolicyRules(profile.domainPolicies);
  const detailCount = profile.routes.length + ruleCount;

  return (
    <div className="profile-detail">
      <div className="profile-detail-head">
        <span
          className={`backend-avatar backend-avatar-lg backend-avatar-${profile.backend}`}
        >
          {backendIcon(profile.backend, 20)}
        </span>
        <div className="profile-detail-title">
          <div className="connection-card-name-row">
            <span className="profile-detail-name">{profile.name}</span>
            {managedConfig === true && (
              <span className="badge badge-managed">Managed</span>
            )}
            {profile.useSystemProxy && (
              <span className="badge badge-managed">Proxy</span>
            )}
            {alwaysOnEntry && (
              <span className="badge badge-managed">
                {alwaysOnEntry.enabled
                  ? alwaysOn?.paused
                    ? "Always-on paused"
                    : "Always-on"
                  : "Always-on cleanup pending"}
              </span>
            )}
            {managedConfig === false && (
              <span className="badge badge-external">External</span>
            )}
          </div>
          <span
            className={`profile-detail-meta ${
              status.state === "failed" ? "failed" : ""
            }`}
            title={
              status.state === "failed" && status.message
                ? status.message
                : undefined
            }
          >
            {status.state === "failed"
              ? (status.message ?? "Connection failed")
              : status.state === "running"
                ? `Running on ${status.interfaceName || profile.interfaceName || "tunnel"}`
                : "Stopped"}
          </span>
        </div>
        <ToggleSwitch
          checked={status.state === "running"}
          onChange={() =>
            status.state === "running" ? onDisconnect() : onConnect()
          }
          disabled={isBusy}
          busy={isBusy}
          title={status.state === "running" ? "Disconnect" : "Connect"}
        />
        <OverflowMenu
          title="Profile actions"
          items={[
            { label: "Edit", onClick: onEdit, disabled: isBusy },
            {
              label: "Move up",
              onClick: onMoveUp,
              disabled: isBusy || !canMoveUp,
            },
            {
              label: "Move down",
              onClick: onMoveDown,
              disabled: isBusy || !canMoveDown,
            },
            ...(os === "linux" &&
            alwaysOnKind &&
            (alwaysOnEntry || canEnableAlwaysOn)
              ? [
                  {
                    label: alwaysOnEntry
                      ? "Disable always-on"
                      : "Enable always-on before sign-in",
                    onClick: () =>
                      onToggleAlwaysOn(alwaysOnKind, Boolean(alwaysOnEntry)),
                    disabled: isBusy,
                  },
                ]
              : []),
            ...(os === "linux" && profile.backend === "openVpn"
              ? [
                  {
                    label: "Credentials…",
                    onClick: onCredentials,
                    disabled: isBusy,
                  },
                ]
              : []),
            ...(profile.subscription && endpoints
              ? [
                  {
                    label: refreshingSubscription
                      ? "Refreshing…"
                      : "Refresh subscription",
                    onClick: onRefreshSubscription,
                    disabled:
                      refreshingSubscription ||
                      switching ||
                      isBusy ||
                      status.state === "running",
                  },
                ]
              : []),
            {
              label: diagBusy ? "Running diagnostics…" : "Diagnostics",
              onClick: onDiagnose,
              disabled: isBusy || diagBusy,
            },
            {
              label: "Delete",
              onClick: onDelete,
              disabled: isBusy,
              danger: true,
            },
          ]}
        />
      </div>

      <div className="profile-detail-body">
        <div className="interface-row">
          <span className="row-label">Backend</span>
          <span className="row-value">{backendLabel}</span>
        </div>
        <div className="interface-row">
          <span className="row-label">Interface</span>
          <span className="row-value mono">
            {profile.interfaceName || "Not assigned"}
          </span>
        </div>
        {rate && (
          <div className="interface-row">
            <span className="row-label">Rate</span>
            <span className="row-value">
              <RateText rx={rate.rxRate} tx={rate.txRate} live />
            </span>
          </div>
        )}

        {profile.backend === "xray" &&
          profile.xrayMode === "socks" &&
          profile.xraySocksPort !== null && (
            <div className="interface-row">
              <span className="row-label">SOCKS5</span>
              <span className="row-value mono">
                127.0.0.1:{profile.xraySocksPort}
              </span>
            </div>
          )}
        {profile.backend === "xray" &&
          profile.xrayMode === "socks" &&
          profile.xrayHttpPort !== null && (
            <div className="interface-row">
              <span className="row-label">HTTP CONNECT</span>
              <span className="row-value mono">
                127.0.0.1:{profile.xrayHttpPort}
              </span>
            </div>
          )}
        {profile.subscription && endpoints && (
          <div className="endpoint-section">
            <div className="endpoint-section-head">
              <span className="section-label">
                Endpoints · {endpoints.length}
                {switching && <span className="endpoint-note">switching…</span>}
              </span>
              <button
                type="button"
                className="btn-sm"
                onClick={onMeasureAllEndpoints}
                disabled={
                  measuringAll ||
                  switching ||
                  refreshingSubscription ||
                  isBusy
                }
                title="Measure delay for every endpoint"
              >
                {measuringAll ? "Testing…" : "Test all"}
              </button>
            </div>
            <ul className="endpoint-list">
              {endpoints.map((ep, i) => {
                const res = delayResults?.[i];
                const measuring = measuringEndpoints.has(`${profile.id}:${i}`);
                return (
                  <li key={i}>
                    <button
                      type="button"
                      className={`endpoint-item ${ep.active ? "active" : ""}`}
                      onClick={() => onSwitchEndpoint(i)}
                      disabled={
                        switching ||
                        refreshingSubscription ||
                        isBusy ||
                        status.state === "running" ||
                        ep.active
                      }
                      title={
                        status.state === "running"
                          ? "Disconnect to switch endpoints"
                          : ep.active
                            ? "Active endpoint"
                            : "Switch to this endpoint"
                      }
                    >
                      <span
                        className={`endpoint-item-dot ${ep.active ? "on" : ""}`}
                      />
                      <span className="endpoint-item-name">{ep.name}</span>
                      <span className="endpoint-item-delay">
                        {measuring
                          ? "…"
                          : res
                            ? res.delayMs !== null
                              ? `${res.delayMs} ms`
                              : "unreachable"
                            : "—"}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
        )}
        {profile.subscription && (
          <div className="interface-row">
            <span className="row-label">Auto-refresh</span>
            <span className="row-value">
              <select
                value={profile.subscription.refreshIntervalMinutes ?? ""}
                onChange={(event) =>
                  onSetRefreshInterval(
                    event.target.value ? Number(event.target.value) : null,
                  )
                }
                disabled={settingRefreshInterval || isBusy}
              >
                <option value="">Off</option>
                <option value="15">Every 15 minutes</option>
                <option value="60">Every hour</option>
                <option value="360">Every 6 hours</option>
              </select>
            </span>
          </div>
        )}

        {(detailCount > 0 ||
          profile.subscription !== null ||
          (profile.backend === "xray" && profile.privateLanDirect) ||
          profile.useSystemProxy) && (
          <div className="connection-card-details">
            {profile.subscription?.userInfo && (
              <div className="interface-row">
                <span className="row-label">Traffic</span>
                <span className="row-value">
                  {formatBytes(
                    profile.subscription.userInfo.uploadBytes +
                      profile.subscription.userInfo.downloadBytes,
                  )}{" "}
                  used
                  {profile.subscription.userInfo.totalBytes !== null
                    ? ` / ${formatBytes(profile.subscription.userInfo.totalBytes)}`
                    : " / unlimited"}
                </span>
              </div>
            )}
            {profile.subscription?.userInfo?.expiresAtUnix != null && (
              <div className="interface-row">
                <span className="row-label">Expires</span>
                <span className="row-value">
                  {new Date(
                    profile.subscription.userInfo.expiresAtUnix * 1000,
                  ).toLocaleDateString()}
                </span>
              </div>
            )}
            {profile.subscription &&
              profile.subscription.lastRefreshAtUnix !== null && (
                <div className="interface-row">
                  <span className="row-label">Last checked</span>
                  <span className="row-value">
                    {new Date(
                      profile.subscription.lastRefreshAtUnix * 1000,
                    ).toLocaleString()}
                  </span>
                </div>
              )}
            {profile.subscription?.lastRefreshError && (
              <div className="interface-row">
                <span className="row-label">Refresh</span>
                <span className="row-value">
                  {profile.subscription.lastRefreshError}
                </span>
              </div>
            )}
            {profile.backend === "xray" && profile.privateLanDirect && (
              <div className="interface-row">
                <span className="row-label">Private/LAN IPs</span>
                <span className="row-value">Direct after custom rules</span>
              </div>
            )}
            {profile.useSystemProxy && (
              <div className="interface-row">
                <span className="row-label">Proxy bypass</span>
                <span className="row-value mono">
                  {profile.proxyBypass.join("; ") || "LAN/localhost defaults"}
                </span>
              </div>
            )}
            {ruleCount > 0 && (
              <div className="interface-row">
                <span className="row-label">Domain/IP rules</span>
                <span className="row-value">
                  {(["block", "proxy", "direct"] as const)
                    .map((target) => ({
                      target,
                      count: countPolicyRules(
                        profile.domainPolicies,
                        target,
                      ),
                    }))
                    .filter((entry) => entry.count > 0)
                    .map(
                      (entry) =>
                        `${DOMAIN_TARGET_LABELS[entry.target]} ${entry.count}`,
                    )
                    .join(" · ")}
                </span>
              </div>
            )}
            {profile.routes.length > 0 && (
              <div className="interface-section">
                <span className="section-label">Routes</span>
                <ul className="profile-route-list">
                  {profile.routes.map((route, i) => (
                    <li key={i}>
                      <span className="mono">{route.destination}</span>
                      <span className="family-tag">metric {route.metric}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
