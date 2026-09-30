import { backendIcon } from "../../icons";
import { formatBytes } from "../../format";
import { useT } from "../../i18n";
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

export const DOMAIN_TARGET_LABEL_KEYS: Record<
  DomainRouteTarget,
  "rules.block" | "rules.proxy" | "rules.direct"
> = {
  block: "rules.block",
  proxy: "rules.proxy",
  direct: "rules.direct",
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
  const t = useT();
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
              <span className="badge badge-managed">{t("detail.managed")}</span>
            )}
            {profile.useSystemProxy && (
              <span className="badge badge-managed">{t("detail.proxy")}</span>
            )}
            {alwaysOnEntry && (
              <span className="badge badge-managed">
                {alwaysOnEntry.enabled
                  ? alwaysOn?.paused
                    ? t("detail.alwaysOnPaused")
                    : t("detail.alwaysOn")
                  : t("detail.alwaysOnPending")}
              </span>
            )}
            {managedConfig === false && (
              <span className="badge badge-external">{t("detail.external")}</span>
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
              ? (status.message ?? t("detail.failed"))
              : status.state === "running"
                ? t("detail.runningOn", {
                    iface:
                      status.interfaceName || profile.interfaceName || "tunnel",
                  })
                : t("detail.stopped")}
          </span>
        </div>
        <ToggleSwitch
          checked={status.state === "running"}
          onChange={() =>
            status.state === "running" ? onDisconnect() : onConnect()
          }
          disabled={isBusy}
          busy={isBusy}
          title={status.state === "running" ? t("common.disconnect") : t("common.connect")}
        />
        <OverflowMenu
          title={t("detail.actions")}
          items={[
            { label: t("common.edit"), onClick: onEdit, disabled: isBusy },
            {
              label: t("detail.moveUp"),
              onClick: onMoveUp,
              disabled: isBusy || !canMoveUp,
            },
            {
              label: t("detail.moveDown"),
              onClick: onMoveDown,
              disabled: isBusy || !canMoveDown,
            },
            ...(os === "linux" &&
            alwaysOnKind &&
            (alwaysOnEntry || canEnableAlwaysOn)
              ? [
                  {
                    label: alwaysOnEntry
                      ? t("detail.disableAlwaysOn")
                      : t("detail.enableAlwaysOn"),
                    onClick: () =>
                      onToggleAlwaysOn(alwaysOnKind, Boolean(alwaysOnEntry)),
                    disabled: isBusy,
                  },
                ]
              : []),
            ...(os === "linux" && profile.backend === "openVpn"
              ? [
                  {
                    label: t("detail.credentials"),
                    onClick: onCredentials,
                    disabled: isBusy,
                  },
                ]
              : []),
            ...(profile.subscription && endpoints
              ? [
                  {
                    label: refreshingSubscription
                      ? t("detail.refreshing")
                      : t("detail.refreshSub"),
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
              label: diagBusy ? t("detail.runningDiag") : t("detail.diagnostics"),
              onClick: onDiagnose,
              disabled: isBusy || diagBusy,
            },
            {
              label: t("common.delete"),
              onClick: onDelete,
              disabled: isBusy,
              danger: true,
            },
          ]}
        />
      </div>

      <div className="profile-detail-body">
        <div className="interface-row">
          <span className="row-label">{t("detail.backend")}</span>
          <span className="row-value">{backendLabel}</span>
        </div>
        <div className="interface-row">
          <span className="row-label">{t("detail.interface")}</span>
          <span className="row-value mono">
            {profile.interfaceName || t("detail.notAssigned")}
          </span>
        </div>
        {rate && (
          <div className="interface-row">
            <span className="row-label">{t("detail.rate")}</span>
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
                {t("detail.endpoints")} · {endpoints.length}
                {switching && <span className="endpoint-note">{t("detail.switching")}</span>}
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
                title={t("detail.testAllTitle")}
              >
                {measuringAll ? t("profiles.testing") : t("detail.testAll")}
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
                          ? t("detail.disconnectToSwitch")
                          : ep.active
                            ? t("detail.activeEndpoint")
                            : t("detail.switchEndpoint")
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
                              : t("detail.unreachable")
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
            <span className="row-label">{t("detail.autoRefresh")}</span>
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
                <option value="">{t("common.off")}</option>
                <option value="15">{t("detail.every15")}</option>
                <option value="60">{t("detail.everyHour")}</option>
                <option value="360">{t("detail.every6h")}</option>
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
                <span className="row-label">{t("detail.traffic")}</span>
                <span className="row-value">
                  {formatBytes(
                    profile.subscription.userInfo.uploadBytes +
                      profile.subscription.userInfo.downloadBytes,
                  )}{" "}
                  {t("detail.used")}
                  {profile.subscription.userInfo.totalBytes !== null
                    ? ` / ${formatBytes(profile.subscription.userInfo.totalBytes)}`
                    : ` / ${t("detail.unlimited")}`}
                </span>
              </div>
            )}
            {profile.subscription?.userInfo?.expiresAtUnix != null && (
              <div className="interface-row">
                <span className="row-label">{t("detail.expires")}</span>
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
                  <span className="row-label">{t("detail.lastChecked")}</span>
                  <span className="row-value">
                    {new Date(
                      profile.subscription.lastRefreshAtUnix * 1000,
                    ).toLocaleString()}
                  </span>
                </div>
              )}
            {profile.subscription?.lastRefreshError && (
              <div className="interface-row">
                <span className="row-label">{t("detail.refreshLabel")}</span>
                <span className="row-value">
                  {profile.subscription.lastRefreshError}
                </span>
              </div>
            )}
            {profile.backend === "xray" && profile.privateLanDirect && (
              <div className="interface-row">
                <span className="row-label">{t("detail.privateLan")}</span>
                <span className="row-value">{t("detail.privateLanValue")}</span>
              </div>
            )}
            {profile.useSystemProxy && (
              <div className="interface-row">
                <span className="row-label">{t("detail.proxyBypass")}</span>
                <span className="row-value mono">
                  {profile.proxyBypass.join("; ") || t("detail.bypassDefault")}
                </span>
              </div>
            )}
            {ruleCount > 0 && (
              <div className="interface-row">
                <span className="row-label">{t("detail.domainRules")}</span>
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
                        `${t(DOMAIN_TARGET_LABEL_KEYS[entry.target])} ${entry.count}`,
                    )
                    .join(" · ")}
                </span>
              </div>
            )}
            {profile.routes.length > 0 && (
              <div className="interface-section">
                <span className="section-label">{t("detail.routes")}</span>
                <ul className="profile-route-list">
                  {profile.routes.map((route, i) => (
                    <li key={i}>
                      <span className="mono">{route.destination}</span>
                      <span className="family-tag">{t("detail.metric", { n: route.metric })}</span>
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
