import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Profile } from "../../types";
import { tr, useT } from "../../i18n";
import Modal from "../Modal";
import { useToast } from "../ui/Toast";

interface TunnelRoleSectionProps {
  profile: Profile;
  /** Disabled while the connection is busy or running: a role applies to a fresh start. */
  disabled: boolean;
  onChanged: () => void;
}

/** Whether this connection can be a secondary one: tunnels only, no SOCKS/HTTP proxy mode. */
export function supportsRole(profile: Profile): boolean {
  return (
    profile.backend === "wireGuard" ||
    profile.backend === "openVpn" ||
    (profile.backend === "xray" && profile.xrayMode === "tun")
  );
}

/** Primary takes all traffic; a secondary connection only the networks listed for it. */
export default function TunnelRoleSection({
  profile,
  disabled,
  onChanged,
}: TunnelRoleSectionProps) {
  const t = useT();
  const toast = useToast();
  const [editing, setEditing] = useState(false);
  const [networks, setNetworks] = useState("");
  const [domains, setDomains] = useState("");
  const [busy, setBusy] = useState(false);
  const secondary = profile.tunnelRole === "secondary";
  const listed = profile.tunnelNetworks ?? [];

  useEffect(() => {
    if (editing) {
      setNetworks(listed.join("\n"));
      setDomains((profile.tunnelDnsDomains ?? []).join(" "));
    }
    // Only when the dialog opens: typing must not be overwritten by a refresh.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [editing]);

  const call = async (command: string, args: Record<string, unknown>) => {
    setBusy(true);
    try {
      await invoke(command, args);
      onChanged();
      return true;
    } catch (err) {
      toast("error", tr(String(err)));
      return false;
    } finally {
      setBusy(false);
    }
  };

  const setRole = (role: "primary" | "secondary") => {
    if (role === (secondary ? "secondary" : "primary")) return;
    void call("set_tunnel_role", { id: profile.id, role });
  };

  const save = async () => {
    if (await call("set_tunnel_networks", {
      id: profile.id,
      networks,
      dnsDomains: domains,
    })) {
      setEditing(false);
    }
  };

  return (
    <div className="interface-section">
      <div className="interface-row">
        <span className="row-label">
          {t("native.role")}
          <span className="profile-help">{t("native.roleHint")}</span>
        </span>
        <span className="segmented" role="group">
          {(["primary", "secondary"] as const).map((role) => (
            <button
              key={role}
              type="button"
              className={`btn-sm${(secondary ? "secondary" : "primary") === role ? " btn-primary" : ""}`}
              aria-pressed={(secondary ? "secondary" : "primary") === role}
              disabled={disabled || busy}
              onClick={() => setRole(role)}
            >
              {t(role === "primary" ? "native.rolePrimary" : "native.roleSecondary")}
            </button>
          ))}
        </span>
      </div>
      {secondary && (
        <div className="interface-row">
          <span className="row-label">{t("native.networks")}</span>
          <span className={`row-value mono${listed.length === 0 ? " warn" : ""}`}>
            {listed.length === 0
              ? t("native.networksEmpty")
              : listed.join(", ")}
          </span>
          <button
            type="button"
            className="btn-sm"
            disabled={disabled || busy}
            onClick={() => setEditing(true)}
          >
            {t("native.networksEdit")}
          </button>
        </div>
      )}
      <Modal
        open={editing}
        title={t("native.networksTitle", { name: profile.name })}
        onClose={() => !busy && setEditing(false)}
        maxWidth="460px"
        footer={
          <>
            <button type="button" disabled={busy} onClick={() => setEditing(false)}>
              {t("common.cancel")}
            </button>
            <button
              type="button"
              className="btn-primary"
              disabled={busy}
              onClick={() => void save()}
            >
              {t("common.save")}
            </button>
          </>
        }
      >
        <form
          className="profile-form"
          onSubmit={(event) => {
            event.preventDefault();
            void save();
          }}
        >
          <label>
            {t("native.networks")}
            <textarea
              rows={5}
              spellCheck={false}
              value={networks}
              onChange={(event) => setNetworks(event.target.value)}
              placeholder="10.10.0.0/16"
            />
          </label>
          <span className="profile-help">{t("native.networksHint")}</span>
          <label>
            {t("native.dnsDomains")}
            <input
              type="text"
              spellCheck={false}
              value={domains}
              onChange={(event) => setDomains(event.target.value)}
              placeholder="corp.example"
            />
          </label>
          <span className="profile-help">{t("native.dnsDomainsHint")}</span>
        </form>
      </Modal>
    </div>
  );
}
