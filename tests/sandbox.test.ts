import assert from "node:assert/strict";
import test from "node:test";
import { SandboxBackend } from "../src/sandbox/backend.ts";
import type { BackendAvailability, Profile, RouteEntry, RouteLookupResult, ServiceCheck, ServiceCheckResult, TunnelStatus } from "../src/types.ts";

import { explainProfileDocument } from "../src/sandbox/routeExplanation.ts";
import type { ProfileDocument } from "../src/profileDocument.ts";

const routeDocument = (profile: ProfileDocument["profile"]): ProfileDocument =>
  ({ version: 1, profile: { backend: "xray", ...profile } });

test("offline explanation matches literal suffix and IP prefix rules", () => {
  const document = routeDocument({
    domainPolicies: [
      { domains: ["domain:example.test"], target: "direct" },
      { domains: ["10.4.0.0/16"], target: "block" },
    ],
  });
  assert.equal(explainProfileDocument(document, "www.example.test").outbound, "direct");
  assert.equal(explainProfileDocument(document, "10.4.2.1").outbound, "block");
  assert.equal(explainProfileDocument(document, "10.5.2.1").source, "default");
});

test("offline explanation leaves a later match probable after unknown earlier selector", () => {
  const result = explainProfileDocument(routeDocument({
    domainPolicies: [
      { domains: ["geosite:not-cached"], target: "block" },
      { domains: ["domain:example.test"], target: "direct" },
    ],
  }), "example.test");
  assert.equal(result.outbound, "direct");
  assert.equal(result.certainty, "probable");
  assert.equal(result.steps[0]?.outcome, "unknown");
});
test("explicit domain policy overrides pinned route selectors", () => {
  const document = routeDocument({
    pinnedPolicies: [{ selectors: ["geosite:category-dev"], endpointKey: "dev" }],
    domainPolicies: [{ domains: ["domain:github.com"], target: "direct" }],
  });
  const exact = explainProfileDocument(document, "github.com");
  assert.equal(exact.outbound, "direct");
  assert.equal(exact.certainty, "certain");
  assert.equal(exact.policyPath, "/profile/domainPolicies/0");

  const suffix = explainProfileDocument(document, "api.github.com");
  assert.equal(suffix.outbound, "direct");
  assert.equal(suffix.certainty, "certain");
  assert.equal(suffix.policyPath, "/profile/domainPolicies/0");

  const other = explainProfileDocument(document, "example.com");
  assert.equal(other.certainty, "probable");
  assert.equal(other.source, "default");
  assert.equal(explainProfileDocument(routeDocument({
    domainPolicies: [{ domains: ["domain:github.com"], target: "direct" }],
  }), "github.com").certainty, "certain");
});

test("offline explanation does not invent Xray routing for other backends", () => {
  assert.throws(() => explainProfileDocument(routeDocument({
    backend: "mihomo",
    domainPolicies: [{ domains: ["domain:example.test"], target: "direct" }],
  }), "example.test"), Error);
});
test("share-link import derives a name and keeps networking unchanged", () => {
  const backend = new SandboxBackend();
  const routes = backend.invoke("get_routes");
  const statuses = backend.invoke("get_tunnel_statuses");
  const result = backend.invoke("import_share_link", {
    link: "  vless://synthetic-private-id@node.test:443?security=tls#Lab%20Node  ", name: "",
  }) as { profiles: Profile[] };
  const imported = result.profiles.at(-1)!;
  assert.equal(imported.name, "Lab Node");
  assert.equal(imported.backend, "xray");
  assert.equal(imported.autoConnect, false);
  assert.equal(imported.useSystemProxy, false);
  assert.equal(imported.subscription, null);
  assert.deepEqual(backend.invoke("get_routes"), routes);
  assert.deepEqual(backend.invoke("get_tunnel_statuses").filter((s: TunnelStatus) => s.profileId !== imported.id), statuses);
  assert.equal(JSON.stringify(result).includes("synthetic-private-id"), false);
  assert.throws(() => backend.invoke("import_share_link", { link: "https://node.test/private-token" }), /unsupported share link/);
});

test("dialog confirmations and always-on use the same IPC contract as Tauri", () => {
  const backend = new SandboxBackend();
  assert.equal(backend.invoke("plugin:dialog|message", { buttons: "OkCancel" }), "Ok");
  assert.equal(backend.invoke("plugin:dialog|message", { buttons: "YesNo" }), "Yes");
  assert.equal(backend.invoke("plugin:dialog|message", { buttons: { OkCancelCustom: ["Proceed", "Cancel"] } }), "Proceed");
  backend.invoke("set_always_on_profile", { id: "wg" });
  backend.invoke("remove_always_on_profile", { kind: "wireGuard", profileId: "wg" });
  assert.deepEqual(backend.invoke("get_always_on_profiles"), { profiles: [], paused: false, supportedKinds: ["wireGuard", "staticRoutes"] });
});

test("imported proxy profiles receive distinct synthetic listener ports", () => {
  const backend = new SandboxBackend();
  backend.invoke("import_subscription");
  const profiles = backend.invoke("get_profiles") as Profile[];
  const ports = profiles.filter((p) => p.backend === "xray").flatMap((p) => [p.xraySocksPort, p.xrayHttpPort]);
  assert.equal(new Set(ports).size, ports.length);
});

test("connecting and disconnecting changes only synthetic routes, with longest-prefix lookup", () => {
  const backend = new SandboxBackend();
  const before = backend.invoke("get_routes") as RouteEntry[];
  backend.invoke("connect_profile", { id: "wg" });
  assert.equal((backend.invoke("get_routes") as RouteEntry[]).length, before.length + 1);
  const lookup = backend.invoke("lookup_destination", { dest: "10.77.0.9" }) as RouteLookupResult;
  assert.equal(lookup.interfaceName, "wg-home");
  backend.invoke("disconnect_profile", { id: "wg" });
  assert.deepEqual(backend.invoke("get_routes"), before);
});

test("destructive or unknown native commands fail closed", () => {
  const backend = new SandboxBackend();
  for (const command of ["set_interface_state", "restart_elevated", "plugin:process|restart", "not_a_command"]) {
    assert.throws(() => backend.invoke(command), /disabled in sandbox/);
  }
});

test("managed Xray install toggles the managed backend without touching the host", () => {
  const backend = new SandboxBackend();
  const missing = (backend.invoke("get_backend_availability") as BackendAvailability[]).find((b) => b.backend === "xray");
  assert.equal(missing?.available, false);
  const path = backend.invoke("install_managed_xray") as string;
  assert.match(path, /xray$/);
  const installed = (backend.invoke("get_backend_availability") as BackendAvailability[]).find((b) => b.backend === "xray");
  assert.equal(installed?.source, "managed");
  assert.equal(installed?.available, true);
  backend.invoke("remove_managed_xray");
  const removed = (backend.invoke("get_backend_availability") as BackendAvailability[]).find((b) => b.backend === "xray");
  assert.equal(removed?.source, null);
});

test("synthetic Mihomo profile exposes native groups and changes only sandbox state", () => {
  const backend = new SandboxBackend();
  const profile = (backend.invoke("get_profiles") as Profile[]).find((item) => item.id === "mihomo")!;
  assert.equal(profile.backend, "mihomo");
  assert.equal(profile.mihomo?.entryGroup, "Auto");
  const groups = backend.invoke("get_mihomo_groups", { id: profile.id }) as { name: string; members: string[] }[];
  assert.ok(groups.some((group) => group.name === "Auto" && group.members.includes("Netherlands")));
  backend.invoke("connect_profile", { id: profile.id });
  assert.equal((backend.invoke("get_tunnel_statuses") as TunnelStatus[]).find((item) => item.profileId === profile.id)?.state, "running");
  backend.invoke("disconnect_profile", { id: profile.id });
  assert.equal((backend.invoke("get_tunnel_statuses") as TunnelStatus[]).find((item) => item.profileId === profile.id)?.state, "stopped");
});

test("saving a synthetic Mihomo document retains backend and selected options", () => {
  const backend = new SandboxBackend();
  const edit = backend.invoke("get_profile_for_edit", { id: "mihomo" }) as { profile: Profile; revision: string };
  const updated = backend.invoke("save_mihomo_document", {
    profile: { ...edit.profile, mihomo: { ...edit.profile.mihomo!, entryGroup: "Auto" } },
    expectedRevision: edit.revision,
    document: "proxies: []\nproxy-groups: []",
  }) as Profile[];
  assert.equal(updated.find((item) => item.id === "mihomo")?.mihomo?.entryGroup, "Auto");
});

test("synthetic Mihomo component is optional and explicitly installed", () => {
  const backend = new SandboxBackend();
  const availability = () => (backend.invoke("get_backend_availability") as BackendAvailability[]).find((item) => item.backend === "mihomo");
  assert.equal(availability()?.available, false);
  backend.invoke("install_managed_mihomo");
  assert.equal(availability()?.source, "managed");
  backend.invoke("remove_managed_mihomo");
  assert.equal(availability()?.available, false);
});

test("profile responses cannot mutate stored fixtures; active profiles cannot be deleted", () => {
  const backend = new SandboxBackend();
  const profiles = backend.invoke("get_profiles") as Profile[];
  profiles[0].name = "Changed outside backend";
  assert.equal((backend.invoke("get_profiles") as Profile[])[0].name, "QA WireGuard");
  backend.invoke("connect_profile", { id: "wg" });
  assert.throws(() => backend.invoke("delete_profile", { id: "wg" }), /Disconnect/);
  assert.throws(() => backend.invoke("connect_profile", { id: "wg" }), /already running/);
});

test("OpenVPN credential flow is simulated without launching a process", () => {
  const backend = new SandboxBackend();
  assert.throws(() => backend.invoke("connect_profile", { id: "ovpn" }));
  assert.throws(() => backend.invoke("connect_openvpn_with_credentials", { id: "ovpn", username: "qa", password: "synthetic" }));
  assert.equal((backend.invoke("get_tunnel_statuses") as TunnelStatus[]).find((s) => s.profileId === "ovpn")!.state, "stopped");
  const status = backend.invoke("connect_openvpn_with_credentials", {
    id: "ovpn", credentials: { authUserPass: { username: "qa", password: "synthetic" } }, remember: false,
  }) as TunnelStatus;
  assert.equal(status.state, "running");
  assert.equal((backend.invoke("get_tunnel_statuses") as TunnelStatus[]).find((s) => s.profileId === "ovpn")!.state, "running");
  backend.invoke("disconnect_profile", { id: "ovpn" });
  assert.throws(() => backend.invoke("connect_profile", { id: "ovpn" }));
});

test("service results cannot be attributed to a URL changed during a manual check", async () => {
  const backend = new SandboxBackend();
  const p = (backend.invoke("get_profiles") as Profile[]).find((p) => p.subscription)!;
  const check: ServiceCheck = {
    id: "service-race", name: "Synthetic service", url: "https://service.example/first",
    endpointKey: p.pinnedPolicies![0].endpointKey, background: false,
  };
  backend.invoke("set_xray_service_checks", { profileId: p.id, checks: [check] });
  const initial = await backend.invoke("run_xray_service_checks", { profileId: p.id }) as ServiceCheckResult[];
  assert.equal(initial[0].outcome, "http");

  const pending = backend.invoke("run_xray_service_checks", { profileId: p.id }) as Promise<ServiceCheckResult[]>;
  backend.invoke("set_xray_service_checks", {
    profileId: p.id, checks: [{ ...check, url: "https://service.example/changed" }],
  });
  await assert.rejects(pending);
});

test("a stale ordinary profile edit rejects newer dedicated service settings", () => {
  const backend = new SandboxBackend();
  const { profile: stale, revision } = backend.invoke("get_profile_for_edit", { id: "xray" }) as { profile: Profile; revision: string };
  const check: ServiceCheck = {
    id: "service-preserved", name: "Synthetic service", url: "https://service.example/health",
    endpointKey: stale.pinnedPolicies![0].endpointKey, background: false,
  };
  backend.invoke("set_xray_service_checks", { profileId: stale.id, checks: [check] });
  stale.name = "Edited ordinary name";
  assert.throws(() => backend.invoke("save_profile", { profile: stale, expectedRevision: revision }), /profile changed/);
  const saved = (backend.invoke("get_profiles") as Profile[]).find((p) => p.id === stale.id)!;
  assert.notEqual(saved.name, "Edited ordinary name");
  assert.deepEqual(saved.xrayServiceChecks, [check]);
});
