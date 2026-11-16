use net_manager_core::models::Profile;
use net_manager_core::profiles::{profile_edit_revision, ProfileStore};
use serde_json::{json, Value};
use std::fs;

fn profile_document() -> Value {
    json!({
        "id": "layered", "name": "Layered", "backend": "xray",
        "configPath": "unused.json", "interfaceName": "",
        "routes": [], "autoConnect": false,
    })
}

#[test]
fn legacy_geo_selectors_become_base_without_losing_explicit_choices() {
    let mut input = profile_document();
    input["domainPolicies"] = json!([
        {"domains": ["geoip:ru", "domain:override.test"], "target": "direct"}
    ]);
    input["pinnedPolicies"] = json!([{
        "selectors": ["geosite:category-dev", "domain:pinned.test"],
        "endpointKey": "1111111111111111", "missing": true,
    }]);
    let profile: Profile = serde_json::from_value(input).unwrap();
    let saved = serde_json::to_value(profile).unwrap();
    assert_eq!(
        saved["routing"]["base"],
        json!([
            {"selectors": ["geosite:category-dev"], "target": {
                "kind": "node", "endpointKey": "1111111111111111", "missing": true
            }},
            {"selectors": ["geoip:ru"], "target": {"kind": "direct"}}
        ])
    );
    assert_eq!(
        saved["routing"]["user"],
        json!([
            {"selectors": ["domain:override.test"], "target": {"kind": "direct"}},
            {"selectors": ["domain:pinned.test"], "target": {
                "kind": "node", "endpointKey": "1111111111111111", "missing": true
            }}
        ])
    );
    for field in [
        "domainPolicies",
        "pinnedPolicies",
        "xrayTrafficRules",
        "xrayInterfaceRoutes",
    ] {
        assert!(
            saved.get(field).is_none(),
            "obsolete field persisted: {field}"
        );
    }
}

#[test]
fn manual_geo_override_and_user_rule_order_survive_round_trip() {
    let mut input = profile_document();
    let routing = json!({
        "base": [{"selectors": ["geoip:ru"], "target": {"kind": "direct"}}],
        "user": [
            {"selectors": ["195.245.249.0/24"], "target": {"kind": "proxy"}},
            {"selectors": ["geoip:ru"], "target": {"kind": "block"}},
            {"selectors": ["domain:override.test"], "target": {"kind": "direct"}}
        ]
    });
    input["routing"] = routing.clone();
    let profile: Profile = serde_json::from_value(input).unwrap();
    assert_eq!(serde_json::to_value(profile).unwrap()["routing"], routing);
}

#[test]
fn mixed_legacy_and_layered_rules_are_rejected_instead_of_shadowed() {
    let mut input = profile_document();
    input["routing"] = json!({"base": [], "user": []});
    input["domainPolicies"] = json!([
        {"domains": ["domain:override.test"], "target": "block"}
    ]);
    assert!(serde_json::from_value::<Profile>(input).is_err());
}

#[test]
fn legacy_store_load_is_read_only_and_cas_persists_canonical_layers() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("profiles.json");
    let store = ProfileStore::new(&path);
    let mut legacy = profile_document();
    legacy["domainPolicies"] = json!([
        {"domains": ["geoip:ru", "domain:first.test"], "target": "direct"},
        {"domains": ["domain:second.test"], "target": "block"}
    ]);
    legacy["pinnedPolicies"] = json!([{
        "selectors": ["geosite:category-dev", "domain:pinned.test"],
        "endpointKey": "1111111111111111", "missing": true
    }]);
    let original = serde_json::to_vec(&json!({"version": 1, "profiles": [legacy]})).unwrap();
    fs::write(&path, &original).unwrap();

    let document = store.load().unwrap();
    assert_eq!(fs::read(&path).unwrap(), original);
    let mut profile = document.profiles[0].clone();
    let revision = profile_edit_revision(&profile).unwrap();
    profile.auto_connect = true;
    store.compare_upsert(profile, Some(&revision)).unwrap();

    let persisted: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(persisted["version"], 2);
    let saved = &persisted["profiles"][0];
    assert_eq!(saved["id"], "layered");
    assert_eq!(saved["name"], "Layered");
    assert_eq!(saved["backend"], "xray");
    assert_eq!(saved["configPath"], "unused.json");
    assert_eq!(saved["autoConnect"], true);
    assert_eq!(
        saved["routing"],
        json!({
            "base": [
                {"selectors": ["geosite:category-dev"], "target": {
                    "kind": "node", "endpointKey": "1111111111111111", "missing": true
                }},
                {"selectors": ["geoip:ru"], "target": {"kind": "direct"}}
            ],
            "user": [
                {"selectors": ["domain:first.test"], "target": {"kind": "direct"}},
                {"selectors": ["domain:second.test"], "target": {"kind": "block"}},
                {"selectors": ["domain:pinned.test"], "target": {
                    "kind": "node", "endpointKey": "1111111111111111", "missing": true
                }}
            ]
        })
    );
    for field in [
        "domainPolicies",
        "pinnedPolicies",
        "xrayTrafficRules",
        "xrayInterfaceRoutes",
    ] {
        assert!(saved.get(field).is_none());
    }
    assert_eq!(
        store.load().unwrap().profiles[0].routing,
        document.profiles[0].routing
    );
}

#[test]
fn manual_geo_user_rows_survive_store_roundtrip_and_stale_cas() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("profiles.json");
    let first = ProfileStore::new(&path);
    let second = ProfileStore::new(&path);
    let mut input = profile_document();
    input["routing"] = json!({
        "base": [{"selectors": ["geoip:ru"], "target": {"kind": "direct"}}],
        "user": [
            {"selectors": ["geoip:ru"], "target": {"kind": "block"}},
            {"selectors": ["domain:first.test"], "target": {"kind": "proxy"}}
        ]
    });
    let profile: Profile = serde_json::from_value(input).unwrap();
    first.compare_upsert(profile, None).unwrap();
    let stale = first.load().unwrap().profiles.remove(0);
    let revision = profile_edit_revision(&stale).unwrap();
    let mut updated = serde_json::to_value(&stale).unwrap();
    updated["routing"]["user"] = json!([
        {"selectors": ["domain:latest.test"], "target": {"kind": "proxy"}},
        {"selectors": ["geoip:ru"], "target": {"kind": "block"}},
        {"selectors": ["domain:first.test"], "target": {"kind": "direct"}}
    ]);
    let expected = updated["routing"].clone();
    second
        .compare_upsert(serde_json::from_value(updated).unwrap(), Some(&revision))
        .unwrap();
    let newest = fs::read(&path).unwrap();
    assert!(first.compare_upsert(stale, Some(&revision)).is_err());
    assert_eq!(fs::read(&path).unwrap(), newest);
    let reloaded = first.load().unwrap();
    assert_eq!(
        serde_json::to_value(&reloaded.profiles[0]).unwrap()["routing"],
        expected
    );
    let persisted: Value = serde_json::from_slice(&newest).unwrap();
    assert_eq!(persisted["profiles"][0]["routing"], expected);
}

#[test]
fn invalid_versions_and_mixed_schema_leave_store_bytes_unchanged() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("profiles.json");
    let store = ProfileStore::new(&path);
    let mut mixed = profile_document();
    mixed["routing"] = json!({"base": [], "user": []});
    mixed["domainPolicies"] = json!([{"domains": ["domain:test.test"], "target": "block"}]);
    for input in [
        json!({"version": 3, "profiles": [profile_document()]}),
        json!({"profiles": [profile_document()]}),
        json!({"version": 1, "profiles": [mixed]}),
    ] {
        let bytes = serde_json::to_vec(&input).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert!(store.load().is_err());
        assert!(store.set_auto_connect("layered", true).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }

    let valid =
        serde_json::to_vec(&json!({"version": 1, "profiles": [profile_document()]})).unwrap();
    fs::write(&path, &valid).unwrap();
    let mut document = store.load().unwrap();
    document.version = 3;
    assert!(store.save(&document).is_err());
    assert_eq!(fs::read(&path).unwrap(), valid);
}
