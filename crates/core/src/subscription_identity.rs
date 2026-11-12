use crate::config_vault::{SubscriptionEndpoint, SubscriptionIdentity, SubscriptionSidecar};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    io,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn name_hash(name: &str) -> String {
    digest(name.trim().as_bytes())
}

fn scrub(value: &mut serde_json::Value, in_users: bool) {
    match value {
        serde_json::Value::Object(map) => {
            map.retain(|key, _| {
                !matches!(
                    key.as_str(),
                    "remarks" | "password" | "username" | "email" | "auth" | "uuid"
                ) && !(in_users && key == "id")
            });
            for (key, value) in map.iter_mut() {
                scrub(value, in_users || key == "users");
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                scrub(item, in_users);
            }
        }
        _ => {}
    }
}

fn fingerprint(url: &str) -> io::Result<String> {
    let mut config = crate::xray::generate_share_link_config(url, 1)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid subscription endpoint"))?;
    if let Some(object) = config.as_object_mut() {
        object.remove("inbounds");
        object.remove("log");
    }
    scrub(&mut config, false);
    let bytes = serde_json::to_vec(&config)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid subscription endpoint"))?;
    Ok(digest(&bytes))
}

fn fresh_id(used: &HashSet<String>) -> String {
    use std::fmt::Write as _;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let mut hasher = Sha256::new();
        hasher.update(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_le_bytes(),
        );
        hasher.update(std::process::id().to_le_bytes());
        hasher.update(NEXT.fetch_add(1, Ordering::Relaxed).to_le_bytes());
        let digest = hasher.finalize();
        let mut id = String::with_capacity(16);
        for byte in &digest[..8] {
            write!(id, "{byte:02x}").expect("writing to a String cannot fail");
        }
        if !used.contains(&id) {
            return id;
        }
    }
}

pub(crate) fn validate_catalog(sidecar: &SubscriptionSidecar) -> io::Result<()> {
    if sidecar.version > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported subscription sidecar version",
        ));
    }
    let mut ids = HashSet::new();
    for endpoint in &sidecar.endpoints {
        if sidecar.version == 0 {
            if endpoint.id.is_empty() {
                continue;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid legacy subscription identities",
            ));
        }
        if !crate::subscription::valid_endpoint_key(&endpoint.id) || !ids.insert(&endpoint.id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid subscription endpoint identities",
            ));
        }
    }
    let mut history = HashSet::new();
    for entry in &sidecar.history {
        if !crate::subscription::valid_endpoint_key(&entry.id)
            || !history.insert(&entry.id)
            || ![&entry.name_hash, &entry.fingerprint].iter().all(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid subscription identity history",
            ));
        }
    }
    if (sidecar.version == 0 && (!sidecar.history.is_empty() || sidecar.migration_pending))
        || (sidecar.version == 1 && ids.iter().any(|id| !history.contains(id)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid subscription identity history",
        ));
    }
    Ok(())
}

pub(crate) fn reconcile_catalog(
    previous: Option<&SubscriptionSidecar>,
    incoming: &[SubscriptionEndpoint],
) -> io::Result<SubscriptionSidecar> {
    reconcile_catalog_reserved(previous, incoming, &HashSet::new())
}

pub(crate) fn reconcile_catalog_reserved(
    previous: Option<&SubscriptionSidecar>,
    incoming: &[SubscriptionEndpoint],
    reserved: &HashSet<String>,
) -> io::Result<SubscriptionSidecar> {
    if let Some(previous) = previous {
        validate_catalog(previous)?;
    }
    let mut history = previous.map(|p| p.history.clone()).unwrap_or_default();
    if let Some(previous) = previous {
        for endpoint in &previous.endpoints {
            if !endpoint.id.is_empty() && !history.iter().any(|h| h.id == endpoint.id) {
                history.push(SubscriptionIdentity {
                    id: endpoint.id.clone(),
                    name_hash: name_hash(&endpoint.name),
                    fingerprint: fingerprint(&endpoint.url)?,
                });
            }
        }
    }
    let names: Vec<_> = incoming.iter().map(|e| name_hash(&e.name)).collect();
    let fingerprints: Vec<_> = incoming
        .iter()
        .map(|endpoint| {
            fingerprint(&endpoint.url).or_else(|error| {
                history
                    .iter()
                    .find(|entry| entry.id == endpoint.id)
                    .map(|entry| entry.fingerprint.clone())
                    .ok_or(error)
            })
        })
        .collect::<io::Result<_>>()?;
    let mut used: HashSet<String> = history.iter().map(|h| h.id.clone()).collect();
    used.extend(reserved.iter().cloned());
    let mut assigned = HashSet::new();
    let mut ids = vec![None; incoming.len()];
    for (index, endpoint) in incoming.iter().enumerate() {
        if !endpoint.id.is_empty() {
            if !crate::subscription::valid_endpoint_key(&endpoint.id)
                || !assigned.insert(endpoint.id.clone())
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid subscription endpoint identities",
                ));
            }
            used.insert(endpoint.id.clone());
            ids[index] = Some(endpoint.id.clone());
        }
    }
    for index in 0..incoming.len() {
        if ids[index].is_some() {
            continue;
        }
        if names.iter().filter(|n| *n == &names[index]).count() != 1 {
            continue;
        }
        let matches: Vec<_> = history
            .iter()
            .filter(|h| h.name_hash == names[index])
            .collect();
        if matches.len() == 1 && assigned.insert(matches[0].id.clone()) {
            ids[index] = Some(matches[0].id.clone());
        }
    }
    for index in 0..incoming.len() {
        if ids[index].is_some() {
            continue;
        }
        if fingerprints
            .iter()
            .filter(|f| *f == &fingerprints[index])
            .count()
            != 1
        {
            continue;
        }
        let matches: Vec<_> = history
            .iter()
            .filter(|h| h.fingerprint == fingerprints[index])
            .collect();
        if matches.len() == 1 && assigned.insert(matches[0].id.clone()) {
            ids[index] = Some(matches[0].id.clone());
        }
    }
    let mut endpoints = incoming.to_vec();
    for (index, endpoint) in endpoints.iter_mut().enumerate() {
        let id = ids[index].clone().unwrap_or_else(|| fresh_id(&used));
        used.insert(id.clone());
        endpoint.id = id.clone();
        let entry = SubscriptionIdentity {
            id: id.clone(),
            name_hash: names[index].clone(),
            fingerprint: fingerprints[index].clone(),
        };
        if let Some(old) = history.iter_mut().find(|h| h.id == id) {
            *old = entry;
        } else {
            history.push(entry);
        }
    }
    Ok(SubscriptionSidecar {
        version: 1,
        endpoints,
        history,
        migration_pending: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, host: &str, secret: &str) -> SubscriptionEndpoint {
        SubscriptionEndpoint {
            id: String::new(),
            name: name.into(),
            url: format!("vless://{secret}@{host}:443?security=tls#{name}"),
        }
    }

    #[test]
    fn unique_names_and_fingerprints_survive_reorder_rename_and_reappearance() {
        let old = reconcile_catalog(
            None,
            &[
                node("One", "one.test", "secret-one"),
                node("Two", "two.test", "secret-two"),
            ],
        )
        .unwrap();
        let next = reconcile_catalog(
            Some(&old),
            &[
                node("Two renamed", "two.test", "rotated"),
                node("One", "changed.test", "rotated"),
            ],
        )
        .unwrap();
        assert_eq!(next.endpoints[0].id, old.endpoints[1].id);
        assert_eq!(next.endpoints[1].id, old.endpoints[0].id);
        let absent =
            reconcile_catalog(Some(&next), &[node("One", "changed.test", "rotated")]).unwrap();
        let returned = reconcile_catalog(
            Some(&absent),
            &[
                node("Two renamed", "else.test", "rotated"),
                node("One", "changed.test", "rotated"),
            ],
        )
        .unwrap();
        assert_eq!(returned.endpoints[0].id, old.endpoints[1].id);
        let history = serde_json::to_string(&returned.history).unwrap();
        assert!(!history.contains("secret-one") && !history.contains("rotated"));
    }

    #[test]
    fn full_config_fingerprint_ignores_credentials_and_name_but_keeps_routing() {
        let entry = |name: &str, secret: &str, domain: &str| {
            crate::xray::xray_json_entry(&serde_json::json!({
                "remarks": name,
                "outbounds": [{"tag":"proxy","protocol":"vless","settings":{"vnext":[
                    {"address":"same.test","port":443,"users":[{"id":secret}]}
                ]}}],
                "routing":{"rules":[{"type":"field","domain":[domain],"outboundTag":"proxy"}]}
            }))
            .unwrap()
        };
        let original = fingerprint(&entry("Auto", "secret", "geosite:uk")).unwrap();
        assert_eq!(
            original,
            fingerprint(&entry("Renamed", "rotated", "geosite:uk")).unwrap()
        );
        assert_ne!(
            original,
            fingerprint(&entry("UK", "secret", "geosite:de")).unwrap()
        );
    }

    #[test]
    fn duplicate_names_do_not_guess_when_fingerprints_are_ambiguous() {
        let old = reconcile_catalog(
            None,
            &[node("Same", "one.test", "a"), node("Same", "two.test", "b")],
        )
        .unwrap();
        let next = reconcile_catalog(
            Some(&old),
            &[
                node("Same", "changed.test", "c"),
                node("Same", "changed.test", "d"),
            ],
        )
        .unwrap();
        for endpoint in &next.endpoints {
            assert!(old
                .endpoints
                .iter()
                .all(|previous| previous.id != endpoint.id));
        }
    }

    #[test]
    fn malformed_duplicate_stored_ids_are_rejected() {
        let mut old = reconcile_catalog(
            None,
            &[node("One", "one.test", "a"), node("Two", "two.test", "b")],
        )
        .unwrap();
        old.endpoints[1].id = old.endpoints[0].id.clone();
        assert_eq!(
            crate::subscription::key_index(&old.endpoints, &old.endpoints[0].id),
            None
        );
        assert!(validate_catalog(&old).is_err());
        assert!(reconcile_catalog(Some(&old), &[node("One", "one.test", "a")]).is_err());
    }
}
