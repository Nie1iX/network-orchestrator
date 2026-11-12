use super::{object, rejected, string, valid_node_key};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::io;

fn scope_ok(scope: &str) -> bool {
    scope == "proxy"
        || ["node-", "pin-"]
            .iter()
            .any(|prefix| scope.strip_prefix(prefix).is_some_and(valid_node_key))
}

fn scoped<'a>(tag: &'a str, kind: &str) -> Option<&'a str> {
    let rest = tag.strip_prefix("src-")?;
    let (scope, index) = rest.rsplit_once(kind)?;
    (scope_ok(scope)
        && index.len() == 4
        && index
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then_some(scope)
}

fn duration(value: &Value) -> io::Result<()> {
    let text = string(value)?;
    let (number, multiplier) = if let Some(n) = text.strip_suffix("ms") {
        (n, 0.001)
    } else if let Some(n) = text.strip_suffix('s') {
        (n, 1.0)
    } else if let Some(n) = text.strip_suffix('m') {
        (n, 60.0)
    } else if let Some(n) = text.strip_suffix('h') {
        (n, 3600.0)
    } else {
        return Err(rejected());
    };
    let seconds = number.parse::<f64>().map_err(|_| rejected())? * multiplier;
    if seconds.is_finite() && (0.001..=86400.0).contains(&seconds) {
        Ok(())
    } else {
        Err(rejected())
    }
}

fn bounded_number(value: &Value, max: f64) -> io::Result<()> {
    if value
        .as_f64()
        .is_some_and(|n| n.is_finite() && (0.0..=max).contains(&n))
    {
        Ok(())
    } else {
        Err(rejected())
    }
}

fn strategy(value: &Value) -> io::Result<()> {
    let map = object(value, &["type", "settings"])?;
    match string(&value["type"])? {
        "random" | "leastPing" => {
            if let Some(settings) = map.get("settings") {
                object(settings, &[])?;
            }
        }
        "leastLoad" => {
            if let Some(settings) = map.get("settings") {
                let settings = object(
                    settings,
                    &["expected", "baselines", "maxRTT", "tolerance", "costs"],
                )?;
                if let Some(value) = settings.get("expected") {
                    if !value.as_u64().is_some_and(|n| n <= 64) {
                        return Err(rejected());
                    }
                }
                if let Some(value) = settings.get("maxRTT") {
                    duration(value)?;
                }
                if let Some(value) = settings.get("tolerance") {
                    bounded_number(value, 1.0)?;
                }
                if let Some(values) = settings.get("baselines") {
                    let values = values.as_array().ok_or_else(rejected)?;
                    if values.len() > 64 {
                        return Err(rejected());
                    }
                    for value in values {
                        duration(value)?;
                    }
                }
                if let Some(values) = settings.get("costs") {
                    let values = values.as_array().ok_or_else(rejected)?;
                    if values.len() > 64 {
                        return Err(rejected());
                    }
                    for value in values {
                        let cost = object(value, &["regexp", "match", "value"])?;
                        if cost.get("regexp").is_some_and(|v| !v.is_boolean())
                            || string(&value["match"])?.len() > 256
                        {
                            return Err(rejected());
                        }
                        bounded_number(&value["value"], 10000.0)?;
                    }
                }
            }
        }
        _ => return Err(rejected()),
    }
    Ok(())
}

fn observation(value: &Value, burst: bool, outbounds: &HashMap<&str, &Value>) -> io::Result<()> {
    let map = if burst {
        object(value, &["subjectSelector", "pingConfig"])?
    } else {
        object(
            value,
            &[
                "subjectSelector",
                "probeURL",
                "probeInterval",
                "enableConcurrency",
            ],
        )?
    };
    let subjects = map
        .get("subjectSelector")
        .and_then(Value::as_array)
        .ok_or_else(rejected)?;
    if subjects.is_empty() || subjects.len() > 512 {
        return Err(rejected());
    }
    for subject in subjects {
        let tag = string(subject)?;
        if scoped(tag, "-o-").is_none()
            || !outbounds
                .get(tag)
                .is_some_and(|v| matches!(v["protocol"].as_str(), Some("vless" | "hysteria")))
        {
            return Err(rejected());
        }
    }
    if let Some(value) = map.get("probeURL") {
        crate::watchdog::checked_probe_url(string(value)?)?;
    }
    if let Some(value) = map.get("probeInterval") {
        duration(value)?;
    }
    if map
        .get("enableConcurrency")
        .is_some_and(|v| !v.is_boolean())
    {
        return Err(rejected());
    }
    if let Some(ping) = map.get("pingConfig") {
        let ping = object(
            ping,
            &[
                "destination",
                "connectivity",
                "interval",
                "timeout",
                "sampling",
                "httpMethod",
            ],
        )?;
        if ping
            .get("httpMethod")
            .is_some_and(|v| !matches!(v.as_str(), Some("GET" | "HEAD")))
        {
            return Err(rejected());
        }
        for key in ["destination", "connectivity"] {
            if let Some(value) = ping.get(key) {
                crate::watchdog::checked_probe_url(string(value)?)?;
            }
        }
        for key in ["interval", "timeout"] {
            if let Some(value) = ping.get(key) {
                duration(value)?;
            }
        }
        if let Some(value) = ping.get("sampling") {
            if !value.as_u64().is_some_and(|n| (1..=64).contains(&n)) {
                return Err(rejected());
            }
        }
    }
    Ok(())
}

fn visit<'a>(
    tag: &'a str,
    edges: &HashMap<&'a str, Vec<&'a str>>,
    visiting: &mut HashSet<&'a str>,
    done: &mut HashSet<&'a str>,
) -> io::Result<()> {
    if done.contains(tag) {
        return Ok(());
    }
    if !visiting.insert(tag) {
        return Err(rejected());
    }
    if let Some(next) = edges.get(tag) {
        for target in next {
            visit(target, edges, visiting, done)?;
        }
    }
    visiting.remove(tag);
    done.insert(tag);
    Ok(())
}

pub(super) fn validate(config: &Value) -> io::Result<()> {
    if config
        .get("observatory")
        .is_some_and(|value| !value.is_null())
        && config
            .get("burstObservatory")
            .is_some_and(|value| !value.is_null())
    {
        return Err(rejected());
    }
    let values = config["outbounds"].as_array().ok_or_else(rejected)?;
    let outbounds: HashMap<&str, &Value> = values
        .iter()
        .map(|v| Ok((string(&v["tag"])?, v)))
        .collect::<io::Result<_>>()?;
    let mut entries = HashMap::new();
    for (tag, outbound) in &outbounds {
        if tag.starts_with("src-") && scoped(tag, "-o-").is_none() {
            return Err(rejected());
        }
        if (tag.starts_with("node-") || tag.starts_with("pin-"))
            && !matches!(
                outbound["protocol"].as_str(),
                Some("vless" | "hysteria" | "loopback" | "blackhole")
            )
        {
            return Err(rejected());
        }
        if outbound["protocol"] == "loopback" {
            let inbound = string(&outbound["settings"]["inboundTag"])?;
            let scope = if let Some(scope) = scoped(tag, "-o-") {
                let index = tag.rsplit_once("-o-").ok_or_else(rejected)?.1;
                if inbound != format!("src-{scope}-in-{index}") {
                    return Err(rejected());
                }
                scope
            } else {
                let scope = inbound
                    .strip_prefix("src-")
                    .and_then(|s| s.strip_suffix("-in"))
                    .filter(|s| scope_ok(s))
                    .ok_or_else(rejected)?;
                if (*tag != "proxy" && !tag.starts_with("node-") && !tag.starts_with("pin-"))
                    || (scope == "proxy" && tag.starts_with("pin-"))
                    || (scope != "proxy" && *tag != scope)
                {
                    return Err(rejected());
                }
                scope
            };
            if entries.insert(inbound, (scope, *tag)).is_some() {
                return Err(rejected());
            }
        }
    }
    let mut edges: HashMap<&str, Vec<&str>> = HashMap::new();
    for (tag, outbound) in &outbounds {
        let scope = scoped(tag, "-o-");
        for value in [
            outbound.pointer("/streamSettings/sockopt/dialerProxy"),
            outbound.pointer("/proxySettings/tag"),
        ]
        .into_iter()
        .flatten()
        {
            let target = string(value)?;
            if !outbounds.contains_key(target)
                || (scope.is_some() && scoped(target, "-o-") != scope)
                || (scope.is_none() && target.starts_with("src-"))
            {
                return Err(rejected());
            }
            edges.entry(tag).or_default().push(target);
        }
    }
    let mut balancers = HashMap::new();
    if let Some(values) = config["routing"].get("balancers") {
        let values = values.as_array().ok_or_else(rejected)?;
        if values.len() > 512 {
            return Err(rejected());
        }
        for value in values {
            let map = object(value, &["tag", "selector", "strategy", "fallbackTag"])?;
            let tag = string(&value["tag"])?;
            if balancers.insert(tag, value).is_some() {
                return Err(rejected());
            }
            if tag == "failover" {
                if map.len() != 2 || value["selector"] != serde_json::json!(["unavailable"]) {
                    return Err(rejected());
                }
                continue;
            }
            let scope = scoped(tag, "-b-").ok_or_else(rejected)?;
            let selectors = value["selector"].as_array().ok_or_else(rejected)?;
            if selectors.is_empty() || selectors.len() > 512 {
                return Err(rejected());
            }
            for selector in selectors {
                let target = string(selector)?;
                if scoped(target, "-o-") != Some(scope)
                    || !outbounds.get(target).is_some_and(|v| {
                        matches!(v["protocol"].as_str(), Some("vless" | "hysteria"))
                    })
                {
                    return Err(rejected());
                }
                edges.entry(tag).or_default().push(target);
            }
            let target = string(map.get("fallbackTag").ok_or_else(rejected)?)?;
            if scoped(target, "-o-") != Some(scope)
                || !outbounds.get(target).is_some_and(|v| {
                    matches!(
                        v["protocol"].as_str(),
                        Some("vless" | "hysteria" | "blackhole" | "loopback")
                    )
                })
            {
                return Err(rejected());
            }
            edges.entry(tag).or_default().push(target);
            if let Some(value) = map.get("strategy") {
                strategy(value)?;
            }
        }
    }
    let rules = config["routing"]["rules"].as_array().ok_or_else(rejected)?;
    let mut dispatched = HashSet::new();
    let mut seen_other = false;
    for rule in rules {
        let inbound =
            rule["inboundTag"]
                .as_array()
                .and_then(|v| if v.len() == 1 { v[0].as_str() } else { None });
        if let Some((inbound, (scope, entry))) =
            inbound.and_then(|tag| entries.get(tag).map(|entry| (tag, *entry)))
        {
            let map = object(rule, &["type", "inboundTag", "outboundTag", "balancerTag"])?;
            if seen_other
                || !dispatched.insert(inbound)
                || map.get("type").is_some_and(|v| v != "field")
            {
                return Err(rejected());
            }
            let target = if let Some(value) = map.get("outboundTag") {
                if map.contains_key("balancerTag") {
                    return Err(rejected());
                }
                let target = string(value)?;
                if scoped(target, "-o-") != Some(scope)
                    || !outbounds.get(target).is_some_and(|v| {
                        matches!(
                            v["protocol"].as_str(),
                            Some("vless" | "hysteria" | "blackhole")
                        )
                    })
                {
                    return Err(rejected());
                }
                target
            } else {
                let target = string(map.get("balancerTag").ok_or_else(rejected)?)?;
                if scoped(target, "-b-") != Some(scope) || !balancers.contains_key(target) {
                    return Err(rejected());
                }
                target
            };
            edges.entry(entry).or_default().push(target);
        } else {
            seen_other = true;
            if rule["balancerTag"] == "failover" && !balancers.contains_key("failover") {
                return Err(rejected());
            }
            if rule["inboundTag"].as_array().is_some_and(|items| {
                items
                    .iter()
                    .any(|v| v.as_str().is_some_and(|s| s.starts_with("src-")))
            }) || rule["outboundTag"]
                .as_str()
                .is_some_and(|s| s.starts_with("src-"))
                || rule["balancerTag"]
                    .as_str()
                    .is_some_and(|s| s.starts_with("src-"))
            {
                return Err(rejected());
            }
        }
    }
    if entries.len() != dispatched.len() {
        return Err(rejected());
    }
    let mut visited = HashSet::new();
    for tag in outbounds.keys().chain(balancers.keys()) {
        visit(tag, &edges, &mut HashSet::new(), &mut visited)?;
    }
    let mut reachable = HashSet::new();
    for (_, entry) in entries.values() {
        if !entry.starts_with("src-") {
            visit(entry, &edges, &mut HashSet::new(), &mut reachable)?;
        }
    }
    if outbounds
        .keys()
        .any(|tag| tag.starts_with("src-") && !reachable.contains(tag))
        || balancers
            .keys()
            .any(|tag| tag.starts_with("src-") && !reachable.contains(tag))
    {
        return Err(rejected());
    }
    for key in ["observatory", "burstObservatory"] {
        if let Some(value) = config.get(key) {
            observation(value, key == "burstObservatory", &outbounds)?;
        }
    }
    Ok(())
}
