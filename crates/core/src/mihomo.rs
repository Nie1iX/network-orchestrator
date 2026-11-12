use crate::models::{DomainRouteTarget, MihomoMode, MihomoProfileOptions, Profile};
use serde::Serialize;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::io;

#[path = "mihomo_yaml.rs"]
mod yaml;

pub const MAX_CONFIG_BYTES: usize = 8 * 1024 * 1024;
const MAX_YAML_NODES: usize = 100_000;
const MAX_YAML_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MihomoGroupInfo {
    pub name: String,
    pub kind: String,
    pub members: Vec<String>,
    pub selected: Option<String>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn parse_config(bytes: &[u8]) -> io::Result<Value> {
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(invalid("Mihomo configuration exceeds the 8 MiB limit"));
    }
    let yaml = yaml::parse(bytes)?;
    let yaml = resolve_yaml_merges(yaml, 0, &mut 0)?;
    let value = serde_json::to_value(yaml)
        .map_err(|_| invalid("Mihomo configuration contains unsupported YAML values"))?;
    validate_source(&value)?;
    Ok(value)
}

fn resolve_yaml_merges(
    value: serde_yaml::Value,
    depth: usize,
    nodes: &mut usize,
) -> io::Result<serde_yaml::Value> {
    use serde_yaml::Value as Yaml;
    *nodes += 1;
    if *nodes > MAX_YAML_NODES || depth > MAX_YAML_DEPTH {
        return Err(invalid("Mihomo YAML exceeds nesting or expansion limits"));
    }
    match value {
        Yaml::Mapping(mut map) => {
            let merge_key = Yaml::String("<<".into());
            let merge = map.remove(&merge_key);
            let mut resolved = serde_yaml::Mapping::new();
            if let Some(merge) = merge {
                let sources = match merge {
                    Yaml::Mapping(map) => vec![Yaml::Mapping(map)],
                    Yaml::Sequence(values) => values,
                    _ => return Err(invalid("Invalid YAML merge value")),
                };
                for source in sources {
                    let Yaml::Mapping(source) = resolve_yaml_merges(source, depth + 1, nodes)?
                    else {
                        return Err(invalid("YAML merge source must be a mapping"));
                    };
                    for (key, value) in source {
                        resolved.entry(key).or_insert(value);
                    }
                }
            }
            for (key, value) in map {
                resolved.insert(key, resolve_yaml_merges(value, depth + 1, nodes)?);
            }
            Ok(Yaml::Mapping(resolved))
        }
        Yaml::Sequence(values) => values
            .into_iter()
            .map(|value| resolve_yaml_merges(value, depth + 1, nodes))
            .collect::<io::Result<Vec<_>>>()
            .map(Yaml::Sequence),
        Yaml::Tagged(_) => Err(invalid("Tagged YAML values are unsupported")),
        value => Ok(value),
    }
}

fn validate_source(source: &Value) -> io::Result<()> {
    prepare_source(source).map(|_| ())
}

fn prepare_source(source: &Value) -> io::Result<Value> {
    let root = source
        .as_object()
        .ok_or_else(|| invalid("Mihomo configuration must be an object"))?;
    if root.get("x-netorch-source").is_some_and(|metadata| {
        !metadata
            .get("proxy-providers")
            .is_some_and(Value::is_object)
    }) {
        return Err(invalid("Invalid protected Mihomo source metadata"));
    }
    let mut safe = source.clone();
    let root = safe.as_object_mut().expect("object checked above");
    root.retain(|key, _| !key.starts_with("x-"));
    for key in [
        "allow-lan",
        "bind-address",
        "tun",
        "profile",
        "mixed-port",
        "port",
        "socks-port",
        "redir-port",
        "tproxy-port",
        "listeners",
        "authentication",
        "secret",
        "external-controller",
        "external-controller-unix",
        "external-controller-tls",
        "external-controller-pipe",
        "external-controller-cors",
        "external-ui",
        "external-ui-url",
        "external-ui-name",
        "routing-mark",
        "geodata-loader",
        "geo-auto-update",
    ] {
        root.remove(key);
    }
    root.insert("mode".into(), Value::String("rule".into()));
    if let Some(dns) = root.get_mut("dns").and_then(Value::as_object_mut) {
        dns.remove("listen");
    }
    rewrite_provider_paths(&mut safe)?;
    materialize_inline_overrides(&mut safe)?;
    validate_config_inner(&safe, true)?;
    Ok(safe)
}

pub fn compile_config(source: &Value, profile: &Profile) -> io::Result<Value> {
    if profile.backend != crate::models::TunnelBackend::Mihomo {
        return Err(invalid("Mihomo configuration requires a Mihomo profile"));
    }
    validate_profile_options(profile)?;
    let mut compiled = prepare_source(source)?;
    let default_options = MihomoProfileOptions::default();
    let options = profile.mihomo.as_ref().unwrap_or(&default_options);
    if options.mode == MihomoMode::Proxy && options.mixed_port.is_none() {
        return Err(invalid("Mihomo proxy mode requires a mixed port"));
    }
    if options.group_selections.len() > 64 {
        return Err(invalid(
            "A Mihomo profile supports at most 64 explicit group selections",
        ));
    }
    let groups = group_info_inner(&compiled, options)?;
    let by_name = groups
        .iter()
        .map(|group| (group.name.as_str(), group))
        .collect::<BTreeMap<_, _>>();
    for (name, member) in &options.group_selections {
        let group = by_name
            .get(name.as_str())
            .ok_or_else(|| invalid("Selected Mihomo group no longer exists"))?;
        if group.kind != "select" {
            return Err(invalid("Explicit Mihomo selection requires a select group"));
        }
        if !group.members.contains(member) {
            return Err(invalid("Selected Mihomo group member no longer exists"));
        }
    }
    if options
        .entry_group
        .as_deref()
        .is_some_and(|name| !by_name.contains_key(name))
    {
        return Err(invalid("Selected Mihomo entry group does not exist"));
    }
    if let Some(entry_group) = options.entry_group.as_deref() {
        let mut matched = false;
        if let Some(rules) = compiled["rules"].as_array_mut() {
            for rule in rules.iter_mut() {
                if rule
                    .as_str()
                    .is_some_and(|value| value.starts_with("MATCH,"))
                {
                    *rule = Value::String(format!("MATCH,{entry_group}"));
                    matched = true;
                }
            }
            if !matched {
                rules.push(Value::String(format!("MATCH,{entry_group}")));
            }
        }
    }
    let default_target = compiled["rules"]
        .as_array()
        .and_then(|rules| {
            rules
                .iter()
                .rev()
                .filter_map(Value::as_str)
                .find_map(|rule| {
                    rule.strip_prefix("MATCH,")
                        .and_then(|target| target.split(',').next())
                })
        })
        .map(str::to_owned)
        .or_else(|| options.entry_group.clone());
    let mut policy_rules = Vec::new();
    for policy in &profile.domain_policies {
        let target = match policy.target {
            DomainRouteTarget::Direct => "DIRECT",
            DomainRouteTarget::Block => "REJECT",
            DomainRouteTarget::Proxy => default_target
                .as_deref()
                .filter(|target| !RESERVED_PROXY_NAMES.contains(target))
                .ok_or_else(|| {
                    invalid(
                        "Proxy domain policy requires a native proxy target or Mihomo entry group",
                    )
                })?,
        };
        for selector in &policy.domains {
            if let Some(selector) = mihomo_selector(selector)? {
                policy_rules.push(format!("{selector},{target}"));
            }
        }
    }
    if !policy_rules.is_empty() || profile.private_lan_direct {
        policy_rules.extend(
            [
                "IP-CIDR,224.0.0.0/4,REJECT,no-resolve",
                "IP-CIDR6,ff00::/8,REJECT,no-resolve",
            ]
            .map(str::to_owned),
        );
    }
    if profile.private_lan_direct {
        policy_rules.extend(
            [
                "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
                "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
                "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
                "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
                "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
                "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
                "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
                "IP-CIDR6,::1/128,DIRECT,no-resolve",
            ]
            .map(str::to_owned),
        );
    }
    if let Some(rules) = compiled["rules"].as_array_mut() {
        let mut merged = policy_rules
            .into_iter()
            .map(Value::String)
            .collect::<Vec<_>>();
        merged.append(rules);
        *rules = merged;
    }
    let root = compiled.as_object_mut().expect("object retained");
    root.insert("allow-lan".into(), Value::Bool(false));
    root.insert("bind-address".into(), Value::String("127.0.0.1".into()));
    root.insert("tun".into(), serde_json::json!({"enable": false}));
    root.insert(
        "profile".into(),
        serde_json::json!({"store-selected": false}),
    );
    if let Some(port) = options.mixed_port {
        root.insert("mixed-port".into(), Value::from(port));
    } else {
        root.remove("mixed-port");
    }
    for key in ["port", "socks-port", "redir-port", "tproxy-port"] {
        root.remove(key);
    }
    root.entry("proxies")
        .or_insert_with(|| Value::Array(Vec::new()));
    validate_config(&compiled)?;
    Ok(compiled)
}

fn validate_profile_options(profile: &Profile) -> io::Result<()> {
    if profile.use_system_proxy
        && profile
            .mihomo
            .as_ref()
            .is_none_or(|options| options.mode != MihomoMode::Proxy)
    {
        return Err(invalid(
            "The system proxy is supported only in Mihomo proxy mode",
        ));
    }
    if !profile.pinned_policies.is_empty()
        || !profile.xray_service_checks.is_empty()
        || !profile.xray_proxy_exits.is_empty()
        || profile.xray_socks_port.is_some()
        || profile.xray_http_port.is_some()
        || profile.xray_mode != Default::default()
        || profile.xray_tun_interface.is_some()
        || profile.xray_tun_ip.is_some()
        || profile.xray_geoip_url.is_some()
        || profile.xray_geosite_url.is_some()
        || profile.xray_domain_strategy.is_some()
        || profile.xray_domain_matcher.is_some()
        || profile.xray_dns != Default::default()
        || profile.xray_split_default
        || profile.xray_quic_reject
        || profile.xray_sockopts.is_some()
        || !profile.xray_traffic_rules.is_empty()
        || !profile.xray_interface_routes.is_empty()
        || profile.xray_connection_idle_secs.is_some()
        || profile.xray_tun_mtu.is_some()
        || !profile.xray_tun_dns_servers.is_empty()
        || profile.xray_direct_domain_strategy.is_some()
    {
        return Err(invalid(
            "Profile contains Xray-only options unsupported by Mihomo",
        ));
    }
    Ok(())
}

fn mihomo_selector(selector: &str) -> io::Result<Option<String>> {
    let Some((category, selector)) = crate::xray::classify_routing_selector(selector)? else {
        return Ok(None);
    };
    if category == "ip" {
        if let Some(code) = selector.strip_prefix("geoip:") {
            return Ok(Some(format!("GEOIP,{code}")));
        }
        let network = selector
            .parse::<ipnet::IpNet>()
            .or_else(|_| selector.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
            .map_err(|_| invalid("Invalid Mihomo profile IP selector"))?;
        let kind = if network.addr().is_ipv4() {
            "IP-CIDR"
        } else {
            "IP-CIDR6"
        };
        return Ok(Some(format!("{kind},{network}")));
    }
    let (kind, value) = match selector.split_once(':') {
        Some(("domain", value)) => ("DOMAIN-SUFFIX", value),
        Some(("full", value)) => ("DOMAIN", value),
        Some(("keyword", value)) => ("DOMAIN-KEYWORD", value),
        Some(("regexp", value)) => ("DOMAIN-REGEX", value),
        Some(("geosite", value)) => ("GEOSITE", value),
        Some(_) => return Err(invalid("Unsupported Mihomo profile domain selector")),
        None => ("DOMAIN-SUFFIX", selector.as_str()),
    };
    if value.is_empty() || value.contains(',') || value.contains(['\r', '\n']) {
        return Err(invalid("Invalid Mihomo profile domain selector"));
    }
    Ok(Some(format!("{kind},{value}")))
}

fn rewrite_provider_paths(config: &mut Value) -> io::Result<()> {
    for (key, prefix) in [("proxy-providers", "proxy"), ("rule-providers", "rule")] {
        let Some(providers) = config.get_mut(key).and_then(Value::as_object_mut) else {
            continue;
        };
        for (index, (_, provider)) in providers.iter_mut().enumerate() {
            let provider = provider
                .as_object_mut()
                .ok_or_else(|| invalid("Invalid Mihomo provider"))?;
            if provider.get("type").and_then(Value::as_str) == Some("inline") {
                continue;
            }
            let extension = if prefix == "proxy" {
                "yaml"
            } else {
                match provider
                    .get("format")
                    .and_then(Value::as_str)
                    .unwrap_or("yaml")
                {
                    "yaml" => "yaml",
                    "mrs" => "mrs",
                    "text" => "text",
                    _ => return Err(invalid("Unsupported Mihomo rule-provider format")),
                }
            };
            provider.insert(
                "path".into(),
                Value::String(format!("providers/{prefix}-{index:04}.{extension}")),
            );
            provider.entry("size-limit").or_insert_with(|| {
                Value::from(crate::subscription::MAX_SUBSCRIPTION_BODY_BYTES as u64)
            });
        }
    }
    Ok(())
}

pub async fn resolve_provider_snapshots(config: &Value) -> io::Result<Value> {
    resolve_provider_snapshots_inner(config, None).await
}

pub async fn resolve_due_provider_snapshots(config: &Value, now: u64) -> io::Result<Value> {
    resolve_provider_snapshots_inner(config, Some(now)).await
}

async fn resolve_provider_snapshots_inner(config: &Value, now: Option<u64>) -> io::Result<Value> {
    validate_source(config)?;
    let root = config
        .as_object()
        .ok_or_else(|| invalid("Mihomo configuration must be an object"))?;
    let source_meta = root
        .get("x-netorch-source")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let source = source_meta
        .get("proxy-providers")
        .and_then(Value::as_object)
        .cloned()
        .or_else(|| {
            root.get("proxy-providers")
                .and_then(Value::as_object)
                .cloned()
        })
        .unwrap_or_default();
    if source.is_empty() {
        return Ok(config.clone());
    }
    let current = root.get("proxy-providers").and_then(Value::as_object);
    let mut output = serde_json::Map::new();
    let mut next_metadata = source.clone();
    let mut changed = false;
    for (name, source_provider) in &source {
        let provider = source_provider
            .as_object()
            .ok_or_else(|| invalid("Invalid Mihomo provider metadata"))?;
        if provider.get("type").and_then(Value::as_str) == Some("inline") {
            output.insert(name.clone(), source_provider.clone());
            continue;
        }
        if provider.get("type").and_then(Value::as_str) != Some("http") {
            return Err(invalid("Only HTTP Mihomo proxy providers can be resolved"));
        }
        let existing = current
            .and_then(|map| map.get(name))
            .filter(|value| value["type"] == "inline");
        let last_attempt = provider
            .get("lastAttemptUnix")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let interval = provider
            .get("interval")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let due = now.is_none()
            || existing.is_none()
            || (interval > 0
                && now.is_some_and(|now| {
                    last_attempt == 0 || now.saturating_sub(last_attempt) >= interval
                }));
        if !due {
            if let Some(existing) = existing {
                output.insert(name.clone(), existing.clone());
            }
            continue;
        }
        let url = provider
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("Mihomo provider has no URL"))?;
        let parsed = url::Url::parse(url).map_err(|_| invalid("Invalid Mihomo provider URL"))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(invalid(
                "Mihomo provider URL must be HTTP(S) without embedded credentials",
            ));
        }
        let headers = provider_headers(provider)?;
        let bytes = crate::subscription::fetch_mihomo_dataset_with_headers(url, &headers)
            .await
            .map_err(|_| invalid("Unable to download Mihomo proxy provider"))?;
        if provider
            .get("size-limit")
            .and_then(Value::as_u64)
            .is_some_and(|limit| bytes.len() as u64 > limit)
        {
            return Err(invalid(
                "Mihomo proxy provider exceeds its configured size limit",
            ));
        }
        let mut inline = serde_json::Map::new();
        inline.insert("type".into(), Value::String("inline".into()));
        inline.insert(
            "payload".into(),
            Value::Array(parse_provider_proxies(&bytes)?),
        );
        for key in [
            "health-check",
            "filter",
            "exclude-filter",
            "exclude-type",
            "override",
        ] {
            if let Some(value) = provider.get(key) {
                inline.insert(key.into(), value.clone());
            }
        }
        output.insert(name.clone(), Value::Object(inline));
        if let Some(meta) = next_metadata.get_mut(name).and_then(Value::as_object_mut) {
            meta.insert(
                "lastAttemptUnix".into(),
                Value::from(now.unwrap_or_else(current_unix_time)),
            );
            meta.remove("lastError");
        }
        changed = true;
    }
    if !changed {
        return Ok(config.clone());
    }
    let mut resolved = config.clone();
    let root = resolved.as_object_mut().expect("config object retained");
    root.insert("proxy-providers".into(), Value::Object(output));
    let mut metadata = source_meta;
    metadata.insert("proxy-providers".into(), Value::Object(next_metadata));
    root.insert("x-netorch-source".into(), Value::Object(metadata));
    validate_source(&resolved)?;
    Ok(resolved)
}

fn provider_headers(
    provider: &serde_json::Map<String, Value>,
) -> io::Result<BTreeMap<String, Vec<String>>> {
    let mut headers = BTreeMap::new();
    let Some(value) = provider.get("header") else {
        return Ok(headers);
    };
    let values = value
        .as_object()
        .ok_or_else(|| invalid("Invalid Mihomo provider headers"))?;
    for (name, values) in values {
        let values = match values {
            Value::String(value) => vec![value.clone()],
            Value::Array(values) => values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| invalid("Invalid Mihomo provider header value"))
                })
                .collect::<io::Result<Vec<_>>>()?,
            _ => return Err(invalid("Invalid Mihomo provider header value")),
        };
        headers.insert(name.clone(), values);
    }
    Ok(headers)
}

fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|time| time.as_secs())
        .unwrap_or(0)
}

fn parse_provider_proxies(bytes: &[u8]) -> io::Result<Vec<Value>> {
    if bytes.len() > crate::subscription::MAX_SUBSCRIPTION_BODY_BYTES {
        return Err(invalid("Mihomo proxy provider exceeds its size limit"));
    }
    let yaml = yaml::parse(bytes)?;
    let value = serde_json::to_value(resolve_yaml_merges(yaml, 0, &mut 0)?)
        .map_err(|_| invalid("Unsupported YAML value in Mihomo proxy provider"))?;
    let proxies = value
        .get("proxies")
        .and_then(Value::as_array)
        .or_else(|| value.as_array())
        .ok_or_else(|| invalid("Mihomo proxy provider contains no proxy list"))?;
    let mut names = BTreeSet::new();
    for proxy in proxies {
        validate_proxy(proxy)?;
        if !names.insert(proxy["name"].as_str().expect("proxy validated")) {
            return Err(invalid("Mihomo provider contains duplicate proxy names"));
        }
    }
    Ok(proxies.clone())
}
pub fn validate_config(config: &Value) -> io::Result<()> {
    validate_config_inner(config, false)
}

fn validate_config_inner(config: &Value, allow_http_proxy: bool) -> io::Result<()> {
    let root = config
        .as_object()
        .ok_or_else(|| invalid("Mihomo configuration must be an object"))?;
    for key in [
        "script",
        "scripts",
        "external-controller",
        "external-controller-tls",
        "external-controller-pipe",
        "external-ui",
        "external-ui-url",
        "external-controller-unix",
        "listeners",
        "redir-port",
        "tproxy-port",
        "socks-port",
        "port",
        "authentication",
        "secret",
        "geodata-loader",
        "geo-auto-update",
        "routing-mark",
        "iptables",
        "tunnels",
        "x-netorch-source",
    ] {
        if root.contains_key(key) {
            return Err(invalid(
                "Mihomo configuration contains an unsafe or generated setting",
            ));
        }
    }
    if root.get("mode").is_some_and(|mode| mode != "rule") {
        return Err(invalid(
            "Mihomo runtime must use rule mode for profile policies",
        ));
    }
    if root
        .get("profile")
        .is_some_and(|value| value != &serde_json::json!({"store-selected":false}))
        || root
            .get("allow-lan")
            .is_some_and(|value| value != &Value::Bool(false))
        || root
            .get("bind-address")
            .is_some_and(|value| value != "127.0.0.1")
        || root
            .get("tun")
            .is_some_and(|value| value != &serde_json::json!({"enable":false}))
        || root.get("mixed-port").is_some_and(|value| {
            value
                .as_u64()
                .is_none_or(|port| port == 0 || port > u16::MAX as u64)
        })
    {
        return Err(invalid(
            "Mihomo listener settings must be disabled or loopback-only",
        ));
    }
    let proxies = root
        .get("proxies")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut names = BTreeSet::new();
    for proxy in &proxies {
        validate_proxy(proxy)?;
        if !names.insert(proxy["name"].as_str().expect("proxy validated").to_owned()) {
            return Err(invalid("Duplicate Mihomo proxy name"));
        }
    }
    let providers = validate_providers(root, allow_http_proxy)?;
    for name in providers.1 {
        if !names.insert(name) {
            return Err(invalid("Duplicate Mihomo proxy name"));
        }
    }
    let groups = root
        .get("proxy-groups")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("Mihomo configuration must contain proxy-groups"))?;
    let mut group_names = BTreeSet::new();
    for group in groups {
        let name = group
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("Mihomo proxy group has no name"))?;
        if name.is_empty()
            || name.len() > 512
            || name.chars().any(char::is_control)
            || RESERVED_PROXY_NAMES.contains(&name)
            || names.contains(name)
            || !group_names.insert(name)
        {
            return Err(invalid("Duplicate Mihomo proxy-group name"));
        }
        if !matches!(
            group.get("type").and_then(Value::as_str),
            Some("select" | "url-test" | "fallback" | "load-balance")
        ) {
            return Err(invalid("Unsupported Mihomo proxy-group type"));
        }
        if group.get("proxies").is_some_and(|value| !value.is_array())
            || group.get("use").is_some_and(|value| !value.is_array())
        {
            return Err(invalid("Mihomo proxy group members must be lists"));
        }
    }
    let mut known = names;
    known.extend(group_names.iter().map(|name| (*name).to_owned()));
    known.extend(
        ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"]
            .into_iter()
            .map(str::to_owned),
    );
    for group in groups {
        for member in group
            .get("proxies")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let name = member
                .as_str()
                .ok_or_else(|| invalid("Invalid Mihomo group member"))?;
            if !known.contains(name) {
                return Err(invalid("Mihomo proxy group references an unknown member"));
            }
        }
        for provider in group
            .get("use")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if !provider
                .as_str()
                .is_some_and(|name| providers.0.contains(name))
            {
                return Err(invalid("Mihomo group references an unknown provider"));
            }
        }
    }
    validate_group_graph(groups, &group_names)?;
    validate_dialer_dependencies(config)?;
    let rules = root
        .get("rules")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("Mihomo configuration must contain native rules"))?;
    for rule in rules {
        let fields = rule
            .as_str()
            .ok_or_else(|| invalid("Invalid Mihomo rule"))?
            .split(',')
            .collect::<Vec<_>>();
        if fields.len() < 2 {
            return Err(invalid("Invalid Mihomo rule"));
        }
        if fields[0] == "RULE-SET" && (fields.len() < 3 || !providers.2.contains(fields[1])) {
            return Err(invalid("Mihomo rule references an unknown rule provider"));
        }
        let target = if fields.last() == Some(&"no-resolve") {
            fields.get(fields.len().saturating_sub(2))
        } else {
            fields.last()
        }
        .ok_or_else(|| invalid("Invalid Mihomo rule target"))?;
        if !known.contains(*target) {
            return Err(invalid("Mihomo rule references an unknown target"));
        }
    }
    for (key, value) in root {
        if key != "proxies" && key != "proxy-providers" && key != "rule-providers" {
            reject_path_or_hook(key, value)?;
        }
    }
    Ok(())
}

const RESERVED_PROXY_NAMES: [&str; 6] = [
    "DIRECT",
    "REJECT",
    "REJECT-DROP",
    "PASS",
    "COMPATIBLE",
    "GLOBAL",
];

fn validate_proxy(proxy: &Value) -> io::Result<()> {
    let proxy = proxy
        .as_object()
        .ok_or_else(|| invalid("Invalid Mihomo proxy entry"))?;
    let name = proxy
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Mihomo proxy has no name"))?;
    if name.is_empty()
        || name.len() > 512
        || name.chars().any(char::is_control)
        || RESERVED_PROXY_NAMES.contains(&name)
    {
        return Err(invalid("Mihomo proxy name must be non-empty"));
    }
    let kind = proxy
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Mihomo proxy has no type"))?;
    if !matches!(
        kind,
        "vless" | "hysteria2" | "vmess" | "trojan" | "ss" | "socks5" | "http"
    ) {
        return Err(invalid("Unsupported Mihomo proxy type"));
    }
    if proxy.keys().any(|key| {
        !key.is_ascii()
            || (key != "alterId" && key.bytes().any(|byte| byte.is_ascii_uppercase()))
            || matches!(
                key.as_str(),
                "plugin" | "plugin-opts" | "interface-name" | "routing-mark" | "ip-version"
            )
    }) {
        return Err(invalid("Mihomo proxy contains an unsafe option"));
    }
    if proxy.get("server").and_then(Value::as_str).is_none()
        || proxy
            .get("port")
            .and_then(Value::as_u64)
            .is_none_or(|port| port == 0 || port > u16::MAX as u64)
    {
        return Err(invalid("Mihomo proxy is missing a valid server or port"));
    }
    let credentials = match kind {
        "vless" | "vmess" => proxy.get("uuid").and_then(Value::as_str),
        "hysteria2" | "trojan" => proxy.get("password").and_then(Value::as_str),
        "ss" => proxy
            .get("cipher")
            .and_then(Value::as_str)
            .filter(|_| proxy.get("password").and_then(Value::as_str).is_some()),
        _ => Some("builtin"),
    };
    if credentials.is_none_or(str::is_empty) {
        return Err(invalid("Mihomo proxy is missing required credentials"));
    }
    if proxy
        .get("dialer-proxy")
        .is_some_and(|value| !value.is_string())
        || proxy.get("tls").is_some_and(|value| !value.is_boolean())
    {
        return Err(invalid("Invalid Mihomo dialer or TLS option"));
    }
    for (key, value) in proxy {
        if matches!(key.as_str(), "ws-opts" | "http-opts" | "h2-opts") {
            let options = value
                .as_object()
                .ok_or_else(|| invalid("Invalid Mihomo transport options"))?;
            for (key, value) in options {
                if key == "path" {
                    let valid = |value: &Value| {
                        value.as_str().is_some_and(|path| {
                            path.starts_with('/')
                                && path.len() <= 4096
                                && !path.chars().any(char::is_control)
                        })
                    };
                    if !valid(value)
                        && !value
                            .as_array()
                            .is_some_and(|paths| paths.len() <= 16 && paths.iter().all(valid))
                    {
                        return Err(invalid("Invalid Mihomo transport path"));
                    }
                } else {
                    reject_path_or_hook(key, value)?;
                }
            }
        } else {
            reject_path_or_hook(key, value)?;
        }
    }
    Ok(())
}

fn validate_dialer_dependencies(config: &Value) -> io::Result<()> {
    let proxies = config.get("proxies").and_then(Value::as_array);
    let root = proxies
        .into_iter()
        .flatten()
        .map(|proxy| (proxy["name"].as_str().expect("proxy validated"), proxy))
        .collect::<BTreeMap<_, _>>();
    let providers = config.get("proxy-providers").and_then(Value::as_object);
    let payloads = providers
        .into_iter()
        .flat_map(|providers| providers.values())
        .flat_map(|provider| {
            provider
                .get("payload")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        });
    for proxy in proxies.into_iter().flatten().chain(payloads) {
        if let Some(dialer) = proxy
            .get("dialer-proxy")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty() && *name != "DIRECT")
        {
            if !root.contains_key(dialer) {
                return Err(invalid(
                    "Mihomo dialer requires a named root proxy or DIRECT",
                ));
            }
        }
    }
    let mut done = BTreeSet::new();
    for &name in root.keys() {
        let mut active = BTreeSet::new();
        let mut current = name;
        while !done.contains(current) {
            if active.len() >= MAX_YAML_DEPTH || !active.insert(current) {
                return Err(invalid(
                    "Mihomo proxy dialers contain a cycle or excessive depth",
                ));
            }
            let Some(next) = root[current]
                .get("dialer-proxy")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty() && *name != "DIRECT")
            else {
                break;
            };
            current = next;
        }
        done.extend(active);
    }
    Ok(())
}

fn validate_providers(
    root: &serde_json::Map<String, Value>,
    allow_http_proxy: bool,
) -> io::Result<(BTreeSet<String>, BTreeSet<String>, BTreeSet<String>)> {
    let mut proxies = BTreeSet::new();
    let mut inline_names = BTreeSet::new();
    let mut rules = BTreeSet::new();
    for (key, prefix) in [("proxy-providers", "proxy"), ("rule-providers", "rule")] {
        let Some(map) = root.get(key) else { continue };
        let map = map
            .as_object()
            .ok_or_else(|| invalid("Invalid Mihomo provider map"))?;
        for (index, (name, value)) in map.iter().enumerate() {
            if name.is_empty() {
                return Err(invalid("Mihomo provider name must not be empty"));
            }
            let provider = value
                .as_object()
                .ok_or_else(|| invalid("Invalid Mihomo provider"))?;
            let kind = provider
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("Mihomo provider has no type"))?;
            if prefix == "proxy" {
                proxies.insert(name.clone());
                match kind {
                    "http" if allow_http_proxy => validate_http_provider(
                        provider,
                        &format!("providers/proxy-{index:04}.yaml"),
                    )?,
                    "http" => {
                        return Err(invalid(
                            "HTTP proxy providers must be resolved before privileged validation",
                        ))
                    }
                    "inline" => {
                        if provider.keys().any(|key| {
                            !matches!(
                                key.as_str(),
                                "type"
                                    | "payload"
                                    | "health-check"
                                    | "filter"
                                    | "exclude-filter"
                                    | "exclude-type"
                                    | "override"
                            )
                        }) {
                            return Err(invalid("Unsupported inline provider setting"));
                        }
                        let payload = provider
                            .get("payload")
                            .and_then(Value::as_array)
                            .ok_or_else(|| invalid("Inline Mihomo provider has no payload"))?;
                        for proxy in payload {
                            validate_proxy(proxy)?;
                            if !inline_names.insert(provider_proxy_name(provider, proxy)?) {
                                return Err(invalid("Duplicate provider proxy name"));
                            }
                        }
                        for (key, value) in provider {
                            if key != "type" && key != "payload" {
                                reject_path_or_hook(key, value)?;
                            }
                        }
                        validate_override(provider)?;
                    }
                    _ => return Err(invalid("Unsupported Mihomo proxy-provider type")),
                }
            } else {
                match kind {
                    "http" => {
                        let extension = match provider
                            .get("format")
                            .and_then(Value::as_str)
                            .unwrap_or("yaml")
                        {
                            "yaml" => "yaml",
                            "mrs" => "mrs",
                            "text" => "text",
                            _ => return Err(invalid("Unsupported rule-provider format")),
                        };
                        validate_http_provider(
                            provider,
                            &format!("providers/rule-{index:04}.{extension}"),
                        )?;
                    }
                    "inline" => {
                        if provider
                            .keys()
                            .any(|key| !matches!(key.as_str(), "type" | "behavior" | "payload"))
                        {
                            return Err(invalid("Unsupported inline rule-provider setting"));
                        }
                        if !matches!(
                            provider.get("behavior").and_then(Value::as_str),
                            Some("domain" | "ipcidr" | "classical")
                        ) {
                            return Err(invalid("Unsupported rule-provider behavior"));
                        }
                        if !provider
                            .get("payload")
                            .and_then(Value::as_array)
                            .is_some_and(|payload| payload.iter().all(Value::is_string))
                        {
                            return Err(invalid("Invalid inline rule-provider payload"));
                        }
                    }
                    _ => return Err(invalid("Unsupported Mihomo rule-provider type")),
                }
                rules.insert(name.clone());
            }
        }
    }
    Ok((proxies, inline_names, rules))
}

fn validate_http_provider(provider: &serde_json::Map<String, Value>, path: &str) -> io::Result<()> {
    let url = provider
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Mihomo provider has no URL"))?;
    let parsed = url::Url::parse(url).map_err(|_| invalid("Invalid Mihomo provider URL"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(invalid(
            "Mihomo provider URL must be HTTP(S) without embedded credentials",
        ));
    }
    if provider.get("path").and_then(Value::as_str) != Some(path) {
        return Err(invalid("Mihomo provider path is not canonical"));
    }
    if provider.get("size-limit").is_some_and(|value| {
        value.as_u64().is_none_or(|size| {
            size == 0 || size > crate::subscription::MAX_SUBSCRIPTION_BODY_BYTES as u64
        })
    }) {
        return Err(invalid("Mihomo provider size limit is invalid"));
    }
    for key in provider.keys() {
        if !matches!(
            key.as_str(),
            "type"
                | "url"
                | "path"
                | "interval"
                | "lazy"
                | "size-limit"
                | "format"
                | "behavior"
                | "health-check"
                | "header"
                | "filter"
                | "exclude-filter"
                | "exclude-type"
                | "override"
        ) {
            return Err(invalid("Unsupported Mihomo provider setting"));
        }
    }
    for (key, value) in provider {
        if key != "url" && key != "path" && key != "header" {
            reject_path_or_hook(key, value)?;
        }
    }
    if provider
        .get("behavior")
        .and_then(Value::as_str)
        .is_some_and(|value| !matches!(value, "domain" | "ipcidr" | "classical"))
    {
        return Err(invalid("Unsupported rule-provider behavior"));
    }
    Ok(())
}

fn validate_override(provider: &serde_json::Map<String, Value>) -> io::Result<()> {
    let Some(value) = provider.get("override") else {
        return Ok(());
    };
    let map = value
        .as_object()
        .ok_or_else(|| invalid("Invalid inline provider override"))?;
    for (key, value) in map {
        match key.as_str() {
            "dialer-proxy"
                if value.as_str().is_some_and(|value| {
                    value.len() <= 512 && !value.chars().any(char::is_control)
                }) => {}
            "udp" | "skip-cert-verify" | "udp-over-tcp" | "tfo" | "mptcp" if value.is_boolean() => {
            }
            "additional-prefix" | "additional-suffix"
                if value.as_str().is_some_and(|value| {
                    value.len() <= 128 && !value.contains([',', '\r', '\n'])
                }) => {}
            _ => return Err(invalid("Unsupported or unsafe inline provider override")),
        }
    }
    Ok(())
}

// Keep name overrides native: Mihomo filters original names before renaming.
fn materialize_inline_overrides(config: &mut Value) -> io::Result<()> {
    let Some(providers) = config
        .get_mut("proxy-providers")
        .and_then(Value::as_object_mut)
    else {
        return Ok(());
    };
    for provider in providers.values_mut() {
        let provider = provider
            .as_object_mut()
            .ok_or_else(|| invalid("Invalid Mihomo provider"))?;
        validate_override(provider)?;
        if provider.get("type").and_then(Value::as_str) != Some("inline") {
            continue;
        }
        let Some(Value::Object(mut overrides)) = provider.remove("override") else {
            continue;
        };
        let naming = ["additional-prefix", "additional-suffix"]
            .into_iter()
            .filter_map(|key| overrides.remove(key).map(|value| (key.to_owned(), value)))
            .collect::<serde_json::Map<_, _>>();
        let payload = provider
            .get_mut("payload")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| invalid("Inline Mihomo provider has no payload"))?;
        for proxy in payload {
            let object = proxy
                .as_object_mut()
                .ok_or_else(|| invalid("Invalid Mihomo proxy entry"))?;
            for (key, value) in &overrides {
                object.insert(key.clone(), value.clone());
            }
            validate_proxy(proxy)?;
        }
        if !naming.is_empty() {
            provider.insert("override".into(), Value::Object(naming));
        }
    }
    Ok(())
}

fn provider_proxy_name(
    provider: &serde_json::Map<String, Value>,
    proxy: &Value,
) -> io::Result<String> {
    let name = proxy
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Mihomo proxy has no name"))?;
    let overrides = provider.get("override");
    let prefix = overrides
        .and_then(|value| value.get("additional-prefix"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let suffix = overrides
        .and_then(|value| value.get("additional-suffix"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let name = format!("{prefix}{name}{suffix}");
    if name.is_empty()
        || name.len() > 512
        || name.chars().any(char::is_control)
        || RESERVED_PROXY_NAMES.contains(&name.as_str())
    {
        return Err(invalid("Invalid effective Mihomo provider proxy name"));
    }
    Ok(name)
}

fn validate_group_graph(groups: &[Value], names: &BTreeSet<&str>) -> io::Result<()> {
    let by_name = groups
        .iter()
        .filter_map(|group| Some((group.get("name")?.as_str()?, group)))
        .collect::<BTreeMap<_, _>>();
    let mut done = BTreeSet::new();
    for &name in names {
        let mut active = BTreeSet::new();
        let mut stack = vec![(name, false)];
        while let Some((name, exiting)) = stack.pop() {
            if exiting {
                active.remove(name);
                done.insert(name);
                continue;
            }
            if done.contains(name) {
                continue;
            }
            if active.len() >= MAX_YAML_DEPTH {
                return Err(invalid("Mihomo proxy-group graph exceeds its depth limit"));
            }
            if !active.insert(name) {
                return Err(invalid("Mihomo proxy groups contain a cycle"));
            }
            stack.push((name, true));
            if let Some(members) = by_name
                .get(name)
                .and_then(|group| group.get("proxies"))
                .and_then(Value::as_array)
            {
                for member in members
                    .iter()
                    .rev()
                    .filter_map(Value::as_str)
                    .filter(|member| by_name.contains_key(member))
                {
                    stack.push((member, false));
                }
            }
        }
    }
    Ok(())
}

fn reject_path_or_hook(key: &str, value: &Value) -> io::Result<()> {
    if key == "path" {
        return Err(invalid(
            "Mihomo configuration contains an arbitrary file path",
        ));
    }
    if matches!(
        key,
        "certificate" | "private-key" | "ca" | "ca-file" | "client-cert" | "client-key"
    ) {
        return Err(invalid(
            "Mihomo client certificate and key files are unsupported",
        ));
    }
    if matches!(
        key,
        "script"
            | "script-file"
            | "process-name"
            | "process-path"
            | "routing-mark"
            | "external-controller"
            | "external-controller-tls"
            | "external-controller-pipe"
            | "external-ui"
            | "external-ui-url"
            | "iptables"
            | "tunnels"
            | "listen"
            | "write-to-system"
    ) {
        return Err(invalid(
            "Mihomo configuration contains an unsafe hook, route, or listener",
        ));
    }
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                reject_path_or_hook(key, value)?;
            }
        }
        Value::Array(items) => {
            for value in items {
                reject_path_or_hook("", value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn group_info(
    config: &Value,
    options: &MihomoProfileOptions,
) -> io::Result<Vec<MihomoGroupInfo>> {
    let config = prepare_source(config)?;
    group_info_inner(&config, options)
}

fn group_info_inner<'a>(
    config: &'a Value,
    options: &MihomoProfileOptions,
) -> io::Result<Vec<MihomoGroupInfo>> {
    let groups = config
        .get("proxy-groups")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("Mihomo configuration has no proxy-groups"))?;
    let providers = config.get("proxy-providers").and_then(Value::as_object);
    let root_proxies = config.get("proxies").and_then(Value::as_array);
    groups
        .iter()
        .map(|group| {
            let name = group
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("Mihomo proxy group has no name"))?;
            let kind = group
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("Mihomo proxy group has no type"))?;
            let mut members = Vec::new();
            let mut seen = BTreeSet::new();
            let mut add = |name: Cow<'a, str>| {
                if seen.insert(name.clone()) {
                    members.push(name.into_owned());
                }
            };
            for member in group
                .get("proxies")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                add(Cow::Borrowed(
                    member
                        .as_str()
                        .ok_or_else(|| invalid("Invalid Mihomo group member"))?,
                ));
            }
            let include_all = group.get("include-all").and_then(Value::as_bool) == Some(true);
            if include_all
                || group.get("include-all-proxies").and_then(Value::as_bool) == Some(true)
            {
                for proxy in root_proxies.into_iter().flatten() {
                    add(Cow::Borrowed(
                        proxy["name"].as_str().expect("proxy validated"),
                    ));
                }
            }
            let include_providers = include_all
                || group.get("include-all-providers").and_then(Value::as_bool) == Some(true);
            if let Some(providers) = providers {
                for (provider_name, provider) in providers {
                    if !include_providers
                        && !group
                            .get("use")
                            .and_then(Value::as_array)
                            .is_some_and(|names| names.iter().any(|name| name == provider_name))
                    {
                        continue;
                    }
                    for proxy in provider
                        .get("payload")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        add(Cow::Owned(provider_proxy_name(
                            provider.as_object().expect("provider validated"),
                            proxy,
                        )?));
                    }
                }
            }
            Ok(MihomoGroupInfo {
                name: name.to_owned(),
                kind: kind.to_owned(),
                members,
                selected: options.group_selections.get(name).cloned(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn yaml_alias_expansion_and_multiple_documents_are_rejected() {
        let mut yaml = "proxies: []\nproxy-groups: []\nrules: []\na0: &a0 [x,x]\n".to_owned();
        for depth in 1..40 {
            yaml.push_str(&format!(
                "a{depth}: &a{depth} [*a{},*a{}]\n",
                depth - 1,
                depth - 1
            ));
        }
        assert!(parse_config(yaml.as_bytes()).is_err());
        assert!(
            parse_config(b"proxies: []\nproxy-groups: []\nrules: []\n---\nproxies: []\n").is_err()
        );
    }

    #[test]
    fn provider_overrides_preserve_validated_named_proxy_dialers_without_extensions() {
        let mut config = source();
        config["proxy-providers"] = json!({"chained":{
            "type":"inline","payload":[config["proxies"][0].clone()],
            "override":{"additional-prefix":"via-","dialer-proxy":"node-a","udp":true}
        }});
        config["proxy-groups"][0]["use"] = json!(["chained"]);
        let compiled = compile_config(
            &config,
            &profile(MihomoMode::Tun, None, &[("Auto", "via-node-a")]),
        )
        .unwrap();
        let groups = group_info(
            &compiled,
            profile(MihomoMode::Tun, None, &[]).mihomo.as_ref().unwrap(),
        )
        .unwrap();
        assert!(groups
            .iter()
            .find(|group| group.name == "Auto")
            .unwrap()
            .members
            .contains(&"via-node-a".to_owned()));
        assert!(validate_config(&compiled).is_ok());
        let mut unknown = compiled.clone();
        unknown["proxies"][0]["dialer-proxy"] = json!("missing");
        assert!(validate_config(&unknown).is_err());
        let mut cycle = source();
        let mut other = cycle["proxies"][0].clone();
        other["name"] = json!("node-b");
        other["dialer-proxy"] = json!("node-a");
        cycle["proxies"].as_array_mut().unwrap().push(other);
        cycle["proxies"][0]["dialer-proxy"] = json!("node-b");
        assert!(validate_config(&cycle).is_err());
    }

    #[test]
    fn transport_uri_paths_are_allowed_but_tls_files_and_reserved_names_are_not() {
        let mut config = source();
        config["proxies"][0]["network"] = json!("ws");
        config["proxies"][0]["ws-opts"] =
            json!({"path":"/socket?early=1","headers":{"Host":"example.org"}});
        assert!(validate_config(&config).is_ok());
        config["proxies"][0]["certificate"] = json!("/tmp/client.pem");
        assert!(validate_config(&config).is_err());
        config["proxies"][0]
            .as_object_mut()
            .unwrap()
            .remove("certificate");
        config["proxy-groups"][0]["name"] = json!("DIRECT");
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn proxy_policy_requires_a_proxy_default_instead_of_silently_using_direct() {
        let mut config = source();
        config["rules"] = json!(["MATCH,DIRECT"]);
        let mut p = profile(MihomoMode::Tun, None, &[]);
        p.domain_policies.push(crate::models::DomainPolicy {
            domains: vec!["full:example.org".into()],
            target: DomainRouteTarget::Proxy,
        });
        assert!(compile_config(&config, &p).is_err());
        p.mihomo.as_mut().unwrap().entry_group = Some("Auto".into());
        let compiled = compile_config(&config, &p).unwrap();
        assert_eq!(compiled["rules"][0], "DOMAIN,example.org,Auto");
    }

    #[test]
    fn system_proxy_requires_the_local_proxy_mode() {
        let mut p = profile(MihomoMode::Tun, None, &[]);
        p.use_system_proxy = true;
        assert!(compile_config(&source(), &p).is_err());
        p.mihomo.as_mut().unwrap().mode = MihomoMode::Proxy;
        assert!(compile_config(&source(), &p).is_ok());
    }

    #[test]
    fn include_all_flags_distinguish_root_proxies_from_provider_members() {
        let mut config = source();
        config["proxy-providers"] = json!({"shared":{"type":"inline","payload":[{"name":"provided","type":"socks5","server":"provided.test","port":1080}]}});
        config["proxy-groups"] = json!([
            {"name":"Auto","type":"select","include-all-proxies":true},
            {"name":"Providers","type":"select","include-all-providers":true},
            {"name":"Everything","type":"select","include-all":true}
        ]);
        let groups = group_info(&config, &MihomoProfileOptions::default()).unwrap();
        assert_eq!(groups[0].members, vec!["node-a"]);
        assert_eq!(groups[1].members, vec!["provided"]);
        assert_eq!(groups[2].members, vec!["node-a", "provided"]);
    }

    fn profile(
        mode: MihomoMode,
        entry_group: Option<&str>,
        selections: &[(&str, &str)],
    ) -> Profile {
        let mut group_selections = BTreeMap::new();
        for (group, member) in selections {
            group_selections.insert((*group).into(), (*member).into());
        }
        Profile { mihomo: Some(MihomoProfileOptions { mode, entry_group: entry_group.map(str::to_owned), mixed_port: Some(7890), group_selections }), ..serde_json::from_value(json!({"id":"test","name":"Test","backend":"mihomo","configPath":"/tmp/config","interfaceName":"mihomo0","routes":[],"autoConnect":false})).unwrap() }
    }

    fn source() -> Value {
        json!({"proxies":[{"name":"node-a","type":"vless","server":"example.com","port":443,"uuid":"00000000-0000-0000-0000-000000000000","tls":true}],"proxy-groups":[{"name":"Auto","type":"select","proxies":["node-a","DIRECT"]}],"rules":["MATCH,Auto"],"dns":{"enable":true}})
    }

    #[test]
    fn parses_json_yaml_and_yaml_merge_keys() {
        let yaml = b"base: &base\n  proxies: []\n  proxy-groups: []\n  rules: []\n<<: *base\n";
        let parsed = parse_config(yaml).unwrap();
        assert_eq!(parsed["rules"], json!([]));
        let json_bytes = br#"{"proxies":[],"proxy-groups":[],"rules":[]}"#;
        assert_eq!(parse_config(json_bytes).unwrap()["proxy-groups"], json!([]));
    }

    #[test]
    fn compile_preserves_native_rules_and_applies_selection_and_safe_defaults() {
        let original = source();
        let compiled = compile_config(
            &original,
            &profile(MihomoMode::Proxy, Some("Auto"), &[("Auto", "node-a")]),
        )
        .unwrap();
        assert_eq!(original["rules"], json!(["MATCH,Auto"]));
        assert_eq!(compiled["rules"], original["rules"]);
        assert_eq!(compiled["proxy-groups"][0]["proxies"][0], json!("node-a"));
        assert_eq!(compiled["profile"]["store-selected"], json!(false));
        assert_eq!(compiled["mixed-port"], json!(7890));
        assert_eq!(compiled["tun"]["enable"], json!(false));
        assert_eq!(compiled["allow-lan"], json!(false));
    }

    #[test]
    fn compile_preserves_inline_rule_providers_and_native_rules() {
        let mut config = source();
        config["rule-providers"] = json!({
            "local": {"type":"inline","behavior":"classical","payload":[
                "DOMAIN-SUFFIX,example.org", "IP-CIDR,192.0.2.0/24,no-resolve"
            ]},
            "domains": {"type":"inline","behavior":"domain","payload":["example.net"]},
            "networks": {"type":"inline","behavior":"ipcidr","payload":["198.51.100.0/24"]}
        });
        config["rules"] = json!(["RULE-SET,local,Auto", "MATCH,Auto"]);
        let bytes = serde_json::to_vec(&config).unwrap();
        let parsed = parse_config(&bytes).unwrap();
        let compiled = compile_config(&parsed, &profile(MihomoMode::Tun, None, &[])).unwrap();
        assert_eq!(compiled["rule-providers"], config["rule-providers"]);
        assert_eq!(compiled["rules"], config["rules"]);
        assert!(validate_config(&compiled).is_ok());
    }

    #[test]
    fn rejects_malformed_or_unsafe_inline_rule_providers() {
        for provider in [
            json!({"type":"inline","behavior":"classical"}),
            json!({"type":"inline","behavior":"classical","payload":"DOMAIN,example.org"}),
            json!({"type":"inline","behavior":"classical","payload":[1]}),
            json!({"type":"inline","payload":[]}),
            json!({"type":"inline","behavior":null,"payload":[]}),
            json!({"type":"inline","behavior":"other","payload":[]}),
            json!({"type":"inline","behavior":"classical","payload":[],"url":"https://example.org"}),
            json!({"type":"inline","behavior":"classical","payload":[],"path":"/tmp/rules"}),
            json!({"type":"inline","behavior":"classical","payload":[],"hook":"run"}),
            json!({"type":"inline","behavior":"classical","payload":[],"format":"yaml"}),
            json!({"type":"file","behavior":"classical","payload":[]}),
        ] {
            let mut config = source();
            config["rule-providers"] = json!({"local": provider});
            assert!(compile_config(&config, &profile(MihomoMode::Tun, None, &[])).is_err());
        }
    }

    #[test]
    fn domain_policies_precede_native_routing_and_private_lan_directs() {
        let mut p = profile(MihomoMode::Tun, None, &[]);
        p.private_lan_direct = true;
        p.domain_policies.push(crate::models::DomainPolicy {
            domains: vec!["domain:example.org".into()],
            target: DomainRouteTarget::Block,
        });
        let compiled = compile_config(&source(), &p).unwrap();
        assert_eq!(compiled["rules"][0], "DOMAIN-SUFFIX,example.org,REJECT");
        let rules = compiled["rules"].as_array().unwrap();
        for prefix in [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "169.254.0.0/16",
        ] {
            let rule = Value::String(format!("IP-CIDR,{prefix},DIRECT,no-resolve"));
            let position = rules.iter().position(|value| value == &rule).unwrap();
            assert!(position > 0 && position < rules.len() - 1);
        }
        assert!(rules.contains(&json!("IP-CIDR6,fc00::/7,DIRECT,no-resolve")));
        assert_eq!(rules.last(), Some(&json!("MATCH,Auto")));
    }

    #[test]
    fn runtime_controls_cannot_bypass_profile_routing_or_open_provider_listeners() {
        let mut original = source();
        original["mode"] = json!("direct");
        original["external-controller"] = json!("0.0.0.0:9090");
        original["external-controller-unix"] = json!("/tmp/caller.sock");
        original["secret"] = json!("caller-secret");
        original["dns"]["listen"] = json!("0.0.0.0:1053");
        let parsed = parse_config(&serde_json::to_vec(&original).unwrap()).unwrap();
        assert_eq!(parsed, original);
        let compiled = compile_config(&parsed, &profile(MihomoMode::Tun, None, &[])).unwrap();
        assert_eq!(compiled["mode"], "rule");
        for key in ["external-controller", "external-controller-unix", "secret"] {
            assert!(compiled.get(key).is_none());
        }
        assert!(compiled["dns"].get("listen").is_none());
        assert!(validate_config(&original).is_err());
    }

    #[test]
    fn profile_policies_accept_shared_ip_selectors_and_annotations() {
        let mut p = profile(MihomoMode::Tun, None, &[]);
        p.domain_policies.push(crate::models::DomainPolicy {
            domains: vec![
                " # annotation".into(),
                "10.24.0.0/16".into(),
                "fc00::1".into(),
            ],
            target: DomainRouteTarget::Block,
        });
        let compiled = compile_config(&source(), &p).unwrap();
        assert_eq!(compiled["rules"][0], "IP-CIDR,10.24.0.0/16,REJECT");
        assert_eq!(compiled["rules"][1], "IP-CIDR6,fc00::1/128,REJECT");
    }

    #[test]
    fn separate_select_groups_do_not_mutate_a_shared_provider_or_fallback_order() {
        let mut config = source();
        config["proxy-providers"] = json!({"shared":{"type":"inline","payload":[
            {"name":"first","type":"socks5","server":"first.test","port":1080},
            {"name":"second","type":"socks5","server":"second.test","port":1080}
        ]}});
        config["proxy-groups"] = json!([
            {"name":"Auto","type":"select","proxies":["DIRECT"],"use":["shared"]},
            {"name":"Other","type":"select","use":["shared"]},
            {"name":"Backup","type":"fallback","proxies":["node-a","DIRECT"],"url":"https://example.org/check","interval":60}
        ]);
        let compiled = compile_config(
            &config,
            &profile(
                MihomoMode::Tun,
                None,
                &[("Auto", "first"), ("Other", "second")],
            ),
        )
        .unwrap();
        assert_eq!(compiled["proxy-providers"], config["proxy-providers"]);
        assert_eq!(compiled["proxy-groups"], config["proxy-groups"]);
    }

    #[test]
    fn rejects_excessive_shallow_group_graph_depth_without_recursive_traversal() {
        let mut config = source();
        let mut groups = (0..128).map(|index| json!({
            "name":format!("group-{index}"), "type":"select",
            "proxies":[if index == 127 { "DIRECT".to_owned() } else { format!("group-{}",index+1) }]
        })).collect::<Vec<_>>();
        groups.push(json!({"name":"Auto","type":"select","proxies":["group-0"]}));
        config["proxy-groups"] = Value::Array(groups);
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn rejects_missing_selections_cycles_dangling_rules_and_unsafe_settings() {
        assert!(compile_config(
            &source(),
            &profile(MihomoMode::Tun, None, &[("gone", "node-a")])
        )
        .is_err());
        let mut cycle = source();
        cycle["proxy-groups"][0]["proxies"] = json!(["Auto"]);
        assert!(validate_config(&cycle).is_err());
        let mut dangling = source();
        dangling["rules"] = json!(["MATCH,missing"]);
        assert!(validate_config(&dangling).is_err());
        let mut unsafe_config = source();
        unsafe_config["dns"]["listen"] = json!("0.0.0.0:53");
        assert!(validate_config(&unsafe_config).is_err());
    }

    #[test]
    fn inline_provider_payloads_are_validated_and_group_info_expands_members() {
        let mut config = source();
        config["proxy-providers"] = json!({"pool":{"type":"inline","payload":[{"name":"node-b","type":"vless","server":"other.test","port":443,"uuid":"00000000-0000-0000-0000-000000000000"}]}});
        config["proxy-groups"][0]["use"] = json!(["pool"]);
        let groups = group_info(&config, &MihomoProfileOptions::default()).unwrap();
        assert!(groups[0].members.contains(&"node-b".to_owned()));
        assert!(validate_config(&config).is_ok());
        config["proxy-providers"]["pool"]["payload"][0]["routing-mark"] = json!(1);
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn rejects_unresolved_remote_proxy_providers_at_compile_boundary() {
        let mut config = source();
        config["proxy-providers"] = json!({"pool":{"type":"http","url":"https://provider.invalid/proxies","path":"/tmp/untrusted.yaml"}});
        config["proxy-groups"][0]["use"] = json!(["pool"]);
        let bytes = serde_json::to_vec(&config).unwrap();
        let parsed = parse_config(&bytes).unwrap();
        assert_eq!(
            parsed["proxy-providers"]["pool"]["path"],
            "/tmp/untrusted.yaml"
        );
        assert!(validate_config(&parsed).is_err());
        assert!(compile_config(&parsed, &profile(MihomoMode::Tun, None, &[])).is_err());
    }

    #[test]
    fn rejects_xray_only_profile_settings_instead_of_ignoring_them() {
        let mut p = profile(MihomoMode::Tun, None, &[]);
        p.xray_socks_port = Some(1080);
        assert!(compile_config(&source(), &p).is_err());
    }
}
