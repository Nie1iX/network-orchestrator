//! Canonical ordered routing layers and the one-way legacy profile migration.
use crate::models::{
    DomainPolicy, DomainRouteTarget, PinnedRoute, RoutingLayer, RoutingPolicy, RoutingRule,
    RoutingTarget, XrayInterfaceRoute, XrayTrafficRule,
};
use std::collections::HashSet;
use std::io;

impl RoutingPolicy {
    pub fn iter(&self) -> impl Iterator<Item = &RoutingRule> {
        self.user.iter().chain(&self.base)
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut RoutingRule> {
        self.user.iter_mut().chain(&mut self.base)
    }

    pub fn layer(&self, layer: RoutingLayer) -> &[RoutingRule] {
        match layer {
            RoutingLayer::Base => &self.base,
            RoutingLayer::User => &self.user,
        }
    }

    pub fn layer_mut(&mut self, layer: RoutingLayer) -> &mut Vec<RoutingRule> {
        match layer {
            RoutingLayer::Base => &mut self.base,
            RoutingLayer::User => &mut self.user,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.base.is_empty() && self.user.is_empty()
    }

    /// User IP/proxy decisions and explicit nodes in either layer require protected DNS.
    pub fn protects_dns(&self) -> bool {
        let effective = |rule: &RoutingRule| {
            rule.selectors.iter().any(|selector| {
                let selector = selector.trim();
                !selector.is_empty() && !selector.starts_with('#')
            })
        };
        self.user.iter().any(|rule| {
            effective(rule)
                && (matches!(
                    rule.target,
                    RoutingTarget::Proxy | RoutingTarget::Node { .. }
                ) || rule.has_ip_selector())
        }) || self
            .base
            .iter()
            .any(|rule| effective(rule) && matches!(rule.target, RoutingTarget::Node { .. }))
    }

    /// Native import DTOs have source-defined groups; only the base is replaced.
    pub fn imported(
        policies: Vec<DomainPolicy>,
        pins: Vec<PinnedRoute>,
        traffic: Vec<XrayTrafficRule>,
        interfaces: Vec<XrayInterfaceRoute>,
    ) -> Self {
        Self {
            base: import_rules(policies, pins, traffic, interfaces),
            user: Vec::new(),
        }
    }
}

impl RoutingTarget {
    pub fn endpoint_key(&self) -> Option<&str> {
        match self {
            Self::Node { endpoint_key, .. } => Some(endpoint_key),
            _ => None,
        }
    }
}

impl From<DomainRouteTarget> for RoutingTarget {
    fn from(value: DomainRouteTarget) -> Self {
        match value {
            DomainRouteTarget::Proxy => Self::Proxy,
            DomainRouteTarget::Direct => Self::Direct,
            DomainRouteTarget::Block => Self::Block,
        }
    }
}

impl From<DomainPolicy> for RoutingRule {
    fn from(value: DomainPolicy) -> Self {
        Self {
            selectors: value.domains,
            target: value.target.into(),
            ..Self::default()
        }
    }
}

impl From<PinnedRoute> for RoutingRule {
    fn from(value: PinnedRoute) -> Self {
        Self {
            selectors: value.selectors,
            target: RoutingTarget::Node {
                endpoint_key: value.endpoint_key,
                missing: value.missing,
            },
            ..Self::default()
        }
    }
}

impl From<XrayInterfaceRoute> for RoutingRule {
    fn from(value: XrayInterfaceRoute) -> Self {
        Self {
            selectors: value.selectors,
            target: RoutingTarget::Interface {
                interface_name: value.interface_name,
                domain_strategy: value.domain_strategy,
            },
            ..Self::default()
        }
    }
}

impl From<XrayTrafficRule> for RoutingRule {
    fn from(value: XrayTrafficRule) -> Self {
        Self {
            selectors: value.ips,
            target: value.target.into(),
            port: Some(value.port),
            network: Some(value.network),
        }
    }
}

fn import_rules(
    policies: Vec<DomainPolicy>,
    pins: Vec<PinnedRoute>,
    traffic: Vec<XrayTrafficRule>,
    interfaces: Vec<XrayInterfaceRoute>,
) -> Vec<RoutingRule> {
    let has_pins = !pins.is_empty();
    let mut rules: Vec<RoutingRule> = traffic.into_iter().map(Into::into).collect();
    let mut remaining = Vec::with_capacity(policies.len());
    for mut policy in policies {
        if has_pins {
            let explicit: Vec<_> = policy
                .domains
                .extract_if(.., |selector| {
                    let selector = selector.trim();
                    selector.starts_with("domain:") || selector.starts_with("full:")
                })
                .collect();
            if !explicit.is_empty() {
                rules.push(
                    DomainPolicy {
                        domains: explicit,
                        target: policy.target,
                    }
                    .into(),
                );
            }
        }
        if !policy.domains.is_empty() {
            remaining.push(policy.into());
        }
    }
    rules.extend(pins.into_iter().map(RoutingRule::from));
    rules.extend(interfaces.into_iter().map(RoutingRule::from));
    rules.extend(remaining);
    rules
}

pub fn validate(policy: &RoutingPolicy) -> io::Result<()> {
    let invalid = |message| io::Error::new(io::ErrorKind::InvalidInput, message);
    let mut nodes = HashSet::new();
    let mut interfaces = HashSet::new();
    for rule in policy.iter() {
        if rule.selectors.is_empty()
            || rule.port == Some(0)
            || rule
                .network
                .as_deref()
                .is_some_and(|n| !matches!(n, "tcp" | "udp" | "tcp,udp"))
        {
            return Err(invalid("invalid routing rule conditions"));
        }
        for selector in &rule.selectors {
            if selector.trim().is_empty() {
                return Err(invalid("routing selectors must not be blank"));
            }
            crate::xray::classify_routing_selector(selector)?;
        }
        match &rule.target {
            RoutingTarget::Node { endpoint_key, .. } => {
                if !crate::subscription::valid_endpoint_key(endpoint_key)
                    || rule.selectors.len() > 128
                {
                    return Err(invalid("invalid routing node rule"));
                }
                nodes.insert(endpoint_key.as_str());
            }
            RoutingTarget::Interface {
                interface_name,
                domain_strategy,
            } => {
                if interface_name.is_empty()
                    || interface_name.len() > 15
                    || interface_name.starts_with('-')
                    || rule.selectors.len() > 128
                    || !interface_name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
                {
                    return Err(invalid("invalid routing interface rule"));
                }
                crate::xray::validate_outbound_domain_strategy(domain_strategy.as_deref())?;
                interfaces.insert((interface_name.as_str(), domain_strategy.as_deref()));
            }
            _ => {}
        }
    }
    if nodes.len() > 32 || interfaces.len() > 16 {
        return Err(invalid("too many routing node or interface targets"));
    }
    Ok(())
}

pub(crate) mod profile_serde {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_json::{Map, Value};

    const LEGACY_FIELDS: [&str; 4] = [
        "domainPolicies",
        "pinnedPolicies",
        "xrayTrafficRules",
        "xrayInterfaceRoutes",
    ];

    pub fn serialize<S: Serializer>(
        policy: &RoutingPolicy,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct View<'a> {
            routing: &'a RoutingPolicy,
        }
        View { routing: policy }.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<RoutingPolicy, D::Error> {
        let mut fields = Map::<String, Value>::deserialize(deserializer)?;
        if let Some(value) = fields.remove("routing") {
            if LEGACY_FIELDS
                .iter()
                .any(|field| fields.contains_key(*field))
            {
                return Err(serde::de::Error::custom(
                    "mixed legacy and layered routing fields",
                ));
            }
            return serde_json::from_value(value)
                .map_err(|_| serde::de::Error::custom("invalid routing layers"));
        }
        fn take<T: serde::de::DeserializeOwned>(
            fields: &mut Map<String, Value>,
            key: &str,
        ) -> Result<Vec<T>, ()> {
            fields.remove(key).map_or(Ok(Vec::new()), |value| {
                serde_json::from_value(value).map_err(|_| ())
            })
        }
        let policies = take(&mut fields, "domainPolicies")
            .map_err(|_| serde::de::Error::custom("invalid legacy routing"))?;
        let pins = take(&mut fields, "pinnedPolicies")
            .map_err(|_| serde::de::Error::custom("invalid legacy routing"))?;
        let traffic = take(&mut fields, "xrayTrafficRules")
            .map_err(|_| serde::de::Error::custom("invalid legacy routing"))?;
        let interfaces = take(&mut fields, "xrayInterfaceRoutes")
            .map_err(|_| serde::de::Error::custom("invalid legacy routing"))?;
        let mut policy = RoutingPolicy::default();
        for mut rule in import_rules(policies, pins, traffic, interfaces) {
            let geo: Vec<_> = rule
                .selectors
                .extract_if(.., |selector| {
                    let selector = selector.trim();
                    selector.starts_with("geoip:") || selector.starts_with("geosite:")
                })
                .collect();
            if !geo.is_empty() {
                if rule.selectors.is_empty() {
                    rule.selectors = geo;
                    policy.base.push(rule);
                    continue;
                }
                policy.base.push(RoutingRule {
                    selectors: geo,
                    target: rule.target.clone(),
                    port: rule.port,
                    network: rule.network.clone(),
                });
            }
            if !rule.selectors.is_empty() {
                policy.user.push(rule);
            }
        }
        Ok(policy)
    }
}
