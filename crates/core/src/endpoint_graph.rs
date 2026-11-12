use super::*;

#[derive(Clone, PartialEq)]
pub struct EndpointGraph {
    pub entry: Value,
    pub outbounds: Vec<Value>,
    pub rules: Vec<Value>,
    pub balancers: Vec<Value>,
    pub observatory: Option<Value>,
    pub burst_observatory: Option<Value>,
}
impl std::fmt::Debug for EndpointGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointGraph")
            .field("entry_tag", &self.entry["tag"].as_str())
            .field("outbounds", &self.outbounds.len())
            .field("rules", &self.rules.len())
            .field("balancers", &self.balancers.len())
            .field("observatory", &self.observatory.is_some())
            .field("burst_observatory", &self.burst_observatory.is_some())
            .finish()
    }
}

impl EndpointGraph {
    fn simple(entry: Value) -> Self {
        Self {
            entry,
            outbounds: Vec::new(),
            rules: Vec::new(),
            balancers: Vec::new(),
            observatory: None,
            burst_observatory: None,
        }
    }
}

fn bad() -> &'static str {
    "Unsupported or ambiguous provider endpoint graph"
}

fn clean_outbound(source: &Value, tag: &str) -> Result<Value, &'static str> {
    let protocol = source["protocol"].as_str().ok_or_else(bad)?;
    if let Some(stream) = source.get("streamSettings") {
        let allowed = [
            "network",
            "security",
            "wsSettings",
            "grpcSettings",
            "xhttpSettings",
            "httpupgradeSettings",
            "tlsSettings",
            "realitySettings",
            "tcpSettings",
            "hysteriaSettings",
            "finalmask",
            "sockopt",
        ];
        if stream
            .as_object()
            .is_none_or(|map| map.keys().any(|key| !allowed.contains(&key.as_str())))
        {
            return Err(bad());
        }
    }
    let mut result = match protocol {
        "vless" => {
            let servers = source["settings"]["vnext"].as_array().ok_or_else(bad)?;
            if servers.len() != 1 {
                return Err(bad());
            }
            let server = &servers[0];
            let users = server["users"].as_array().ok_or_else(bad)?;
            if users.len() != 1 {
                return Err(bad());
            }
            json!({"tag":tag,"protocol":"vless", "settings":{"vnext":[{"address":server["address"],"port":server["port"],"users":[keep_keys(&users[0], &["id","encryption","flow"])]}]},"streamSettings":tun_stream_settings(&source["streamSettings"], false)})
        }
        "hysteria" => {
            json!({"tag":tag,"protocol":"hysteria", "settings":keep_keys(&source["settings"], &["version","address","port"]), "streamSettings":tun_stream_settings(&source["streamSettings"], true)})
        }
        "freedom" => {
            let allowed = [
                "fragment",
                "domainStrategy",
                "redirect",
                "timeout",
                "userLevel",
            ];
            if let Some(settings) = source.get("settings") {
                if settings
                    .as_object()
                    .is_none_or(|map| map.keys().any(|key| !allowed.contains(&key.as_str())))
                {
                    return Err(bad());
                }
            }
            json!({"tag":tag,"protocol":"freedom", "settings":keep_keys(&source["settings"], &allowed)})
        }
        "blackhole" => json!({"tag":tag,"protocol":"blackhole"}),
        _ => return Err(bad()),
    };
    if let Some(mux) = source.get("mux") {
        result["mux"] = tun_mux(mux);
    }
    if let Some(proxy) = source.get("proxySettings") {
        if proxy
            .as_object()
            .is_none_or(|o| o.keys().any(|k| k != "tag" && k != "transportLayer"))
            || proxy["tag"].as_str().is_none()
        {
            return Err(bad());
        }
        result["proxySettings"] = proxy.clone();
    }
    if let Some(sockopt) = source["streamSettings"].get("sockopt") {
        if !sockopt.is_object() {
            return Err(bad());
        }
        let clean = keep_keys(
            sockopt,
            &[
                "dialerProxy",
                "domainStrategy",
                "tcpFastOpen",
                "tcpKeepAliveInterval",
                "tcpKeepAliveIdle",
                "tcpUserTimeout",
                "tcpcongestion",
                "V6Only",
                "tcpWindowClamp",
                "tcpMptcp",
                "tcpNoDelay",
            ],
        );
        if clean["dialerProxy"].as_str().is_none() && clean.get("dialerProxy").is_some() {
            return Err(bad());
        }
        if !clean.as_object().is_some_and(Map::is_empty) {
            result["streamSettings"]["sockopt"] = clean;
        }
    }
    Ok(result)
}

fn exact_scope(scope: &str) -> bool {
    !scope.is_empty()
        && scope.len() <= 64
        && scope
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub(super) fn source_graph(base: &Value, scope: &str) -> Result<EndpointGraph, &'static str> {
    if base
        .get("observatory")
        .is_some_and(|value| !value.is_null())
        && base
            .get("burstObservatory")
            .is_some_and(|value| !value.is_null())
    {
        return Err(bad());
    }
    if !exact_scope(scope) {
        return Err(bad());
    }
    let source = base["outbounds"].as_array().ok_or_else(bad)?;
    if source.len() > 4096 {
        return Err(bad());
    }
    let mut by_tag = HashMap::new();
    for (i, outbound) in source.iter().enumerate() {
        if let Some(tag) = outbound["tag"].as_str() {
            if tag.is_empty() || by_tag.insert(tag, i).is_some() {
                return Err(bad());
            }
        }
    }
    let routing = &base["routing"];
    if routing
        .get("script")
        .is_some_and(|value| !value.is_null() && value.as_str() != Some(""))
    {
        return Err(bad());
    }
    let balancers = routing["balancers"].as_array().cloned().unwrap_or_default();
    if balancers.len() > 4096 {
        return Err(bad());
    }
    let empty_rules = Vec::new();
    let rules = match routing.get("rules") {
        None => &empty_rules,
        Some(rules) => rules.as_array().ok_or_else(bad)?,
    };
    let defaults: Vec<_> = rules
        .iter()
        .filter(|rule| {
            rule.as_object().is_some_and(|o| {
                o.keys().all(|key| {
                    matches!(
                        key.as_str(),
                        "type" | "network" | "outboundTag" | "balancerTag"
                    )
                })
            }) && rule["type"] == "field"
                && (rule.get("network").is_none()
                    || rule["network"] == "tcp,udp"
                    || rule["network"] == "udp,tcp")
        })
        .collect();
    if defaults.len() > 1 {
        return Err(bad());
    }
    let no_default = Value::Null;
    let default = defaults.first().copied().unwrap_or(&no_default);
    let mut roots = Vec::new();
    let mut health_subjects = Vec::new();
    let mut output_balancers = Vec::new();
    let mut aliases = Vec::new();
    let mut alias_rules = Vec::new();
    let dispatch_target;
    if let Some(tag) = default["balancerTag"].as_str() {
        if default.get("outboundTag").is_some() {
            return Err(bad());
        }
        let matches: Vec<_> = balancers
            .iter()
            .enumerate()
            .filter(|(_, b)| b["tag"] == tag)
            .collect();
        if matches.len() != 1 {
            return Err(bad());
        }
        let mut index = matches[0].0;
        dispatch_target = json!({"balancerTag":format!("src-{scope}-b-{index:04x}")});
        let mut seen = HashSet::new();
        loop {
            if !seen.insert(index) {
                return Err(bad());
            }
            let balancer = &balancers[index];
            let selectors = balancer["selector"].as_array().ok_or_else(bad)?;
            if selectors.is_empty() {
                return Err(bad());
            }
            let mut selected = Vec::new();
            for selector in selectors {
                let selector = selector
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(bad)?;
                let mut matched = false;
                for (i, outbound) in source.iter().enumerate() {
                    if outbound["tag"]
                        .as_str()
                        .is_some_and(|tag| tag.starts_with(selector))
                    {
                        if !matches!(outbound["protocol"].as_str(), Some("vless" | "hysteria")) {
                            return Err(bad());
                        }
                        matched = true;
                        if !selected.contains(&i) {
                            selected.push(i);
                        }
                    }
                }
                if !matched {
                    return Err(bad());
                }
            }
            if let Some(strategy) = balancer.get("strategy") {
                match strategy["type"].as_str() {
                    Some("leastPing" | "leastLoad") => {
                        health_subjects.extend(selected.iter().copied())
                    }
                    Some("random") => {}
                    _ => return Err(bad()),
                }
                if let Some(costs) = strategy["settings"].get("costs") {
                    if costs.as_array().is_none_or(|items| !items.is_empty()) {
                        return Err(bad());
                    }
                }
            }
            roots.extend(selected.iter().copied());
            let mut clean = keep_keys(balancer, &["strategy"]);
            clean["tag"] = json!(format!("src-{scope}-b-{index:04x}"));
            clean["selector"] = json!(selected
                .iter()
                .map(|i| format!("src-{scope}-o-{i:04x}"))
                .collect::<Vec<_>>());
            let mut next = None;
            if let Some(fallback) = balancer.get("fallbackTag") {
                let tag = fallback.as_str().ok_or_else(bad)?;
                if let Some(&i) = by_tag.get(tag) {
                    if !matches!(
                        source[i]["protocol"].as_str(),
                        Some("vless" | "hysteria" | "blackhole")
                    ) {
                        return Err(bad());
                    }
                    roots.push(i);
                    clean["fallbackTag"] = json!(format!("src-{scope}-o-{i:04x}"));
                } else {
                    let matches: Vec<_> = balancers
                        .iter()
                        .enumerate()
                        .filter(|(_, b)| b["tag"] == tag)
                        .collect();
                    if matches.len() > 1 {
                        return Err(bad());
                    }
                    if let Some((target, _)) = matches.first() {
                        let alias_index = source.len() + index;
                        let alias = format!("src-{scope}-o-{alias_index:04x}");
                        let inbound = format!("src-{scope}-in-{alias_index:04x}");
                        aliases.push(json!({"tag":alias,"protocol":"loopback","settings":{"inboundTag":inbound}}));
                        alias_rules.push(json!({"type":"field","inboundTag":[inbound],"balancerTag":format!("src-{scope}-b-{target:04x}")}));
                        clean["fallbackTag"] = json!(alias);
                        next = Some(*target);
                    }
                }
            }
            if clean.get("fallbackTag").is_none() {
                let tag = format!(
                    "src-{scope}-o-{:04x}",
                    source.len() + balancers.len() + index
                );
                aliases.push(json!({"tag":tag,"protocol":"blackhole"}));
                clean["fallbackTag"] = json!(tag);
            }
            output_balancers.push(clean);
            match next {
                Some(target) => index = target,
                None => break,
            }
        }
    } else if let Some(tag) = default["outboundTag"].as_str() {
        let i = *by_tag.get(tag).ok_or_else(bad)?;
        if !matches!(source[i]["protocol"].as_str(), Some("vless" | "hysteria")) {
            return Err(bad());
        }
        roots.push(i);
        dispatch_target = json!({"outboundTag":format!("src-{scope}-o-{i:04x}")});
    } else if defaults.is_empty()
        && source.first().is_some_and(|outbound| {
            matches!(outbound["protocol"].as_str(), Some("vless" | "hysteria"))
        })
    {
        roots.push(0);
        dispatch_target = json!({"outboundTag":format!("src-{scope}-o-0000")});
    } else {
        return Err(bad());
    }

    fn visit(
        i: usize,
        source: &[Value],
        by_tag: &HashMap<&str, usize>,
        state: &mut [u8],
        order: &mut Vec<usize>,
        depth: usize,
    ) -> Result<(), &'static str> {
        if depth > 64 || state[i] == 1 {
            return Err(bad());
        }
        if state[i] == 2 {
            return Ok(());
        }
        state[i] = 1;
        for reference in [
            source[i]["proxySettings"].get("tag"),
            source[i]["streamSettings"]["sockopt"].get("dialerProxy"),
        ]
        .into_iter()
        .flatten()
        {
            let tag = reference.as_str().ok_or_else(bad)?;
            let next = *by_tag.get(tag).ok_or_else(bad)?;
            visit(next, source, by_tag, state, order, depth + 1)?;
        }
        state[i] = 2;
        order.push(i);
        Ok(())
    }
    let mut state = vec![0; source.len()];
    let mut order = Vec::new();
    for i in roots {
        visit(i, source, &by_tag, &mut state, &mut order, 0)?;
    }
    order.sort_unstable();
    let mut outbounds = Vec::new();
    for &i in &order {
        let mut outbound = clean_outbound(&source[i], &format!("src-{scope}-o-{i:04x}"))?;
        if let Some(tag) = source[i]["proxySettings"]["tag"].as_str() {
            outbound["proxySettings"]["tag"] = json!(format!("src-{scope}-o-{:04x}", by_tag[tag]));
        }
        if let Some(tag) = source[i]["streamSettings"]["sockopt"]["dialerProxy"].as_str() {
            outbound["streamSettings"]["sockopt"]["dialerProxy"] =
                json!(format!("src-{scope}-o-{:04x}", by_tag[tag]));
        }
        outbounds.push(outbound);
    }
    outbounds.extend(aliases);
    let observation = |key: &str| -> Result<Option<Value>, &'static str> {
        let Some(value) = base.get(key).filter(|value| !value.is_null()) else {
            return Ok(None);
        };
        let selectors = value["subjectSelector"].as_array().ok_or_else(bad)?;
        let mut subjects = Vec::new();
        for selector in selectors {
            let selector = selector
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or_else(bad)?;
            for &i in &order {
                if matches!(source[i]["protocol"].as_str(), Some("vless" | "hysteria"))
                    && source[i]["tag"]
                        .as_str()
                        .is_some_and(|tag| tag.starts_with(selector))
                {
                    let tag = format!("src-{scope}-o-{i:04x}");
                    if !subjects.contains(&tag) {
                        subjects.push(tag);
                    }
                }
            }
        }
        if subjects.is_empty() {
            return Ok(None);
        }
        let mut result = value.clone();
        result["subjectSelector"] = json!(subjects);
        Ok(Some(result))
    };
    let inbound = format!("src-{scope}-in");
    let mut rule = json!({"type":"field", "inboundTag":[inbound]});
    for (key, value) in dispatch_target.as_object().ok_or_else(bad)? {
        rule[key] = value.clone();
    }
    let mut rules = vec![rule];
    rules.extend(alias_rules);
    let observatory = observation("observatory")?;
    let burst_observatory = observation("burstObservatory")?;
    for index in health_subjects {
        let tag = format!("src-{scope}-o-{index:04x}");
        let observed = [&observatory, &burst_observatory]
            .into_iter()
            .flatten()
            .any(|observation| {
                observation["subjectSelector"]
                    .as_array()
                    .is_some_and(|subjects| {
                        subjects
                            .iter()
                            .any(|subject| subject.as_str() == Some(tag.as_str()))
                    })
            });
        if !observed {
            return Err(bad());
        }
    }
    let mut observation_config = json!({});
    if let Some(value) = &observatory {
        observation_config["observatory"] = value.clone();
    }
    if let Some(value) = &burst_observatory {
        observation_config["burstObservatory"] = value.clone();
    }
    crate::subscription::observation_startup(&observation_config).map_err(|_| bad())?;
    Ok(EndpointGraph {
        entry: json!({"tag":scope,"protocol":"loopback","settings":{"inboundTag":inbound}}),
        outbounds,
        rules,
        balancers: output_balancers,
        observatory,
        burst_observatory,
    })
}

pub fn multinode_endpoint(url: &str, tag: &str) -> io::Result<EndpointGraph> {
    let config = generate_share_link_config(url, 1)
        .map_err(|_| invalid_input("invalid or unsupported subscription endpoint"))?;
    if !url.trim().starts_with(XRAY_JSON_PREFIX) {
        let mut entry = config["outbounds"][0].clone();
        entry["tag"] = json!(tag);
        return Ok(EndpointGraph::simple(entry));
    }
    source_graph(&config, tag).map_err(invalid_input)
}

/// Merge an endpoint using the first source's per-process observation policy.
pub fn append_endpoint_graph(config: &mut Value, graph: &EndpointGraph) -> io::Result<()> {
    let regular = graph.observatory.is_some()
        || config
            .get("observatory")
            .is_some_and(|value| !value.is_null());
    let burst = graph.burst_observatory.is_some()
        || config
            .get("burstObservatory")
            .is_some_and(|value| !value.is_null());
    if regular && burst {
        return Err(invalid_data(
            "incompatible endpoint observation implementations",
        ));
    }
    for (key, observation) in [
        ("observatory", &graph.observatory),
        ("burstObservatory", &graph.burst_observatory),
    ] {
        if let Some(observation) = observation {
            let subjects = observation["subjectSelector"]
                .as_array()
                .ok_or_else(|| invalid_data("invalid observation subjects"))?;
            if let Some(existing) = config.get_mut(key).filter(|value| !value.is_null()) {
                let merged = existing["subjectSelector"]
                    .as_array_mut()
                    .ok_or_else(|| invalid_data("invalid observation subjects"))?;
                for subject in subjects {
                    if !merged.contains(subject) {
                        merged.push(subject.clone());
                    }
                }
            } else {
                config[key] = observation.clone();
            }
        }
    }
    let outbounds = config["outbounds"]
        .as_array_mut()
        .ok_or_else(|| invalid_data("xray config outbounds must be an array"))?;
    outbounds.push(graph.entry.clone());
    outbounds.extend(graph.outbounds.iter().cloned());
    let routing = config["routing"]
        .as_object_mut()
        .ok_or_else(|| invalid_data("xray config routing must be an object"))?;
    let rules = routing
        .entry("rules")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| invalid_data("xray rules must be an array"))?;
    rules.splice(0..0, graph.rules.iter().cloned());
    if !graph.balancers.is_empty() {
        routing
            .entry("balancers")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or_else(|| invalid_data("xray balancers must be an array"))?
            .extend(graph.balancers.iter().cloned());
    }
    Ok(())
}
