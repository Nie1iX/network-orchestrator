use ipnet::IpNet;
use std::io;

pub fn parse_bulk_cidrs(input: &str) -> io::Result<Vec<IpNet>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid bulk CIDR input");
    if input.len() > 1024 * 1024 {
        return Err(invalid());
    }
    let mut networks = Vec::new();
    for line in input.lines() {
        let content = line.split('#').next().unwrap_or("");
        for token in content
            .split(|character: char| character.is_whitespace() || matches!(character, ',' | ';'))
        {
            if token.is_empty() {
                continue;
            }
            let network = token.parse::<IpNet>().map_err(|_| invalid())?;
            networks.push(network.trunc());
        }
    }
    let aggregated = IpNet::aggregate(&networks);
    if aggregated.len() > crate::daemon_protocol::MAX_ROUTES_PER_REQUEST {
        return Err(invalid());
    }
    Ok(aggregated)
}

/// Routes of a static-route profile: bulk CIDRs, aggregated as usual, plus
/// lines of the form `10.1.0.0/16 via 10.0.0.1` that keep their own gateway
/// (those are never merged with others).
pub fn parse_static_routes(
    input: &str,
    metric: u32,
) -> io::Result<Vec<crate::models::PolicyRoute>> {
    use crate::models::PolicyRoute;
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid route input");
    let mut plain = String::new();
    let mut gateways: Vec<PolicyRoute> = Vec::new();
    for line in input.lines() {
        let content = line.split('#').next().unwrap_or("").trim();
        let words: Vec<&str> = content.split_whitespace().collect();
        if words.contains(&"via") {
            let [network, "via", gateway] = words[..] else {
                return Err(invalid());
            };
            let route = PolicyRoute {
                destination: network.parse::<IpNet>().map_err(|_| invalid())?.trunc(),
                metric,
                via: Some(gateway.parse().map_err(|_| invalid())?),
            };
            if !gateways.contains(&route) {
                gateways.push(route);
            }
        } else {
            plain.push_str(content);
            plain.push('\n');
        }
    }
    let mut routes: Vec<PolicyRoute> = parse_bulk_cidrs(&plain)?
        .into_iter()
        .map(|destination| PolicyRoute {
            destination,
            metric,
            via: None,
        })
        .collect();
    routes.extend(gateways);
    if routes.len() > crate::daemon_protocol::MAX_ROUTES_PER_REQUEST {
        return Err(invalid());
    }
    Ok(routes)
}

#[cfg(test)]
mod tests {
    use super::{parse_bulk_cidrs, parse_static_routes};
    use std::io::ErrorKind;

    #[test]
    fn aggregates_duplicate_adjacent_ipv4_and_ipv6_networks() {
        let routes = parse_bulk_cidrs(
            "10.0.0.0/25, 10.0.0.128/25\n10.0.0.0/25\n2001:db8::/33\n2001:db8:8000::/33",
        )
        .unwrap();
        assert_eq!(
            routes,
            [
                "10.0.0.0/24".parse().unwrap(),
                "2001:db8::/32".parse().unwrap()
            ]
        );
    }

    #[test]
    fn accepts_comment_lines_but_rejects_invalid_tokens_atomically() {
        let routes = parse_bulk_cidrs("# office\n10.0.0.0/8 # local\n2001:db8::/32").unwrap();
        assert_eq!(routes.len(), 2);
        let error = parse_bulk_cidrs("10.0.0.0/8\nnot-a-cidr").unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(!error.to_string().contains("not-a-cidr"));
    }

    #[test]
    fn bounds_pasted_input() {
        let input = "x".repeat(1024 * 1024 + 1);
        assert_eq!(
            parse_bulk_cidrs(&input).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn static_routes_keep_their_own_gateway_and_aggregate_the_rest() {
        let routes = parse_static_routes(
            "10.0.0.0/25, 10.0.0.128/25  # merged\n192.0.2.0/24 via 10.9.0.1\n192.0.2.0/24 via 10.9.0.1\n198.51.100.0/24 via 10.9.0.2",
            5,
        )
        .unwrap();
        let shown: Vec<_> = routes
            .iter()
            .map(|r| {
                (
                    r.destination.to_string(),
                    r.via.map(|v| v.to_string()),
                    r.metric,
                )
            })
            .collect();
        assert_eq!(
            shown,
            [
                ("10.0.0.0/24".to_string(), None, 5),
                ("192.0.2.0/24".to_string(), Some("10.9.0.1".to_string()), 5),
                (
                    "198.51.100.0/24".to_string(),
                    Some("10.9.0.2".to_string()),
                    5
                ),
            ]
        );
    }

    #[test]
    fn malformed_static_routes_are_refused() {
        for bad in [
            "10.0.0.0/8 via",
            "10.0.0.0/8 via nope",
            "10.0.0.0/8 via 10.0.0.1 extra",
            "nope via 10.0.0.1",
            "10.0.0.0/8 through 10.0.0.1",
        ] {
            assert!(parse_static_routes(bad, 5).is_err(), "{bad}");
        }
        assert!(parse_static_routes("", 5).unwrap().is_empty());
    }
}
