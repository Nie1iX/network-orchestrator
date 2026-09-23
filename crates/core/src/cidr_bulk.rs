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

#[cfg(test)]
mod tests {
    use super::parse_bulk_cidrs;
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
}
