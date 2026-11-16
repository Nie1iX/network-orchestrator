//! Lower ordered IP checks into native Xray conditions without treating DNS failure as a miss.
use serde_json::{json, Value};

#[derive(Default, PartialEq, Eq)]
struct Ports {
    all: bool,
    values: Vec<u16>,
}

impl Ports {
    fn add(&mut self, port: Option<u16>) {
        if self.all {
            return;
        }
        match port {
            None => {
                self.all = true;
                self.values.clear();
            }
            Some(port) => {
                if let Err(index) = self.values.binary_search(&port) {
                    self.values.insert(index, port);
                }
            }
        }
    }

    fn contains(&self, port: u16) -> bool {
        self.all || self.values.binary_search(&port).is_ok()
    }

    fn empty(&self) -> bool {
        !self.all && self.values.is_empty()
    }

    fn expressions(&self, required: bool) -> Vec<Option<String>> {
        if self.all {
            return if required { vec![None] } else { Vec::new() };
        }
        if self.values.is_empty() {
            return if required { Vec::new() } else { vec![None] };
        }
        let mut ranges = Vec::new();
        if required {
            for &port in &self.values {
                match ranges.last_mut() {
                    Some((_, end)) if u32::from(*end) + 1 == u32::from(port) => *end = port,
                    _ => ranges.push((port, port)),
                }
            }
        } else {
            let mut begin = 1u32;
            for &port in &self.values {
                let port = u32::from(port);
                if begin < port {
                    ranges.push((begin as u16, (port - 1) as u16));
                }
                begin = port + 1;
            }
            if begin <= u32::from(u16::MAX) {
                ranges.push((begin as u16, u16::MAX));
            }
        }
        let mut fields = Vec::new();
        let mut field = String::new();
        for (start, end) in ranges {
            let token = if start == end {
                start.to_string()
            } else {
                format!("{start}-{end}")
            };
            if !field.is_empty() && field.len() + token.len() + 1 > 128 {
                fields.push(Some(std::mem::take(&mut field)));
            }
            if !field.is_empty() {
                field.push(',');
            }
            field.push_str(&token);
        }
        if !field.is_empty() {
            fields.push(Some(field));
        }
        fields
    }
}

#[derive(Default)]
pub(crate) struct IpRequirements {
    tcp: Ports,
    udp: Ports,
}

struct Branch {
    network: &'static str,
    port: Option<String>,
    known_ip: bool,
}

impl IpRequirements {
    pub fn is_empty(&self) -> bool {
        self.tcp.empty() && self.udp.empty()
    }

    pub fn add(&mut self, port: Option<u16>, network: Option<&str>) {
        match network.unwrap_or("tcp,udp") {
            "tcp" => self.tcp.add(port),
            "udp" => self.udp.add(port),
            _ => {
                self.tcp.add(port);
                self.udp.add(port);
            }
        }
    }

    /// Later decisions need a known IP only where an earlier IP rule could apply.
    pub fn emit(
        &self,
        template: Value,
        port: Option<u16>,
        network: Option<&str>,
        out: &mut Vec<Value>,
    ) {
        if self.is_empty() {
            out.push(template);
            return;
        }
        let mut branches = Vec::new();
        let allowed = network.unwrap_or("tcp,udp");
        let networks: &[(&str, &Ports)] = if self.tcp == self.udp && allowed == "tcp,udp" {
            &[("tcp,udp", &self.tcp)]
        } else {
            &[("tcp", &self.tcp), ("udp", &self.udp)]
        };
        for &(protocol, ports) in networks {
            if allowed != "tcp,udp" && allowed != protocol {
                continue;
            }
            if let Some(port) = port {
                branches.push(Branch {
                    network: protocol,
                    port: None,
                    known_ip: ports.contains(port),
                });
            } else {
                for known_ip in [false, true] {
                    for port in ports.expressions(known_ip) {
                        branches.push(Branch {
                            network: protocol,
                            port,
                            known_ip,
                        });
                    }
                }
            }
        }
        let Some(last) = branches.pop() else {
            return;
        };
        let apply = |mut row: Value, branch: Branch| {
            row["network"] = json!(branch.network);
            if let Some(port) = branch.port {
                row["port"] = json!(port);
            }
            if branch.known_ip {
                row["ip"] = json!(["0.0.0.0/0", "::/0"]);
            }
            row
        };
        for branch in branches {
            out.push(apply(template.clone(), branch));
        }
        out.push(apply(template, last));
    }
}
