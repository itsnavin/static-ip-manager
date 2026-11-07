use crate::model::{Config, Mode};
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue {
    pub field: &'static str,
    pub severity: Severity,
    pub message: String,
}

fn err(field: &'static str, m: impl Into<String>) -> Issue {
    Issue { field, severity: Severity::Error, message: m.into() }
}
fn warn(field: &'static str, m: impl Into<String>) -> Issue {
    Issue { field, severity: Severity::Warning, message: m.into() }
}

/// Raw text as typed in the form.
#[derive(Clone, Debug, Default)]
pub struct FormInput {
    pub address: String,
    /// Prefix length ("24", "/24") or dotted netmask ("255.255.255.0").
    pub mask: String,
    pub gateway: String,
    /// Comma, space or semicolon separated.
    pub dns: String,
}

pub fn parse_ipv4(s: &str) -> Option<Ipv4Addr> {
    let s = s.trim();
    // Reject leading zeros ("010.0.0.1") which are ambiguous (octal in some tools).
    if s.split('.').any(|p| p.len() > 1 && p.starts_with('0')) {
        return None;
    }
    s.parse().ok()
}

pub fn netmask_to_prefix(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let ones = bits.count_ones();
    // Contiguous ones followed by zeros only.
    if ones == 0 || bits.leading_ones() != ones { None } else { Some(ones as u8) }
}

pub fn prefix_to_netmask(prefix: u8) -> Ipv4Addr {
    if prefix == 0 { Ipv4Addr::UNSPECIFIED } else { Ipv4Addr::from(u32::MAX << (32 - prefix as u32)) }
}

pub fn parse_mask(s: &str) -> Option<u8> {
    let s = s.trim().trim_start_matches('/');
    if let Ok(p) = s.parse::<u8>() {
        return if (1..=32).contains(&p) { Some(p) } else { None };
    }
    netmask_to_prefix(parse_ipv4(s)?)
}

pub fn network_of(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(ip) & u32::from(prefix_to_netmask(prefix)))
}

pub fn broadcast_of(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(ip) | !u32::from(prefix_to_netmask(prefix)))
}

fn check_unicast(field: &'static str, ip: Ipv4Addr, issues: &mut Vec<Issue>) {
    if ip.is_unspecified() {
        issues.push(err(field, "0.0.0.0 is not a usable address"));
    } else if ip.is_loopback() {
        issues.push(err(field, "Loopback addresses (127.x.x.x) cannot be used"));
    } else if ip.is_multicast() {
        issues.push(err(field, "Multicast addresses (224.0.0.0 and above) cannot be used"));
    } else if ip.is_broadcast() {
        issues.push(err(field, "255.255.255.255 is the broadcast address"));
    } else if ip.octets()[0] >= 240 {
        issues.push(err(field, "Reserved address range (240.0.0.0 and above)"));
    }
}

/// Validate form input. Returns the Config (if no errors) and every issue found.
pub fn validate_static(input: &FormInput) -> (Option<Config>, Vec<Issue>) {
    let mut issues = Vec::new();

    let address = match parse_ipv4(&input.address) {
        Some(a) => {
            check_unicast("address", a, &mut issues);
            Some(a)
        }
        None => {
            issues.push(err("address", "Enter a valid IPv4 address such as 192.168.1.50"));
            None
        }
    };

    let prefix = match parse_mask(&input.mask) {
        Some(p) => Some(p),
        None => {
            issues.push(err(
                "mask",
                "Enter a prefix length (1-32, e.g. 24) or a contiguous netmask (e.g. 255.255.255.0)",
            ));
            None
        }
    };

    if let (Some(a), Some(p)) = (address, prefix) {
        if p <= 30 {
            if network_of(a, p) == a {
                issues.push(err("address", format!("{a} is the network address of this subnet")));
            }
            if broadcast_of(a, p) == a {
                issues.push(err("address", format!("{a} is the broadcast address of this subnet")));
            }
        } else if p == 32 {
            issues.push(warn("mask", "/32 has no room for a gateway on the same subnet"));
        }
        if a.is_link_local() {
            issues.push(warn("address", "169.254.x.x is link-local (APIPA); it will not be routable"));
        }
    }

    let gateway_text = input.gateway.trim();
    let gateway = if gateway_text.is_empty() {
        issues.push(warn("gateway", "No gateway: this adapter will not reach other networks or the internet"));
        None
    } else {
        match parse_ipv4(gateway_text) {
            None => {
                issues.push(err("gateway", "Enter a valid IPv4 gateway or leave it empty"));
                None
            }
            Some(g) => {
                check_unicast("gateway", g, &mut issues);
                if let (Some(a), Some(p)) = (address, prefix) {
                    if g == a {
                        issues.push(err("gateway", "Gateway cannot be the same as the adapter's own address"));
                    } else if network_of(g, p) != network_of(a, p) {
                        issues.push(err(
                            "gateway",
                            format!("Gateway {g} is not inside the subnet {}/{p}", network_of(a, p)),
                        ));
                    } else if p <= 30 && (g == network_of(a, p) || g == broadcast_of(a, p)) {
                        issues.push(err("gateway", "Gateway cannot be the network or broadcast address"));
                    }
                }
                Some(g)
            }
        }
    };

    let mut dns = Vec::new();
    for tok in input.dns.split(|c: char| c == ',' || c == ';' || c.is_whitespace()).filter(|t| !t.is_empty()) {
        match parse_ipv4(tok) {
            None => issues.push(err("dns", format!("'{tok}' is not a valid IPv4 DNS server"))),
            Some(d) => {
                check_unicast("dns", d, &mut issues);
                if dns.contains(&d) {
                    issues.push(warn("dns", format!("{d} is listed more than once")));
                } else {
                    dns.push(d);
                }
            }
        }
    }
    if dns.len() > 3 {
        issues.push(err("dns", "At most 3 DNS servers are supported"));
    }
    if dns.is_empty() {
        issues.push(warn("dns", "No DNS servers: names such as example.com will not resolve"));
    }

    let has_error = issues.iter().any(|i| i.severity == Severity::Error);
    let cfg = match (has_error, address, prefix) {
        (false, Some(a), Some(p)) => {
            Some(Config { mode: Mode::Static, address: Some(a), prefix: p, gateway, dns })
        }
        _ => None,
    };
    (cfg, issues)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(a: &str, m: &str, g: &str, d: &str) -> FormInput {
        FormInput { address: a.into(), mask: m.into(), gateway: g.into(), dns: d.into() }
    }
    fn errors(issues: &[Issue]) -> Vec<&'static str> {
        issues.iter().filter(|i| i.severity == Severity::Error).map(|i| i.field).collect()
    }

    #[test]
    fn valid_config() {
        let (cfg, issues) = validate_static(&form("192.168.1.50", "24", "192.168.1.1", "1.1.1.1, 8.8.8.8"));
        assert!(errors(&issues).is_empty(), "{issues:?}");
        let cfg = cfg.unwrap();
        assert_eq!(cfg.prefix, 24);
        assert_eq!(cfg.dns.len(), 2);
    }

    #[test]
    fn netmask_forms() {
        assert_eq!(parse_mask("255.255.255.0"), Some(24));
        assert_eq!(parse_mask("/16"), Some(16));
        assert_eq!(parse_mask("255.0.255.0"), None);
        assert_eq!(parse_mask("0.0.0.0"), None);
        assert_eq!(parse_mask("33"), None);
        assert_eq!(parse_mask("0"), None);
        assert_eq!(prefix_to_netmask(20), Ipv4Addr::new(255, 255, 240, 0));
    }

    #[test]
    fn rejects_network_and_broadcast() {
        let (_, i) = validate_static(&form("192.168.1.0", "24", "192.168.1.1", ""));
        assert_eq!(errors(&i), vec!["address"]);
        let (_, i) = validate_static(&form("192.168.1.255", "24", "192.168.1.1", ""));
        assert_eq!(errors(&i), vec!["address"]);
        // Valid host in a larger subnet that happens to end in .255
        let (c, i) = validate_static(&form("192.168.0.255", "23", "192.168.0.1", ""));
        assert!(errors(&i).is_empty() && c.is_some());
    }

    #[test]
    fn gateway_must_be_in_subnet() {
        let (c, i) = validate_static(&form("192.168.1.50", "24", "192.168.2.1", ""));
        assert!(c.is_none());
        assert_eq!(errors(&i), vec!["gateway"]);
        let (_, i) = validate_static(&form("192.168.1.50", "24", "192.168.1.50", ""));
        assert_eq!(errors(&i), vec!["gateway"]);
        let (_, i) = validate_static(&form("192.168.1.50", "24", "192.168.1.255", ""));
        assert_eq!(errors(&i), vec!["gateway"]);
    }

    #[test]
    fn rejects_special_addresses_and_bad_text() {
        for bad in ["0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255", "256.1.1.1", "1.2.3", "010.0.0.5", "abc", ""] {
            let (c, i) = validate_static(&form(bad, "24", "", ""));
            assert!(c.is_none(), "{bad} should be rejected");
            assert!(errors(&i).contains(&"address"), "{bad}");
        }
    }

    #[test]
    fn dns_rules() {
        let (_, i) = validate_static(&form("10.0.0.5", "8", "10.0.0.1", "1.1.1.1 nope"));
        assert_eq!(errors(&i), vec!["dns"]);
        let (_, i) = validate_static(&form("10.0.0.5", "8", "10.0.0.1", "1.1.1.1,8.8.8.8,9.9.9.9,4.4.4.4"));
        assert_eq!(errors(&i), vec!["dns"]);
        let (c, i) = validate_static(&form("10.0.0.5", "8", "10.0.0.1", "1.1.1.1,1.1.1.1"));
        assert_eq!(c.unwrap().dns.len(), 1);
        assert!(i.iter().any(|x| x.severity == Severity::Warning && x.field == "dns"));
    }

    #[test]
    fn slash_31_has_no_network_broadcast_restriction() {
        let (c, i) = validate_static(&form("10.0.0.0", "31", "10.0.0.1", "1.1.1.1"));
        assert!(errors(&i).is_empty(), "{i:?}");
        assert!(c.is_some());
    }
}
