use crate::model::Adapter;

/// Warnings about changing an adapter the user may currently depend on.
/// `env` is injected so this is testable without touching the real environment.
pub fn warnings(adapter: &Adapter, env: &dyn Fn(&str) -> Option<String>) -> Vec<String> {
    let mut w = Vec::new();
    if adapter.gateway.is_some() {
        w.push(format!(
            "'{}' carries the default route. Changing it can cut off internet and remote access.",
            adapter.name
        ));
    }
    let ssh = env("SSH_CONNECTION").or_else(|| env("SSH_CLIENT"));
    if let Some(conn) = ssh {
        // SSH_CONNECTION: client_ip client_port server_ip server_port
        let server_ip = conn.split_whitespace().nth(2).and_then(crate::validate::parse_ipv4);
        match server_ip {
            Some(ip) if adapter.addresses.iter().any(|(a, _)| *a == ip) => w.push(format!(
                "This session is connected over SSH through {ip}, which belongs to '{}'. Changing this address will drop your connection.",
                adapter.name
            )),
            _ => w.push("This machine is being used over SSH; make sure you are not changing the adapter carrying that session.".into()),
        }
    }
    if env("SESSIONNAME").map(|s| s.to_ascii_uppercase().starts_with("RDP")).unwrap_or(false) {
        w.push("You appear to be in a Remote Desktop session. Changing the active adapter can disconnect you.".into());
    }
    if !adapter.up {
        w.push(format!("'{}' is not connected; the new settings will take effect once it is.", adapter.name));
    }
    w
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Mode;
    use std::net::Ipv4Addr;

    fn adapter(gw: bool) -> Adapter {
        Adapter {
            name: "eth0".into(),
            index: None,
            mac: String::new(),
            up: true,
            mode: Mode::Static,
            addresses: vec![(Ipv4Addr::new(192, 168, 1, 20), 24)],
            gateway: gw.then(|| Ipv4Addr::new(192, 168, 1, 1)),
            dns: vec![],
            ipv6: vec![],
        }
    }

    #[test]
    fn default_route_warning() {
        let w = warnings(&adapter(true), &|_| None);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("default route"));
        assert!(warnings(&adapter(false), &|_| None).is_empty());
    }

    #[test]
    fn ssh_on_same_adapter() {
        let env = |k: &str| (k == "SSH_CONNECTION").then(|| "10.0.0.2 5000 192.168.1.20 22".to_string());
        let w = warnings(&adapter(false), &env);
        assert!(w.iter().any(|m| m.contains("drop your connection")));
        let env = |k: &str| (k == "SSH_CONNECTION").then(|| "10.0.0.2 5000 172.16.0.5 22".to_string());
        assert!(warnings(&adapter(false), &env).iter().any(|m| m.contains("used over SSH")));
    }

    #[test]
    fn rdp_and_down() {
        let env = |k: &str| (k == "SESSIONNAME").then(|| "RDP-Tcp#3".to_string());
        assert!(warnings(&adapter(false), &env).iter().any(|m| m.contains("Remote Desktop")));
        let mut a = adapter(false);
        a.up = false;
        assert!(warnings(&a, &|_| None).iter().any(|m| m.contains("not connected")));
    }
}
