use crate::model::{Adapter, Backend, Config, Mode};
use crate::runner::CommandRunner;
use crate::validate::parse_ipv4;
use serde_json::Value;
use std::net::Ipv4Addr;

// ---------------------------------------------------------------- listing

pub fn parse_ip_addr_json(addr_json: &str, route_json: &str) -> Result<Vec<Adapter>, String> {
    let addrs: Value = serde_json::from_str(addr_json).map_err(|e| format!("cannot parse `ip -j addr`: {e}"))?;
    let routes: Value = if route_json.trim().is_empty() {
        Value::Array(vec![])
    } else {
        serde_json::from_str(route_json).map_err(|e| format!("cannot parse `ip -j route`: {e}"))?
    };
    let mut out = Vec::new();
    for it in addrs.as_array().into_iter().flatten() {
        let name = it.get("ifname").and_then(Value::as_str).unwrap_or("").to_string();
        let flags: Vec<&str> = it.get("flags").and_then(Value::as_array).map(|f| f.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        if name.is_empty() || name == "lo" || flags.contains(&"LOOPBACK") {
            continue;
        }
        let mut addresses = Vec::new();
        let mut ipv6 = Vec::new();
        let mut dynamic = false;
        for a in it.get("addr_info").and_then(Value::as_array).into_iter().flatten() {
            let local = a.get("local").and_then(Value::as_str).unwrap_or("");
            let plen = a.get("prefixlen").and_then(Value::as_u64).unwrap_or(0);
            match a.get("family").and_then(Value::as_str) {
                Some("inet") => {
                    if let Some(ip) = parse_ipv4(local) {
                        addresses.push((ip, plen as u8));
                        dynamic |= a.get("dynamic").and_then(Value::as_bool).unwrap_or(false);
                    }
                }
                Some("inet6") => ipv6.push(format!("{local}/{plen}")),
                _ => {}
            }
        }
        let gateway = routes
            .as_array()
            .into_iter()
            .flatten()
            .find(|r| r.get("dev").and_then(Value::as_str) == Some(name.as_str()))
            .and_then(|r| r.get("gateway").and_then(Value::as_str))
            .and_then(parse_ipv4);
        let oper = it.get("operstate").and_then(Value::as_str).unwrap_or("UNKNOWN");
        out.push(Adapter {
            name,
            index: None,
            mac: it.get("address").and_then(Value::as_str).unwrap_or("").to_string(),
            up: oper.eq_ignore_ascii_case("up") || (oper.eq_ignore_ascii_case("unknown") && flags.contains(&"UP")),
            mode: if addresses.is_empty() || dynamic { Mode::Dhcp } else { Mode::Static },
            addresses,
            gateway,
            dns: vec![],
            ipv6,
        });
    }
    Ok(out)
}

/// `resolvectl dns` lines look like `Link 2 (eth0): 192.168.1.1 8.8.8.8`.
pub fn parse_resolvectl_dns(s: &str) -> Vec<(String, Vec<Ipv4Addr>)> {
    let mut out = Vec::new();
    for line in s.lines() {
        let Some(rest) = line.trim().strip_prefix("Link ") else { continue };
        let (Some(open), Some(close)) = (rest.find('('), rest.find(')')) else { continue };
        let name = rest[open + 1..close].to_string();
        let servers = rest[close + 1..].trim_start_matches(':').split_whitespace().filter_map(parse_ipv4).collect();
        out.push((name, servers));
    }
    out
}

pub fn parse_resolv_conf(s: &str) -> Vec<Ipv4Addr> {
    s.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|v| parse_ipv4(v.trim()))
        .filter(|ip| !ip.is_loopback())
        .collect()
}

pub fn list_adapters(runner: &dyn CommandRunner, resolv_conf: Option<String>) -> Result<Vec<Adapter>, String> {
    let a = runner.run("ip", &["-j", "addr", "show"])?;
    if a.code != 0 {
        return Err(format!("`ip -j addr show` failed (needs iproute2 with JSON support): {}", a.stderr.trim()));
    }
    let r = runner.run("ip", &["-j", "route", "show", "default"]).map(|o| o.stdout).unwrap_or_default();
    let mut adapters = parse_ip_addr_json(&a.stdout, &r)?;
    let per_link = runner.run("resolvectl", &["dns"]).ok().filter(|o| o.code == 0).map(|o| parse_resolvectl_dns(&o.stdout)).unwrap_or_default();
    let global = resolv_conf.as_deref().map(parse_resolv_conf).unwrap_or_default();
    for ad in &mut adapters {
        ad.dns = per_link.iter().find(|(n, _)| *n == ad.name).map(|(_, d)| d.clone()).filter(|d| !d.is_empty()).unwrap_or_else(|| global.clone());
    }
    Ok(adapters)
}

// ---------------------------------------------------------------- backend detection

#[derive(Debug, PartialEq, Eq)]
pub struct Detection {
    pub preferred: Backend,
    pub available: Vec<Backend>,
}

pub fn detect_backend(runner: &dyn CommandRunner, path_exists: &dyn Fn(&str) -> bool) -> Option<Detection> {
    let ok = |prog: &str, args: &[&str], want: &str| {
        runner.run(prog, args).map(|o| o.stdout.trim().eq_ignore_ascii_case(want)).unwrap_or(false)
    };
    let mut available = Vec::new();
    if ok("nmcli", &["-t", "-f", "RUNNING", "general"], "running") {
        available.push(Backend::NetworkManager);
    }
    if (path_exists("/usr/sbin/netplan") || path_exists("/usr/bin/netplan")) && path_exists("/etc/netplan") {
        available.push(Backend::Netplan);
    }
    if ok("systemctl", &["is-active", "systemd-networkd"], "active") {
        available.push(Backend::SystemdNetworkd);
    }
    if ok("systemctl", &["is-active", "dhcpcd"], "active") || ok("systemctl", &["is-active", "dhcpcd5"], "active") {
        available.push(Backend::Dhcpcd);
    }
    available.first().copied().map(|preferred| Detection { preferred, available })
}

// ---------------------------------------------------------------- script generation

pub fn valid_iface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | ':'))
}

pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn dns_list(cfg: &Config) -> Vec<String> {
    cfg.dns.iter().map(|d| d.to_string()).collect()
}

fn nm_commands(cfg: &Config) -> String {
    match cfg.mode {
        Mode::Dhcp => "nmcli connection modify \"$CON\" ipv4.method auto ipv4.addresses '' ipv4.gateway '' ipv4.dns '' ipv4.ignore-auto-dns no\nnmcli connection up \"$CON\"".to_string(),
        Mode::Static => {
            let addr = format!("{}/{}", cfg.address.map(|a| a.to_string()).unwrap_or_default(), cfg.prefix);
            let gw = cfg.gateway.map(|g| g.to_string()).unwrap_or_default();
            let dns = dns_list(cfg).join(" ");
            format!(
                "nmcli connection modify \"$CON\" ipv4.method manual ipv4.addresses {addr} ipv4.gateway '{gw}' ipv4.dns '{dns}' ipv4.ignore-auto-dns {}\nnmcli connection up \"$CON\"",
                if cfg.dns.is_empty() { "no" } else { "yes" }
            )
        }
    }
}

pub fn netplan_yaml(iface: &str, cfg: &Config) -> String {
    let mut y = format!("network:\n  version: 2\n  ethernets:\n    {iface}:\n");
    match cfg.mode {
        Mode::Dhcp => y.push_str("      dhcp4: true\n"),
        Mode::Static => {
            y.push_str("      dhcp4: false\n");
            y.push_str(&format!("      addresses: [{}/{}]\n", cfg.address.map(|a| a.to_string()).unwrap_or_default(), cfg.prefix));
            if let Some(g) = cfg.gateway {
                y.push_str(&format!("      routes:\n        - to: 0.0.0.0/0\n          via: {g}\n"));
            }
            if !cfg.dns.is_empty() {
                y.push_str(&format!("      nameservers:\n        addresses: [{}]\n", dns_list(cfg).join(", ")));
            }
        }
    }
    y
}

pub fn networkd_unit(iface: &str, cfg: &Config) -> String {
    let mut u = format!("[Match]\nName={iface}\n\n[Network]\n");
    match cfg.mode {
        Mode::Dhcp => u.push_str("DHCP=ipv4\n"),
        Mode::Static => {
            u.push_str("DHCP=no\n");
            u.push_str(&format!("Address={}/{}\n", cfg.address.map(|a| a.to_string()).unwrap_or_default(), cfg.prefix));
            if let Some(g) = cfg.gateway {
                u.push_str(&format!("Gateway={g}\n"));
            }
            for d in dns_list(cfg) {
                u.push_str(&format!("DNS={d}\n"));
            }
        }
    }
    u
}

pub fn dhcpcd_block(iface: &str, cfg: &Config) -> String {
    if cfg.mode == Mode::Dhcp {
        return String::new();
    }
    let mut b = format!("# BEGIN static-ip-manager {iface}\ninterface {iface}\nstatic ip_address={}/{}\n", cfg.address.map(|a| a.to_string()).unwrap_or_default(), cfg.prefix);
    if let Some(g) = cfg.gateway {
        b.push_str(&format!("static routers={g}\n"));
    }
    if !cfg.dns.is_empty() {
        b.push_str(&format!("static domain_name_servers={}\n", dns_list(cfg).join(" ")));
    }
    b.push_str(&format!("# END static-ip-manager {iface}\n"));
    b
}

pub fn netplan_path(iface: &str) -> String {
    format!("/etc/netplan/90-static-ip-manager-{iface}.yaml")
}
pub fn networkd_path(iface: &str) -> String {
    format!("/etc/systemd/network/05-static-ip-manager-{iface}.network")
}

/// Returns (setup, apply, revert) shell fragments for a backend. `previous` is the
/// snapshot taken from the GUI before applying; file backends restore the real backup file.
fn fragments(backend: Backend, iface: &str, new: &Config, previous: &Config) -> Result<(String, String, String), String> {
    if !valid_iface(iface) {
        return Err(format!("unsafe interface name '{iface}'"));
    }
    match backend {
        Backend::NetworkManager => {
            let setup = format!(
                "CON=$(nmcli -g GENERAL.CONNECTION device show {i} 2>/dev/null)\n[ -n \"$CON\" ] || {{ log 'failed: no active NetworkManager connection on {iface}; connect it first'; exit 1; }}\nmkdir -p \"$BK\" && nmcli -t connection show \"$CON\" > \"$BK/nmcli-connection.txt\" 2>/dev/null",
                i = sh_quote(iface)
            );
            Ok((setup, nm_commands(new), nm_commands(previous)))
        }
        Backend::Netplan => {
            let f = sh_quote(&netplan_path(iface));
            let yaml = sh_quote(&netplan_yaml(iface, new));
            let setup = format!("mkdir -p \"$BK\"\nHAD=0; [ -e {f} ] && {{ cp -p {f} \"$BK/netplan.yaml\" && HAD=1; }}"); 
            let apply = format!("umask 077\nprintf '%s' {yaml} > {f}\nnetplan generate\nnetplan apply");
            let revert = format!("if [ \"$HAD\" = 1 ]; then cp -p \"$BK/netplan.yaml\" {f}; else rm -f {f}; fi\nnetplan apply");
            Ok((setup, apply, revert))
        }
        Backend::SystemdNetworkd => {
            let f = sh_quote(&networkd_path(iface));
            let unit = sh_quote(&networkd_unit(iface, new));
            let reload = format!("networkctl reload\nnetworkctl reconfigure {i} || systemctl restart systemd-networkd", i = sh_quote(iface));
            let setup = format!("mkdir -p \"$BK\"\nHAD=0; [ -e {f} ] && {{ cp -p {f} \"$BK/unit.network\" && HAD=1; }}");
            let apply = format!("printf '%s' {unit} > {f}\n{reload}");
            let revert = format!("if [ \"$HAD\" = 1 ]; then cp -p \"$BK/unit.network\" {f}; else rm -f {f}; fi\n{reload}");
            Ok((setup, apply, revert))
        }
        Backend::Dhcpcd => {
            let f = "/etc/dhcpcd.conf";
            let strip = format!("sed -i '/^# BEGIN static-ip-manager {iface}$/,/^# END static-ip-manager {iface}$/d' {f}");
            let block = dhcpcd_block(iface, new);
            let restart = "systemctl restart dhcpcd || systemctl restart dhcpcd5";
            let setup = format!("mkdir -p \"$BK\"\ncp -p {f} \"$BK/dhcpcd.conf\"");
            let mut apply = strip.clone();
            if !block.is_empty() {
                apply.push_str(&format!("\nprintf '%s' {} >> {f}", sh_quote(&block)));
            }
            apply.push_str(&format!("\n{restart}"));
            let revert = format!("cp -p \"$BK/dhcpcd.conf\" {f}\n{restart}");
            Ok((setup, apply, revert))
        }
        Backend::Windows => Err("Windows backend is not a Linux backend".into()),
    }
}

/// Complete `/bin/sh` script, executed once through pkexec: back up, apply, wait for
/// confirmation, otherwise revert automatically.
pub fn watchdog_script(
    backend: Backend,
    iface: &str,
    new: &Config,
    previous: &Config,
    control_dir: &str,
    timeout_secs: u32,
) -> Result<String, String> {
    let (setup, apply, revert) = fragments(backend, iface, new, previous)?;
    Ok(format!(
        r#"CTL={ctl}
log() {{ echo "$1" >> "$CTL/status"; }}
BK=/var/lib/static-ip-manager/backups/$(date +%Y%m%d-%H%M%S)-{iface}
{setup}
revert() {{
  (
{revert}
  ) && log reverted || log revert-failed
}}
if ! (
set -e
{apply}
); then
  log 'failed: command error (reverting)'
  revert
  exit 1
fi
log applied
i=0
while [ "$i" -lt {grace} ]; do
  if [ -e "$CTL/confirm" ]; then log confirmed; exit 0; fi
  if [ -e "$CTL/revert" ]; then break; fi
  sleep 1
  i=$((i+1))
done
revert
"#,
        ctl = sh_quote(control_dir),
        grace = timeout_secs + 5,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;

    const ADDR: &str = r#"[
 {"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP"],"operstate":"UNKNOWN","address":"00:00:00:00:00:00","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8}]},
 {"ifindex":2,"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"operstate":"UP","address":"dc:a6:32:01:02:03",
  "addr_info":[{"family":"inet","local":"192.168.1.20","prefixlen":24,"dynamic":true},{"family":"inet6","local":"fe80::1","prefixlen":64}]},
 {"ifindex":3,"ifname":"eth1","flags":["BROADCAST","MULTICAST"],"operstate":"DOWN","address":"dc:a6:32:0a:0b:0c","addr_info":[]},
 {"ifindex":4,"ifname":"wlan0","flags":["BROADCAST","UP"],"operstate":"UP","address":"aa:bb:cc:dd:ee:ff","addr_info":[{"family":"inet","local":"10.0.0.7","prefixlen":8}]}
]"#;
    const ROUTE: &str = r#"[{"dst":"default","gateway":"192.168.1.1","dev":"eth0","protocol":"dhcp"}]"#;

    fn static_cfg() -> Config {
        Config {
            mode: Mode::Static,
            address: Some(Ipv4Addr::new(192, 168, 1, 50)),
            prefix: 24,
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            dns: vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)],
        }
    }

    #[test]
    fn parses_ip_json() {
        let a = parse_ip_addr_json(ADDR, ROUTE).unwrap();
        assert_eq!(a.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(), ["eth0", "eth1", "wlan0"]);
        assert_eq!(a[0].mode, Mode::Dhcp, "dynamic flag means DHCP");
        assert!(a[0].up);
        assert_eq!(a[0].gateway, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(a[0].ipv6, vec!["fe80::1/64"]);
        assert!(!a[1].up);
        assert_eq!(a[2].mode, Mode::Static);
        assert_eq!(a[2].gateway, None);
        assert_eq!(a[2].mac, "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn dns_parsers() {
        let r = parse_resolvectl_dns("Global: 9.9.9.9\nLink 2 (eth0): 192.168.1.1 8.8.8.8\nLink 3 (wlan0):\n");
        assert_eq!(r.len(), 2);
        assert_eq!(r[0], ("eth0".to_string(), vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(8, 8, 8, 8)]));
        assert!(r[1].1.is_empty());
        let rc = parse_resolv_conf("# c\nnameserver 127.0.0.53\nnameserver 1.1.1.1\nsearch lan\n");
        assert_eq!(rc, vec![Ipv4Addr::new(1, 1, 1, 1)]);
    }

    #[test]
    fn list_adapters_merges_dns_with_mock() {
        let r = MockRunner::new()
            .on("ip -j addr", ADDR, 0)
            .on("ip -j route", ROUTE, 0)
            .on("resolvectl dns", "Link 2 (eth0): 192.168.1.1\n", 0);
        let a = list_adapters(&r, Some("nameserver 8.8.4.4\n".into())).unwrap();
        assert_eq!(a[0].dns, vec![Ipv4Addr::new(192, 168, 1, 1)]);
        assert_eq!(a[1].dns, vec![Ipv4Addr::new(8, 8, 4, 4)], "falls back to resolv.conf");
        let bad = MockRunner::new().on("ip -j addr", "", 2);
        assert!(list_adapters(&bad, None).is_err());
    }

    #[test]
    fn backend_detection_order() {
        let r = MockRunner::new()
            .on("nmcli", "running\n", 0)
            .on("systemctl is-active systemd-networkd", "active\n", 0)
            .on("systemctl is-active dhcpcd", "inactive\n", 3);
        let exists = |p: &str| p == "/usr/sbin/netplan" || p == "/etc/netplan";
        let d = detect_backend(&r, &exists).unwrap();
        assert_eq!(d.preferred, Backend::NetworkManager);
        assert_eq!(d.available, vec![Backend::NetworkManager, Backend::Netplan, Backend::SystemdNetworkd]);

        let r = MockRunner::new().fail("nmcli", "not found").on("systemctl is-active dhcpcd", "active\n", 0).on("systemctl", "inactive\n", 3);
        let d = detect_backend(&r, &|_| false).unwrap();
        assert_eq!(d.preferred, Backend::Dhcpcd);

        let r = MockRunner::new().fail("nmcli", "x").on("systemctl", "inactive\n", 3);
        assert!(detect_backend(&r, &|_| false).is_none());
    }

    #[test]
    fn netplan_yaml_static_and_dhcp() {
        let y = netplan_yaml("eth0", &static_cfg());
        assert!(y.contains("addresses: [192.168.1.50/24]"));
        assert!(y.contains("to: 0.0.0.0/0") && y.contains("via: 192.168.1.1"));
        assert!(y.contains("addresses: [1.1.1.1, 8.8.8.8]"));
        assert!(netplan_yaml("eth0", &Config::dhcp()).contains("dhcp4: true"));
    }

    #[test]
    fn networkd_and_dhcpcd_content() {
        let u = networkd_unit("eth0", &static_cfg());
        assert!(u.contains("Name=eth0") && u.contains("Address=192.168.1.50/24") && u.contains("Gateway=192.168.1.1"));
        assert_eq!(u.matches("DNS=").count(), 2);
        let b = dhcpcd_block("eth0", &static_cfg());
        assert!(b.contains("static ip_address=192.168.1.50/24"));
        assert!(b.contains("static routers=192.168.1.1"));
        assert!(b.contains("static domain_name_servers=1.1.1.1 8.8.8.8"));
        assert_eq!(dhcpcd_block("eth0", &Config::dhcp()), "");
    }

    #[test]
    fn nm_script_applies_and_reverts() {
        let s = watchdog_script(Backend::NetworkManager, "eth0", &static_cfg(), &Config::dhcp(), "/tmp/sipm-1", 30).unwrap();
        assert!(s.contains("ipv4.method manual ipv4.addresses 192.168.1.50/24 ipv4.gateway '192.168.1.1' ipv4.dns '1.1.1.1 8.8.8.8'"));
        assert!(s.contains("ipv4.method auto"), "revert to previous DHCP present");
        assert!(s.contains("[ \"$i\" -lt 35 ]"));
        assert!(s.contains("CTL='/tmp/sipm-1'"));
    }

    #[test]
    fn file_backends_back_up_and_restore() {
        for b in [Backend::Netplan, Backend::SystemdNetworkd, Backend::Dhcpcd] {
            let s = watchdog_script(b, "eth0", &static_cfg(), &Config::dhcp(), "/tmp/x", 20).unwrap();
            assert!(s.contains("/var/lib/static-ip-manager/backups/"), "{b:?}");
            assert!(s.contains("cp -p"), "{b:?}");
            assert!(s.contains("revert()"), "{b:?}");
        }
        let d = watchdog_script(Backend::Dhcpcd, "eth0", &Config::dhcp(), &static_cfg(), "/tmp/x", 20).unwrap();
        assert!(d.contains("sed -i '/^# BEGIN static-ip-manager eth0$/"));
        assert!(!d.contains("static ip_address"));
    }

    #[test]
    fn rejects_unsafe_interface_names() {
        for bad in ["", "eth0; rm -rf /", "a b", "$(x)", "averyveryverylongname", "e'th"] {
            assert!(watchdog_script(Backend::NetworkManager, bad, &static_cfg(), &Config::dhcp(), "/tmp/x", 20).is_err(), "{bad}");
        }
    }

    #[test]
    fn sh_quote_escapes() {
        assert_eq!(sh_quote("a'b"), "'a'\\''b'");
    }
}
