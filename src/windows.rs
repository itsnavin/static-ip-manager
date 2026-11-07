use crate::model::{Adapter, Config, Mode};
use crate::runner::CommandRunner;
use crate::validate::parse_ipv4;
use serde_json::Value;

pub const LIST_SCRIPT: &str = r#"$ErrorActionPreference='SilentlyContinue'
$out = @(Get-NetAdapter | ForEach-Object {
  $i = $_.ifIndex
  $ipif = Get-NetIPInterface -InterfaceIndex $i -AddressFamily IPv4
  $v4 = @(Get-NetIPAddress -InterfaceIndex $i -AddressFamily IPv4 | ForEach-Object { [pscustomobject]@{ Address = "$($_.IPAddress)"; Prefix = [int]$_.PrefixLength } })
  $v6 = @(Get-NetIPAddress -InterfaceIndex $i -AddressFamily IPv6 | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" })
  $gw = Get-NetRoute -InterfaceIndex $i -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1
  $dns = @((Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv4).ServerAddresses | ForEach-Object { "$_" })
  [pscustomobject]@{ Name = "$($_.Name)"; Index = [int]$i; Mac = "$($_.MacAddress)"; Status = "$($_.Status)"; Dhcp = "$($ipif.Dhcp)"; Ipv4 = $v4; Gateway = "$($gw.NextHop)"; Dns = $dns; Ipv6 = $v6 }
})
ConvertTo-Json -InputObject $out -Compress -Depth 4"#;

fn list(v: Option<&Value>) -> Vec<&Value> {
    match v {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(Value::Null) | None => vec![],
        Some(other) => vec![other],
    }
}

/// "fe80::1%40/64" -> "fe80::1/64"
fn strip_zone(s: &str) -> String {
    match (s.find('%'), s.find('/')) {
        (Some(z), Some(p)) if z < p => format!("{}{}", &s[..z], &s[p..]),
        (Some(z), None) => s[..z].to_string(),
        _ => s.to_string(),
    }
}

fn text(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

/// Parse the JSON produced by `LIST_SCRIPT`. Tolerates PowerShell's single-item collapsing.
pub fn parse_adapters(json: &str) -> Result<Vec<Adapter>, String> {
    let json = json.trim().trim_start_matches('\u{feff}');
    if json.is_empty() {
        return Ok(vec![]);
    }
    let root: Value = serde_json::from_str(json).map_err(|e| format!("cannot parse adapter list: {e}"))?;
    let items = match &root {
        Value::Array(a) => a.iter().collect(),
        Value::Null => vec![],
        other => vec![other],
    };
    let mut out = Vec::new();
    for it in items {
        let mut addresses = Vec::new();
        for a in list(it.get("Ipv4")) {
            if let (Some(ip), Some(p)) = (parse_ipv4(&text(a, "Address")), a.get("Prefix").and_then(Value::as_u64)) {
                // Skip APIPA addresses that Windows assigns when DHCP fails.
                if !ip.is_link_local() {
                    addresses.push((ip, p as u8));
                }
            }
        }
        let dns = list(it.get("Dns")).iter().filter_map(|d| d.as_str().and_then(parse_ipv4)).collect();
        let ipv6 = list(it.get("Ipv6")).iter().filter_map(|d| d.as_str().map(strip_zone)).collect();
        let dhcp = text(it, "Dhcp").eq_ignore_ascii_case("enabled");
        out.push(Adapter {
            name: text(it, "Name"),
            index: it.get("Index").and_then(Value::as_u64).map(|i| i as u32),
            mac: text(it, "Mac"),
            up: text(it, "Status").eq_ignore_ascii_case("up"),
            mode: if dhcp { Mode::Dhcp } else { Mode::Static },
            addresses,
            gateway: parse_ipv4(&text(it, "Gateway")).filter(|g| !g.is_unspecified()),
            dns,
            ipv6,
        });
    }
    Ok(out)
}

pub fn list_adapters(runner: &dyn CommandRunner) -> Result<Vec<Adapter>, String> {
    let o = runner.run("powershell", &["-NoProfile", "-NonInteractive", "-Command", LIST_SCRIPT])?;
    if o.code != 0 {
        return Err(format!("PowerShell failed: {}", o.stderr.trim()));
    }
    parse_adapters(&o.stdout)
}

pub fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// PowerShell statements that make interface `index` match `cfg`. Used for both
/// applying a new config and reverting to a snapshot.
pub fn config_commands(index: u32, cfg: &Config) -> Vec<String> {
    let i = index;
    let mut c = vec![
        format!("Get-NetIPAddress -InterfaceIndex {i} -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {{ $_.PrefixOrigin -ne 'WellKnown' }} | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue"),
        format!("Remove-NetRoute -InterfaceIndex {i} -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue"),
    ];
    match cfg.mode {
        Mode::Dhcp => {
            c.push(format!("Set-NetIPInterface -InterfaceIndex {i} -AddressFamily IPv4 -Dhcp Enabled"));
            c.push(format!("Set-DnsClientServerAddress -InterfaceIndex {i} -ResetServerAddresses"));
        }
        Mode::Static => {
            let addr = cfg.address.map(|a| a.to_string()).unwrap_or_default();
            c.push(format!("Set-NetIPInterface -InterfaceIndex {i} -AddressFamily IPv4 -Dhcp Disabled"));
            let gw = cfg.gateway.map(|g| format!(" -DefaultGateway {}", ps_quote(&g.to_string()))).unwrap_or_default();
            c.push(format!(
                "New-NetIPAddress -InterfaceIndex {i} -AddressFamily IPv4 -IPAddress {} -PrefixLength {}{gw} | Out-Null",
                ps_quote(&addr),
                cfg.prefix
            ));
            if cfg.dns.is_empty() {
                c.push(format!("Set-DnsClientServerAddress -InterfaceIndex {i} -ResetServerAddresses"));
            } else {
                let list = cfg.dns.iter().map(|d| ps_quote(&d.to_string())).collect::<Vec<_>>().join(",");
                c.push(format!("Set-DnsClientServerAddress -InterfaceIndex {i} -ServerAddresses ({list})"));
            }
        }
    }
    c
}

/// Full elevated PowerShell script: apply, wait for confirmation, otherwise revert.
pub fn watchdog_script(index: u32, new: &Config, previous: &Config, control_dir: &str, timeout_secs: u32) -> String {
    let apply = config_commands(index, new).join("\n    ");
    let revert = config_commands(index, previous).join("\n    ");
    format!(
        r#"$ErrorActionPreference = 'Stop'
$ctl = {ctl}
function Log($m) {{ Add-Content -Path (Join-Path $ctl 'status') -Value $m }}
function Revert {{
  $ErrorActionPreference = 'Continue'
  try {{
    {revert}
    Log 'reverted'
  }} catch {{ Log ('revert-failed: ' + $_.Exception.Message) }}
}}
try {{
    {apply}
    Log 'applied'
}} catch {{
  Log ('failed: ' + $_.Exception.Message)
  Revert
  exit 1
}}
$deadline = (Get-Date).AddSeconds({grace})
while ((Get-Date) -lt $deadline) {{
  if (Test-Path (Join-Path $ctl 'confirm')) {{ Log 'confirmed'; exit 0 }}
  if (Test-Path (Join-Path $ctl 'revert')) {{ break }}
  Start-Sleep -Seconds 1
}}
Revert
"#,
        ctl = ps_quote(control_dir),
        grace = timeout_secs + 5,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;
    use std::net::Ipv4Addr;

    const SAMPLE: &str = r#"[
 {"Name":"Ethernet","Index":12,"Mac":"AA-BB-CC-DD-EE-FF","Status":"Up","Dhcp":"Disabled",
  "Ipv4":[{"Address":"192.168.1.50","Prefix":24}],"Gateway":"192.168.1.1","Dns":["1.1.1.1","8.8.8.8"],"Ipv6":["fe80::1/64"]},
 {"Name":"Wi-Fi","Index":7,"Mac":"11-22-33-44-55-66","Status":"Disconnected","Dhcp":"Enabled",
  "Ipv4":[{"Address":"169.254.4.4","Prefix":16}],"Gateway":"","Dns":[],"Ipv6":[]}
]"#;

    #[test]
    fn parses_list() {
        let a = parse_adapters(SAMPLE).unwrap();
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].name, "Ethernet");
        assert_eq!(a[0].index, Some(12));
        assert!(a[0].up);
        assert_eq!(a[0].mode, Mode::Static);
        assert_eq!(a[0].addresses, vec![(Ipv4Addr::new(192, 168, 1, 50), 24)]);
        assert_eq!(a[0].gateway, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(a[0].dns.len(), 2);
        assert!(!a[1].up);
        assert_eq!(a[1].mode, Mode::Dhcp);
        assert!(a[1].addresses.is_empty(), "APIPA address filtered");
        assert_eq!(a[1].gateway, None);
    }

    #[test]
    fn tolerates_single_object_and_scalars() {
        let one = r#"{"Name":"Ethernet","Index":3,"Mac":"","Status":"Up","Dhcp":"Enabled","Ipv4":{"Address":"10.0.0.2","Prefix":8},"Gateway":"","Dns":"9.9.9.9","Ipv6":null}"#;
        let a = parse_adapters(one).unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].addresses.len(), 1);
        assert_eq!(a[0].dns, vec![Ipv4Addr::new(9, 9, 9, 9)]);
        assert!(parse_adapters("").unwrap().is_empty());
        assert!(parse_adapters("not json").is_err());
    }

    #[test]
    fn strips_ipv6_zone() {
        assert_eq!(strip_zone("fe80::1%40/64"), "fe80::1/64");
        assert_eq!(strip_zone("2001:db8::1/64"), "2001:db8::1/64");
    }

    #[test]
    fn list_uses_runner() {
        let r = MockRunner::new().on("powershell", SAMPLE, 0);
        assert_eq!(list_adapters(&r).unwrap().len(), 2);
        let r = MockRunner::new().on("powershell", "", 1);
        assert!(list_adapters(&r).is_err());
    }

    #[test]
    fn static_commands() {
        let cfg = Config {
            mode: Mode::Static,
            address: Some(Ipv4Addr::new(192, 168, 1, 50)),
            prefix: 24,
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            dns: vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)],
        };
        let c = config_commands(12, &cfg).join("\n");
        assert!(c.contains("-Dhcp Disabled"));
        assert!(c.contains("New-NetIPAddress -InterfaceIndex 12 -AddressFamily IPv4 -IPAddress '192.168.1.50' -PrefixLength 24 -DefaultGateway '192.168.1.1'"));
        assert!(c.contains("-ServerAddresses ('1.1.1.1','8.8.8.8')"));
    }

    #[test]
    fn dhcp_commands() {
        let c = config_commands(7, &Config::dhcp()).join("\n");
        assert!(c.contains("-Dhcp Enabled"));
        assert!(c.contains("-ResetServerAddresses"));
        assert!(!c.contains("New-NetIPAddress"));
    }

    #[test]
    fn watchdog_contains_apply_revert_and_quotes_path() {
        let new = Config {
            mode: Mode::Static,
            address: Some(Ipv4Addr::new(10, 0, 0, 9)),
            prefix: 24,
            gateway: None,
            dns: vec![],
        };
        let s = watchdog_script(5, &new, &Config::dhcp(), "C:\\Users\\O'Neil\\Temp\\sipm", 30);
        assert!(s.contains("'C:\\Users\\O''Neil\\Temp\\sipm'"));
        assert!(s.contains("10.0.0.9"));
        assert!(s.contains("-Dhcp Enabled"), "revert path present");
        assert!(s.contains("AddSeconds(35)"));
        assert!(!s.contains("-DefaultGateway"));
    }
}
