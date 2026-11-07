use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    Dhcp,
    Static,
}

/// A desired (or snapshotted) IPv4 configuration for one adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub mode: Mode,
    pub address: Option<Ipv4Addr>,
    pub prefix: u8,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
}

impl Config {
    pub fn dhcp() -> Self {
        Config { mode: Mode::Dhcp, address: None, prefix: 0, gateway: None, dns: vec![] }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Adapter {
    pub name: String,
    /// Windows interface index (None on Linux).
    pub index: Option<u32>,
    pub mac: String,
    pub up: bool,
    pub mode: Mode,
    pub addresses: Vec<(Ipv4Addr, u8)>,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub ipv6: Vec<String>,
}

impl Adapter {
    /// Snapshot of the adapter's current IPv4 settings, usable to restore later.
    pub fn to_config(&self) -> Config {
        match (self.mode, self.addresses.first()) {
            (Mode::Static, Some((a, p))) => Config {
                mode: Mode::Static,
                address: Some(*a),
                prefix: *p,
                gateway: self.gateway,
                dns: self.dns.clone(),
            },
            _ => Config::dhcp(),
        }
    }

    pub fn summary(&self) -> String {
        match self.addresses.first() {
            Some((a, p)) => format!("{a}/{p}"),
            None => "no IPv4 address".to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Backend {
    NetworkManager,
    Netplan,
    SystemdNetworkd,
    Dhcpcd,
    Windows,
}

impl Backend {
    pub fn label(&self) -> &'static str {
        match self {
            Backend::NetworkManager => "NetworkManager (nmcli)",
            Backend::Netplan => "netplan",
            Backend::SystemdNetworkd => "systemd-networkd",
            Backend::Dhcpcd => "dhcpcd",
            Backend::Windows => "Windows (NetTCPIP / DnsClient)",
        }
    }
}
