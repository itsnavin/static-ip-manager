use static_ip_manager::linux::watchdog_script;
use static_ip_manager::model::*;
use std::net::Ipv4Addr;

fn main() {
    let new = Config { mode: Mode::Static, address: Some(Ipv4Addr::new(192, 168, 1, 50)), prefix: 24, gateway: Some(Ipv4Addr::new(192, 168, 1, 1)), dns: vec![Ipv4Addr::new(1, 1, 1, 1)] };
    for (b, n) in [(Backend::NetworkManager, "nm"), (Backend::Netplan, "np"), (Backend::SystemdNetworkd, "nd"), (Backend::Dhcpcd, "dc")] {
        for (cfg, t) in [(&new, "s"), (&Config::dhcp(), "d")] {
            let s = watchdog_script(b, "eth0", cfg, &new, "/tmp/it's", 30).unwrap();
            std::fs::write(format!("{}/sipm_{n}_{t}.sh", std::env::args().nth(1).unwrap()), s).unwrap();
        }
    }
}
