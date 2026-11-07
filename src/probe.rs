use crate::runner::CommandRunner;
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq, Eq)]
pub enum ProbeResult {
    /// A host answered: the address is very likely in use.
    InUse,
    /// No answer. This does NOT prove the address is free (hosts may drop ping).
    NoReply,
    Error(String),
}

/// Explicit, user-triggered check: sends two ICMP echo requests to ONE address.
pub fn check_in_use(runner: &dyn CommandRunner, ip: Ipv4Addr, windows: bool) -> ProbeResult {
    let ip_s = ip.to_string();
    let args: Vec<&str> = if windows { vec!["-n", "2", "-w", "1000", &ip_s] } else { vec!["-c", "2", "-W", "1", &ip_s] };
    match runner.run("ping", &args) {
        Err(e) => ProbeResult::Error(e),
        Ok(o) if windows => {
            // Windows returns exit code 0 even for "Destination host unreachable" replies
            // from the local gateway, so require a real echo reply (TTL=).
            if o.stdout.to_ascii_uppercase().contains("TTL=") { ProbeResult::InUse } else { ProbeResult::NoReply }
        }
        Ok(o) if o.code == 0 => ProbeResult::InUse,
        Ok(o) if o.code == 1 => ProbeResult::NoReply,
        Ok(o) => ProbeResult::Error(format!("ping failed (exit {}): {}", o.code, o.stderr.trim())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;

    const IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);

    #[test]
    fn linux_results() {
        let r = MockRunner::new().on("ping -c 2 -W 1 192.168.1.50", "2 received", 0);
        assert_eq!(check_in_use(&r, IP, false), ProbeResult::InUse);
        let r = MockRunner::new().on("ping", "0 received", 1);
        assert_eq!(check_in_use(&r, IP, false), ProbeResult::NoReply);
        let r = MockRunner::new().on("ping", "", 2);
        assert!(matches!(check_in_use(&r, IP, false), ProbeResult::Error(_)));
        let r = MockRunner::new().fail("ping", "no ping");
        assert!(matches!(check_in_use(&r, IP, false), ProbeResult::Error(_)));
    }

    #[test]
    fn windows_requires_ttl() {
        let reply = "Reply from 192.168.1.50: bytes=32 time<1ms TTL=64";
        let r = MockRunner::new().on("ping -n 2 -w 1000 192.168.1.50", reply, 0);
        assert_eq!(check_in_use(&r, IP, true), ProbeResult::InUse);
        let unreachable = "Reply from 192.168.1.5: Destination host unreachable.";
        let r = MockRunner::new().on("ping", unreachable, 0);
        assert_eq!(check_in_use(&r, IP, true), ProbeResult::NoReply);
    }
}
