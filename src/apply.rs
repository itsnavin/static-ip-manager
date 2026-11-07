use crate::model::{Adapter, Backend, Config};
use crate::{linux, windows};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

pub const DEFAULT_TIMEOUT_SECS: u32 = 60;

/// What will be executed with elevated privileges. The preview in the GUI shows `script` verbatim.
#[derive(Clone, Debug)]
pub struct Plan {
    pub backend: Backend,
    pub script: String,
    pub control_dir: PathBuf,
    pub timeout_secs: u32,
}

pub fn build_plan(
    adapter: &Adapter,
    backend: Backend,
    new: &Config,
    previous: &Config,
    control_dir: &Path,
    timeout_secs: u32,
) -> Result<Plan, String> {
    let dir = control_dir.to_string_lossy().to_string();
    let script = if backend == Backend::Windows {
        let idx = adapter.index.ok_or("adapter has no interface index")?;
        windows::watchdog_script(idx, new, previous, &dir, timeout_secs)
    } else {
        linux::watchdog_script(backend, &adapter.name, new, previous, &dir, timeout_secs)?
    };
    Ok(Plan { backend, script, control_dir: control_dir.to_path_buf(), timeout_secs })
}

pub fn new_control_dir(base: &Path) -> io::Result<PathBuf> {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let dir = base.join(format!("sipm-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Elevated script has not reported anything yet (waiting for UAC/polkit or still running).
    Pending,
    Applied,
    Confirmed,
    Reverted,
    Failed(String),
}

pub fn read_status(dir: &Path) -> Status {
    let text = fs::read_to_string(dir.join("status")).unwrap_or_default();
    let text = text.trim_start_matches('\u{feff}');
    let mut status = Status::Pending;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        status = match line {
            "applied" => Status::Applied,
            "confirmed" => Status::Confirmed,
            "reverted" => Status::Reverted,
            l if l.starts_with("failed") || l.starts_with("revert-failed") => Status::Failed(l.to_string()),
            _ => continue,
        };
    }
    status
}

pub fn confirm(dir: &Path) -> io::Result<()> {
    fs::write(dir.join("confirm"), b"1")
}

pub fn request_revert(dir: &Path) -> io::Result<()> {
    fs::write(dir.join("revert"), b"1")
}

/// Standard base64 (needed for PowerShell -EncodedCommand).
pub fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for ch in data.chunks(3) {
        let n = (ch[0] as u32) << 16 | (*ch.get(1).unwrap_or(&0) as u32) << 8 | *ch.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if ch.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if ch.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

pub fn encode_powershell(script: &str) -> String {
    let bytes: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    base64(&bytes)
}

/// Arguments for the (unprivileged) outer PowerShell that triggers the UAC prompt.
/// The script is passed encoded, never written to a user-writable file.
pub fn windows_launch_args(script: &str) -> Vec<String> {
    let inner = format!(
        "Start-Process -FilePath powershell.exe -Verb RunAs -ErrorAction Stop -WindowStyle Hidden -ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand','{}'",
        encode_powershell(script)
    );
    vec!["-NoProfile".into(), "-NonInteractive".into(), "-WindowStyle".into(), "Hidden".into(), "-Command".into(), inner]
}

/// Start the privileged script (UAC on Windows, polkit/pkexec on Linux). Non-blocking.
pub fn launch(plan: &Plan) -> io::Result<Child> {
    if plan.backend == Backend::Windows {
        let mut c = Command::new("powershell");
        c.args(windows_launch_args(&plan.script));
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            c.creation_flags(0x0800_0000);
        }
        c.spawn()
    } else {
        Command::new("pkexec").args(["/bin/sh", "-c", &plan.script]).spawn()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Mode;
    use std::net::Ipv4Addr;

    #[test]
    fn base64_known_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn powershell_encoding_is_utf16le() {
        // "A" in UTF-16LE is 41 00
        assert_eq!(encode_powershell("A"), "QQA=");
        let args = windows_launch_args("Write-Host hi");
        assert_eq!(args.last().unwrap().matches("-EncodedCommand").count(), 1);
        assert!(args.last().unwrap().contains("-Verb RunAs"));
    }

    #[test]
    fn status_parsing_uses_last_known_state() {
        let t = tempfile::tempdir().unwrap();
        assert_eq!(read_status(t.path()), Status::Pending);
        fs::write(t.path().join("status"), "applied\n").unwrap();
        assert_eq!(read_status(t.path()), Status::Applied);
        confirm(t.path()).unwrap();
        fs::write(t.path().join("status"), "applied\r\nconfirmed\r\n").unwrap();
        assert_eq!(read_status(t.path()), Status::Confirmed);
        fs::write(t.path().join("status"), "applied\nreverted\n").unwrap();
        assert_eq!(read_status(t.path()), Status::Reverted);
        fs::write(t.path().join("status"), "failed: boom\nreverted\n").unwrap();
        assert_eq!(read_status(t.path()), Status::Reverted);
        fs::write(t.path().join("status"), "failed: boom\nrevert-failed\n").unwrap();
        assert!(matches!(read_status(t.path()), Status::Failed(_)));
    }

    #[test]
    fn plans_for_each_os() {
        let a = Adapter {
            name: "eth0".into(),
            index: Some(4),
            mac: String::new(),
            up: true,
            mode: Mode::Dhcp,
            addresses: vec![],
            gateway: None,
            dns: vec![],
            ipv6: vec![],
        };
        let new = Config { mode: Mode::Static, address: Some(Ipv4Addr::new(10, 0, 0, 2)), prefix: 24, gateway: None, dns: vec![] };
        let t = tempfile::tempdir().unwrap();
        let p = build_plan(&a, Backend::Windows, &new, &Config::dhcp(), t.path(), 30).unwrap();
        assert!(p.script.contains("New-NetIPAddress -InterfaceIndex 4"));
        let p = build_plan(&a, Backend::Netplan, &new, &Config::dhcp(), t.path(), 30).unwrap();
        assert!(p.script.contains("netplan apply"));
        let mut no_idx = a.clone();
        no_idx.index = None;
        assert!(build_plan(&no_idx, Backend::Windows, &new, &Config::dhcp(), t.path(), 30).is_err());
    }

    #[test]
    fn control_dirs_are_unique() {
        let t = tempfile::tempdir().unwrap();
        let a = new_control_dir(t.path()).unwrap();
        let b = new_control_dir(t.path()).unwrap();
        assert_ne!(a, b);
        assert!(a.is_dir());
    }
}
