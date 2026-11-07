use crate::model::Config;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub address: String,
    pub mask: String,
    pub gateway: String,
    pub dns: String,
}

pub fn default_dir(env: &dyn Fn(&str) -> Option<String>) -> PathBuf {
    let base = if let Some(p) = env("APPDATA") {
        PathBuf::from(p)
    } else if let Some(p) = env("XDG_CONFIG_HOME") {
        PathBuf::from(p)
    } else if let Some(h) = env("HOME") {
        Path::new(&h).join(".config")
    } else {
        PathBuf::from(".")
    };
    base.join("static-ip-manager")
}

pub struct Store {
    dir: PathBuf,
}

fn safe_name(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
}

impl Store {
    pub fn new(dir: PathBuf) -> Self {
        Store { dir }
    }

    pub fn load_profiles(&self) -> Vec<Profile> {
        fs::read_to_string(self.dir.join("profiles.json")).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }

    pub fn save_profiles(&self, profiles: &[Profile]) -> io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        let json = serde_json::to_string_pretty(profiles).map_err(io::Error::other)?;
        fs::write(self.dir.join("profiles.json"), json)
    }

    /// Insert or replace by name.
    pub fn upsert_profile(&self, p: Profile) -> io::Result<()> {
        let mut all = self.load_profiles();
        all.retain(|x| x.name != p.name);
        all.push(p);
        all.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        self.save_profiles(&all)
    }

    pub fn delete_profile(&self, name: &str) -> io::Result<()> {
        let mut all = self.load_profiles();
        all.retain(|x| x.name != name);
        self.save_profiles(&all)
    }

    /// Save the pre-change configuration of an adapter. `stamp` makes names sortable.
    pub fn save_snapshot(&self, adapter: &str, stamp: u64, cfg: &Config) -> io::Result<PathBuf> {
        let d = self.dir.join("backups");
        fs::create_dir_all(&d)?;
        let path = d.join(format!("{stamp:020}-{}.json", safe_name(adapter)));
        fs::write(&path, serde_json::to_string_pretty(cfg).map_err(io::Error::other)?)?;
        Ok(path)
    }

    pub fn latest_snapshot(&self, adapter: &str) -> Option<Config> {
        let suffix = format!("-{}.json", safe_name(adapter));
        let mut files: Vec<PathBuf> = fs::read_dir(self.dir.join("backups"))
            .ok()?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.file_name().and_then(|n| n.to_str()).map(|n| n.ends_with(&suffix)).unwrap_or(false))
            .collect();
        files.sort();
        files.last().and_then(|p| fs::read_to_string(p).ok()).and_then(|s| serde_json::from_str(&s).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Mode;
    use std::net::Ipv4Addr;

    fn profile(n: &str) -> Profile {
        Profile { name: n.into(), address: "10.0.0.5".into(), mask: "24".into(), gateway: "10.0.0.1".into(), dns: "1.1.1.1".into() }
    }

    #[test]
    fn profiles_roundtrip_and_upsert() {
        let t = tempfile::tempdir().unwrap();
        let s = Store::new(t.path().join("cfg"));
        assert!(s.load_profiles().is_empty());
        s.upsert_profile(profile("Lab")).unwrap();
        s.upsert_profile(profile("Home")).unwrap();
        let mut p = profile("Lab");
        p.address = "10.0.0.9".into();
        s.upsert_profile(p).unwrap();
        let all = s.load_profiles();
        assert_eq!(all.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), ["Home", "Lab"]);
        assert_eq!(all[1].address, "10.0.0.9");
        s.delete_profile("Home").unwrap();
        assert_eq!(s.load_profiles().len(), 1);
    }

    #[test]
    fn corrupt_profiles_are_ignored() {
        let t = tempfile::tempdir().unwrap();
        std::fs::write(t.path().join("profiles.json"), "{oops").unwrap();
        assert!(Store::new(t.path().to_path_buf()).load_profiles().is_empty());
    }

    #[test]
    fn snapshots_latest_wins_per_adapter() {
        let t = tempfile::tempdir().unwrap();
        let s = Store::new(t.path().to_path_buf());
        let a = Config { mode: Mode::Static, address: Some(Ipv4Addr::new(10, 0, 0, 5)), prefix: 24, gateway: None, dns: vec![] };
        s.save_snapshot("Ethernet 2", 100, &Config::dhcp()).unwrap();
        s.save_snapshot("Ethernet 2", 200, &a).unwrap();
        s.save_snapshot("Wi-Fi", 300, &Config::dhcp()).unwrap();
        assert_eq!(s.latest_snapshot("Ethernet 2"), Some(a));
        assert_eq!(s.latest_snapshot("Wi-Fi"), Some(Config::dhcp()));
        assert_eq!(s.latest_snapshot("none"), None);
    }

    #[test]
    fn default_dir_precedence() {
        let e = |k: &str| match k {
            "APPDATA" => Some("C:\\A".to_string()),
            "HOME" => Some("/h".to_string()),
            _ => None,
        };
        assert_eq!(default_dir(&e), PathBuf::from("C:\\A").join("static-ip-manager"));
        let e = |k: &str| (k == "HOME").then(|| "/home/u".to_string());
        assert_eq!(default_dir(&e), Path::new("/home/u").join(".config").join("static-ip-manager"));
    }
}
