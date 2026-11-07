//! Read-only diagnostic: prints the adapters this machine reports. Changes nothing.
use static_ip_manager::runner::RealRunner;

fn main() {
    let r = RealRunner;
    let res = if cfg!(windows) {
        static_ip_manager::windows::list_adapters(&r)
    } else {
        static_ip_manager::linux::list_adapters(&r, std::fs::read_to_string("/etc/resolv.conf").ok())
    };
    match res {
        Ok(list) => list.iter().for_each(|a| println!("{a:#?}")),
        Err(e) => eprintln!("error: {e}"),
    }
}
