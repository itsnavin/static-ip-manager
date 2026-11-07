use eframe::egui::{self, Color32, RichText};
use static_ip_manager::apply::{self, Plan, Status};
use static_ip_manager::linux;
use static_ip_manager::model::{Adapter, Backend, Config, Mode};
use static_ip_manager::probe::{self, ProbeResult};
use static_ip_manager::runner::RealRunner;
use static_ip_manager::safety;
use static_ip_manager::store::{self, Profile, Store};
use static_ip_manager::validate::{self, FormInput, Issue, Severity};
use static_ip_manager::windows;
use std::path::PathBuf;
use std::process::Child;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

const ACCENT: Color32 = Color32::from_rgb(56, 139, 253);
const OK: Color32 = Color32::from_rgb(63, 185, 80);
const WARN: Color32 = Color32::from_rgb(227, 179, 65);
const ERR: Color32 = Color32::from_rgb(248, 81, 73);
const MUTED: Color32 = Color32::from_rgb(139, 148, 158);

pub fn apply_style(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = Color32::from_rgb(13, 17, 23);
    v.window_fill = Color32::from_rgb(22, 27, 34);
    v.extreme_bg_color = Color32::from_rgb(1, 4, 9);
    v.selection.bg_fill = ACCENT.linear_multiply(0.45);
    v.widgets.inactive.bg_fill = Color32::from_rgb(33, 38, 45);
    v.widgets.inactive.weak_bg_fill = Color32::from_rgb(33, 38, 45);
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(48, 54, 61);
    let r = egui::CornerRadius::same(8);
    v.widgets.noninteractive.corner_radius = r;
    v.widgets.inactive.corner_radius = r;
    v.widgets.hovered.corner_radius = r;
    v.widgets.active.corner_radius = r;
    v.window_corner_radius = egui::CornerRadius::same(12);
    ctx.set_visuals(v);
    ctx.global_style_mut(|s| {
        s.spacing.item_spacing = egui::vec2(10.0, 8.0);
        s.spacing.button_padding = egui::vec2(14.0, 7.0);
        s.spacing.interact_size.y = 30.0;
    });
}

struct Loaded {
    adapters: Vec<Adapter>,
    backend: Backend,
    available: Vec<Backend>,
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok()
}

fn load_system() -> Result<Loaded, String> {
    let runner = RealRunner;
    if cfg!(windows) {
        let adapters = windows::list_adapters(&runner)?;
        Ok(Loaded { adapters, backend: Backend::Windows, available: vec![Backend::Windows] })
    } else {
        let resolv = std::fs::read_to_string("/etc/resolv.conf").ok();
        let adapters = linux::list_adapters(&runner, resolv)?;
        let det = linux::detect_backend(&runner, &|p| std::path::Path::new(p).exists())
            .ok_or("No supported network backend detected (NetworkManager, netplan, systemd-networkd or dhcpcd).")?;
        Ok(Loaded { adapters, backend: det.preferred, available: det.available })
    }
}

struct Review {
    title: String,
    previous: Config,
    plan: Result<Plan, String>,
    warnings: Vec<String>,
    ack: bool,
}

struct Session {
    plan: Plan,
    child: Option<Child>,
    started: Instant,
    applied_at: Option<Instant>,
    adapter: String,
}

enum Notice {
    Info(String),
    Good(String),
    Bad(String),
}

pub struct App {
    adapters: Vec<Adapter>,
    selected: Option<usize>,
    backend: Backend,
    available: Vec<Backend>,
    load_error: Option<String>,
    loading: Option<Receiver<Result<Loaded, String>>>,
    mode: Mode,
    form: FormInput,
    timeout: u32,
    store: Store,
    profiles: Vec<Profile>,
    profile_name: String,
    review: Option<Review>,
    session: Option<Session>,
    probe: Option<Receiver<ProbeResult>>,
    probe_msg: Option<Notice>,
    notice: Option<Notice>,
}

impl App {
    pub fn new() -> Self {
        let store = Store::new(store::default_dir(&env));
        let profiles = store.load_profiles();
        let mut app = App {
            adapters: vec![],
            selected: None,
            backend: if cfg!(windows) { Backend::Windows } else { Backend::NetworkManager },
            available: vec![],
            load_error: None,
            loading: None,
            mode: Mode::Static,
            form: FormInput { mask: "24".into(), ..Default::default() },
            timeout: apply::DEFAULT_TIMEOUT_SECS,
            store,
            profiles,
            profile_name: String::new(),
            review: None,
            session: None,
            probe: None,
            probe_msg: None,
            notice: None,
        };
        app.refresh();
        app
    }

    fn refresh(&mut self) {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(load_system());
        });
        self.loading = Some(rx);
    }

    fn poll_loading(&mut self) {
        let Some(rx) = &self.loading else { return };
        match rx.try_recv() {
            Ok(Ok(l)) => {
                let keep = self.selected.and_then(|i| self.adapters.get(i)).map(|a| a.name.clone());
                self.adapters = l.adapters;
                self.available = l.available;
                if !self.available.contains(&self.backend) {
                    self.backend = l.backend;
                }
                self.load_error = None;
                self.loading = None;
                let idx = keep.and_then(|n| self.adapters.iter().position(|a| a.name == n)).or(if self.adapters.is_empty() { None } else { Some(0) });
                if let Some(i) = idx {
                    self.select(i);
                } else {
                    self.selected = None;
                }
            }
            Ok(Err(e)) => {
                self.load_error = Some(e);
                self.loading = None;
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => self.loading = None,
        }
    }

    fn select(&mut self, i: usize) {
        self.selected = Some(i);
        self.probe_msg = None;
        let a = &self.adapters[i];
        self.form = FormInput {
            address: a.addresses.first().map(|(ip, _)| ip.to_string()).unwrap_or_default(),
            mask: a.addresses.first().map(|(_, p)| p.to_string()).unwrap_or_else(|| "24".into()),
            gateway: a.gateway.map(|g| g.to_string()).unwrap_or_default(),
            dns: a.dns.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", "),
        };
        self.mode = Mode::Static;
    }

    fn current(&self) -> Option<&Adapter> {
        self.selected.and_then(|i| self.adapters.get(i))
    }

    fn open_review(&mut self, title: &str, cfg: Config) {
        let Some(adapter) = self.current().cloned() else { return };
        let previous = adapter.to_config();
        let plan = apply::new_control_dir(&std::env::temp_dir())
            .map_err(|e| format!("cannot create control directory: {e}"))
            .and_then(|dir| apply::build_plan(&adapter, self.backend, &cfg, &previous, &dir, self.timeout));
        let warnings = safety::warnings(&adapter, &env);
        self.review = Some(Review { title: title.into(), previous, plan, warnings, ack: false });
    }

    fn start_apply(&mut self, r: Review) {
        let Some(adapter) = self.current().cloned() else { return };
        let Ok(plan) = r.plan else { return };
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        if let Err(e) = self.store.save_snapshot(&adapter.name, stamp, &r.previous) {
            self.notice = Some(Notice::Bad(format!("Could not save backup, aborting: {e}")));
            return;
        }
        match apply::launch(&plan) {
            Ok(child) => {
                self.session = Some(Session { plan, child: Some(child), started: Instant::now(), applied_at: None, adapter: adapter.name });
            }
            Err(e) => self.notice = Some(Notice::Bad(format!("Could not request administrator rights: {e}"))),
        }
    }

    fn poll_session(&mut self, ctx: &egui::Context) {
        let Some(s) = &mut self.session else { return };
        ctx.request_repaint_after(Duration::from_millis(300));
        let status = apply::read_status(&s.plan.control_dir);
        let mut finished: Option<Notice> = None;
        match status {
            Status::Applied if s.applied_at.is_none() => s.applied_at = Some(Instant::now()),
            Status::Applied => {}
            Status::Confirmed => finished = Some(Notice::Good(format!("Settings on '{}' were applied and kept.", s.adapter))),
            Status::Reverted => finished = Some(Notice::Info(format!("Settings on '{}' were reverted to the previous configuration.", s.adapter))),
            Status::Failed(m) => finished = Some(Notice::Bad(format!("Apply failed: {m}. A revert was attempted; check the adapter."))),
            Status::Pending => {
                if let Some(c) = &mut s.child {
                    if let Ok(Some(code)) = c.try_wait() {
                        s.child = None;
                        if code.code() != Some(0) {
                            finished = Some(Notice::Bad("Administrator approval was cancelled or denied. Nothing was changed.".into()));
                        }
                    }
                }
                if s.applied_at.is_none() && s.started.elapsed() > Duration::from_secs(180) {
                    finished = Some(Notice::Bad("No response from the privileged helper after 3 minutes. Nothing is known to have changed.".into()));
                }
            }
        }
        if let Some(n) = finished {
            let dir = s.plan.control_dir.clone();
            self.session = None;
            let _ = std::fs::remove_dir_all(dir);
            self.notice = Some(n);
            self.refresh();
        }
    }

    fn poll_probe(&mut self) {
        if let Some(rx) = &self.probe {
            if let Ok(r) = rx.try_recv() {
                self.probe_msg = Some(match r {
                    ProbeResult::InUse => Notice::Bad("A device answered at this address. It is probably already in use - pick another.".into()),
                    ProbeResult::NoReply => Notice::Info("No reply. The address is probably free, but hosts that ignore ping cannot be detected.".into()),
                    ProbeResult::Error(e) => Notice::Bad(format!("Check failed: {e}")),
                });
                self.probe = None;
            }
        }
    }
}

fn badge(ui: &mut egui::Ui, text: &str, color: Color32) {
    ui.label(RichText::new(text).small().strong().color(color));
}

fn card_title(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).strong().size(15.0));
    ui.add_space(2.0);
}

fn show_notice(ui: &mut egui::Ui, n: &Notice) {
    let (c, t) = match n {
        Notice::Info(t) => (ACCENT, t),
        Notice::Good(t) => (OK, t),
        Notice::Bad(t) => (ERR, t),
    };
    ui.colored_label(c, t);
}

fn field_issues(ui: &mut egui::Ui, issues: &[Issue], field: &str) {
    for i in issues.iter().filter(|i| i.field == field) {
        let (c, p) = if i.severity == Severity::Error { (ERR, "x ") } else { (WARN, "! ") };
        ui.colored_label(c, format!("{p}{}", i.message));
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll_loading();
        self.poll_probe();
        self.poll_session(&ctx);
        if self.loading.is_some() || self.probe.is_some() {
            ctx.request_repaint_after(Duration::from_millis(200));
        }
        let busy = self.session.is_some() || self.review.is_some();

        egui::Panel::top("top").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Static IP Manager").heading().color(ACCENT));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add_enabled(!busy && self.loading.is_none(), egui::Button::new("Refresh")).clicked() {
                        self.refresh();
                    }
                    if self.available.len() > 1 {
                        egui::ComboBox::from_id_salt("backend")
                            .selected_text(self.backend.label())
                            .show_ui(ui, |ui| {
                                for b in self.available.clone() {
                                    ui.selectable_value(&mut self.backend, b, b.label());
                                }
                            });
                    } else if !self.available.is_empty() {
                        ui.label(self.backend.label());
                    }
                    ui.label(RichText::new("Backend:").color(MUTED));
                });
            });
            ui.add_space(6.0);
        });

        egui::Panel::bottom("bottom").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                if let Some(n) = &self.notice {
                    show_notice(ui, n);
                } else {
                    ui.colored_label(MUTED, "Nothing is changed until you review the exact commands and approve the administrator prompt. No telemetry; no network scans.");
                }
            });
            ui.add_space(4.0);
        });

        let mut pick = None;
        egui::Panel::left("adapters").default_size(280.0).resizable(false).show(ui, |ui| {
            ui.add_space(8.0);
            ui.label(RichText::new("Network adapters").strong().size(15.0));
            if self.loading.is_some() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.colored_label(MUTED, "Reading adapters...");
                });
            }
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (i, a) in self.adapters.iter().enumerate() {
                    let sel = self.selected == Some(i);
                    let resp = egui::Frame::group(ui.style())
                        .fill(if sel { ACCENT.linear_multiply(0.18) } else { Color32::from_rgb(22, 27, 34) })
                        .stroke(egui::Stroke::new(if sel { 1.5 } else { 1.0 }, if sel { ACCENT } else { Color32::from_rgb(48, 54, 61) }))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.colored_label(if a.up { OK } else { MUTED }, "●");
                                ui.label(RichText::new(&a.name).strong());
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if a.mode == Mode::Dhcp { badge(ui, "DHCP", ACCENT) } else { badge(ui, "STATIC", WARN) }
                                });
                            });
                            ui.colored_label(MUTED, a.summary());
                        })
                        .response
                        .interact(egui::Sense::click());
                    if resp.clicked() {
                        pick = Some(i);
                    }
                }
            });
        });
        if let (Some(i), false) = (pick, busy) {
            self.select(i);
        }

        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| self.central(ui, busy));
        });

        self.review_window(&ctx);
        self.session_window(&ctx);
    }
}

impl App {
    fn central(&mut self, ui: &mut egui::Ui, busy: bool) {
        if let Some(e) = &self.load_error {
            ui.colored_label(ERR, e);
            ui.colored_label(MUTED, "On Linux this app needs `ip` (iproute2 with JSON) and one of NetworkManager, netplan, systemd-networkd or dhcpcd.");
            return;
        }
        let Some(adapter) = self.current().cloned() else {
            ui.add_space(40.0);
            ui.label(RichText::new("Select an adapter on the left.").color(MUTED));
            return;
        };

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new(&adapter.name).heading());
            if adapter.up { badge(ui, "CONNECTED", OK) } else { badge(ui, "DISCONNECTED", MUTED) }
        });

        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            card_title(ui, "Current configuration");
            egui::Grid::new("info").num_columns(2).spacing([24.0, 6.0]).show(ui, |ui| {
                let row = |ui: &mut egui::Ui, k: &str, v: String| {
                    ui.colored_label(MUTED, k);
                    ui.label(v);
                    ui.end_row();
                };
                row(ui, "Mode", if adapter.mode == Mode::Dhcp { "DHCP (automatic)".into() } else { "Static".into() });
                row(ui, "MAC address", adapter.mac.clone());
                row(ui, "IPv4", adapter.addresses.iter().map(|(a, p)| format!("{a}/{p} ({})", validate::prefix_to_netmask(*p))).collect::<Vec<_>>().join(", "));
                row(ui, "Gateway", adapter.gateway.map(|g| g.to_string()).unwrap_or_else(|| "-".into()));
                row(ui, "DNS", if adapter.dns.is_empty() { "-".into() } else { adapter.dns.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", ") });
                row(ui, "IPv6 (read-only)", if adapter.ipv6.is_empty() { "-".into() } else { adapter.ipv6.join(", ") });
            });
        });

        for w in safety::warnings(&adapter, &env) {
            ui.colored_label(WARN, format!("! {w}"));
        }

        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            card_title(ui, "New configuration");
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.mode, Mode::Static, "Static IP");
                ui.selectable_value(&mut self.mode, Mode::Dhcp, "Automatic (DHCP)");
            });
            ui.add_space(4.0);

            let (cfg, issues) = if self.mode == Mode::Static {
                validate::validate_static(&self.form)
            } else {
                (Some(Config::dhcp()), vec![])
            };

            if self.mode == Mode::Static {
                self.profile_row(ui);
                ui.add_space(4.0);
                egui::Grid::new("form").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
                    let edit = |ui: &mut egui::Ui, label: &str, text: &mut String, hint: &str, field: &str| {
                        ui.label(label);
                        ui.vertical(|ui| {
                            ui.add(egui::TextEdit::singleline(text).hint_text(hint).desired_width(280.0));
                            if !text.trim().is_empty() || field == "dns" || field == "gateway" {
                                field_issues(ui, &issues, field);
                            }
                        });
                        ui.end_row();
                    };
                    edit(ui, "IP address", &mut self.form.address, "192.168.1.50", "address");
                    edit(ui, "Prefix / netmask", &mut self.form.mask, "24 or 255.255.255.0", "mask");
                    edit(ui, "Gateway", &mut self.form.gateway, "192.168.1.1 (optional)", "gateway");
                    edit(ui, "DNS servers", &mut self.form.dns, "1.1.1.1, 8.8.8.8", "dns");
                });
                ui.horizontal(|ui| {
                    let ip = validate::parse_ipv4(&self.form.address);
                    let tip = "Sends 2 ping packets to this single address. Nothing else on your network is contacted.";
                    if ui.add_enabled(ip.is_some() && self.probe.is_none(), egui::Button::new("Check if address is in use")).on_hover_text(tip).clicked() {
                        if let Some(ip) = ip {
                            let (tx, rx) = mpsc::channel();
                            std::thread::spawn(move || {
                                let _ = tx.send(probe::check_in_use(&RealRunner, ip, cfg!(windows)));
                            });
                            self.probe = Some(rx);
                            self.probe_msg = None;
                        }
                    }
                    if self.probe.is_some() {
                        ui.spinner();
                    }
                    if let Some(m) = &self.probe_msg {
                        show_notice(ui, m);
                    }
                });
            } else {
                ui.colored_label(MUTED, "The adapter will obtain address, gateway and DNS from your router/DHCP server.");
            }

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("Auto-revert timer");
                ui.add(egui::Slider::new(&mut self.timeout, 15..=300).suffix(" s"));
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let ready = !busy && cfg.is_some() && self.available.contains(&self.backend);
                if ui.add_enabled(ready, egui::Button::new(RichText::new("Review and apply...").strong()).fill(ACCENT.linear_multiply(0.6))).clicked() {
                    if let Some(c) = cfg.clone() {
                        self.open_review("Apply new configuration", c);
                    }
                }
                if ui.add_enabled(!busy && self.available.contains(&self.backend), egui::Button::new("Reset to DHCP")).clicked() {
                    self.open_review("Reset to DHCP", Config::dhcp());
                }
                let snap = self.store.latest_snapshot(&adapter.name);
                if ui.add_enabled(!busy && snap.is_some(), egui::Button::new("Restore last backup")).on_hover_text("Re-apply the configuration saved before the last change").clicked() {
                    if let Some(s) = snap {
                        self.open_review("Restore last backup", s);
                    }
                }
            });
        });
    }

    fn profile_row(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Profiles");
            let mut chosen = None;
            egui::ComboBox::from_id_salt("profiles").selected_text("Load profile...").show_ui(ui, |ui| {
                for p in &self.profiles {
                    if ui.selectable_label(false, &p.name).clicked() {
                        chosen = Some(p.clone());
                    }
                }
            });
            if let Some(p) = chosen {
                self.form = FormInput { address: p.address, mask: p.mask, gateway: p.gateway, dns: p.dns };
                self.profile_name = p.name;
            }
            ui.add(egui::TextEdit::singleline(&mut self.profile_name).hint_text("profile name").desired_width(150.0));
            if ui.add_enabled(!self.profile_name.trim().is_empty(), egui::Button::new("Save")).clicked() {
                let p = Profile {
                    name: self.profile_name.trim().to_string(),
                    address: self.form.address.clone(),
                    mask: self.form.mask.clone(),
                    gateway: self.form.gateway.clone(),
                    dns: self.form.dns.clone(),
                };
                match self.store.upsert_profile(p) {
                    Ok(()) => {
                        self.profiles = self.store.load_profiles();
                        self.notice = Some(Notice::Good("Profile saved.".into()));
                    }
                    Err(e) => self.notice = Some(Notice::Bad(format!("Could not save profile: {e}"))),
                }
            }
            if ui.add_enabled(self.profiles.iter().any(|p| p.name == self.profile_name), egui::Button::new("Delete")).clicked() {
                let _ = self.store.delete_profile(&self.profile_name);
                self.profiles = self.store.load_profiles();
            }
        });
    }

    fn review_window(&mut self, ctx: &egui::Context) {
        let Some(mut r) = self.review.take() else { return };
        enum Act {
            None,
            Cancel,
            Apply,
        }
        let mut act = Act::None;
        egui::Window::new(&r.title).collapsible(false).resizable(true).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).default_width(720.0).show(ctx, |ui| {
            match &r.plan {
                Err(e) => {
                    ui.colored_label(ERR, e);
                }
                Ok(p) => {
                    ui.label(format!("Backend: {}. This exact script will run with administrator rights (UAC / polkit):", p.backend.label()));
                    egui::ScrollArea::vertical().max_height(280.0).show(ui, |ui| {
                        ui.add(egui::TextEdit::multiline(&mut p.script.as_str()).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY));
                    });
                    ui.add_space(4.0);
                    ui.label(format!(
                        "After applying, you have {} seconds to press Keep. Otherwise the previous configuration is restored automatically (even if you lose the connection).",
                        p.timeout_secs
                    ));
                }
            }
            for w in &r.warnings {
                ui.colored_label(WARN, format!("! {w}"));
            }
            if !r.warnings.is_empty() {
                ui.checkbox(&mut r.ack, "I understand the risk of losing connectivity");
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let ok = r.plan.is_ok() && (r.warnings.is_empty() || r.ack);
                if ui.add_enabled(ok, egui::Button::new(RichText::new("Apply (asks for admin approval)").strong()).fill(ACCENT.linear_multiply(0.6))).clicked() {
                    act = Act::Apply;
                }
                if ui.button("Cancel").clicked() {
                    act = Act::Cancel;
                }
            });
        });
        match act {
            Act::None => self.review = Some(r),
            Act::Cancel => {
                if let Ok(p) = &r.plan {
                    let _ = std::fs::remove_dir_all(&p.control_dir);
                }
            }
            Act::Apply => self.start_apply(r),
        }
    }

    fn session_window(&mut self, ctx: &egui::Context) {
        let Some(s) = &self.session else { return };
        let dir: PathBuf = s.plan.control_dir.clone();
        let applied_at = s.applied_at;
        let timeout = s.plan.timeout_secs;
        let adapter = s.adapter.clone();
        let mut keep = false;
        let mut revert = false;
        let title = if applied_at.is_some() { "Keep these network settings?" } else { "Waiting for administrator approval" };
        egui::Window::new(title).collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| match applied_at {
            None => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Approve the UAC / polkit prompt to continue. You can also dismiss it to cancel.");
                });
            }
            Some(t) => {
                let left = (timeout as f32 - t.elapsed().as_secs_f32()).max(0.0);
                ui.label(format!("New settings are active on '{adapter}'. If you can read this, the connection works."));
                ui.add(egui::ProgressBar::new(left / timeout as f32).text(format!("Reverting in {} s", left.ceil() as u32)));
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new(RichText::new("Keep settings").strong()).fill(OK.linear_multiply(0.5))).clicked() {
                        keep = true;
                    }
                    if ui.button("Revert now").clicked() {
                        revert = true;
                    }
                });
            }
        });
        if keep {
            if let Err(e) = apply::confirm(&dir) {
                self.notice = Some(Notice::Bad(format!("Could not confirm: {e}. Settings will revert automatically.")));
            }
        }
        if revert {
            let _ = apply::request_revert(&dir);
        }
    }
}
