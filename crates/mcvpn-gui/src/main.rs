// Hide the console window in release Windows builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use mcvpn::client::{self, ClientState};
use mcvpn::config::ClientConfig;
use mcvpn::device;
use mcvpn::stats::SharedStats;
use mcvpn::tunnel::TunnelInfo;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const BG: egui::Color32 = egui::Color32::from_rgb(15, 15, 19);
const CARD: egui::Color32 = egui::Color32::from_rgb(26, 26, 33);
const ACCENT: egui::Color32 = egui::Color32::from_rgb(79, 195, 247);
const OK: egui::Color32 = egui::Color32::from_rgb(80, 200, 120);
const ERR: egui::Color32 = egui::Color32::from_rgb(230, 90, 90);
const WARN: egui::Color32 = egui::Color32::from_rgb(230, 190, 70);
const MUTED: egui::Color32 = egui::Color32::from_rgb(140, 140, 152);

#[derive(clap::Parser, Debug)]
#[command(name = "mcvpn", about = "Minecraft-camouflaged VPN client")]
struct Args {
    /// Headless CLI mode (no GUI)
    #[arg(long)]
    cli: bool,
    #[arg(long)]
    server: Option<String>,
    #[arg(long, default_value_t = 25565)]
    port: u16,
    #[arg(long)]
    token: Option<String>,
    /// In-memory device (loopback smoke test)
    #[arg(long)]
    mock_device: bool,
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq)]
enum UiState {
    Idle,
    Connecting,
    Connected,
    Error(String),
    Disconnected,
}

struct Driver {
    shutdown: tokio::sync::watch::Sender<bool>,
    stats: SharedStats,
    info: Arc<Mutex<Option<(TunnelInfo, Instant)>>>,
    thread: Option<std::thread::JoinHandle<()>>,
    mock: bool,
}

struct App {
    server: String,
    port: String,
    token: String,
    state: Arc<Mutex<UiState>>,
    driver: Option<Driver>,
    last_stats: (u64, u64),
    up_rate: f64,
    down_rate: f64,
    rtt_ms: Option<u32>,
    totals: (u64, u64),
    probe_seen: bool,
    connecting_since: Option<Instant>,
    last_poll: Instant,
    config_path: PathBuf,
    log_path: PathBuf,
    status_msg: String,
    show_log: bool,
    copied_at: Option<Instant>,
}

fn config_path() -> PathBuf {
    if let Ok(x) = std::env::var("APPDATA") {
        return PathBuf::from(x).join("mcvpn").join("client.toml");
    }
    if let Ok(x) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(x).join("mcvpn").join("client.toml");
    }
    PathBuf::from(".mcvpn-client.toml")
}

/// Log next to the exe when writable (easy to find), else the temp dir.
fn log_path() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("mcvpn.log");
            if std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&p)
                .is_ok()
            {
                return p;
            }
        }
    }
    std::env::temp_dir().join("mcvpn.log")
}

#[cfg(target_os = "windows")]
fn make_os_device(
    info: &TunnelInfo,
    server_ip: Option<IpAddr>,
) -> mcvpn::VpnResult<device::DeviceHandle> {
    let v4 = match server_ip {
        Some(IpAddr::V4(v)) => Some(v),
        _ => None,
    };
    device::wintun::open(info, v4)
}

#[cfg(target_os = "linux")]
fn make_os_device(
    info: &TunnelInfo,
    server_ip: Option<IpAddr>,
) -> mcvpn::VpnResult<device::DeviceHandle> {
    let route_mode = match std::env::var("MCVPN_ROUTES").as_deref() {
        Ok("none") => device::tun::RouteMode::None,
        Ok(other) => device::tun::RouteMode::Targeted(
            other
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        ),
        Err(_) => device::tun::RouteMode::Full,
    };
    let ip = std::net::Ipv4Addr::from(info.ip);
    let mask = std::net::Ipv4Addr::from(info.netmask);
    let prefix = u32::from(mask).count_ones() as u8;
    let mut handle = device::tun::open("mcvpnc0", &format!("{ip}/{prefix}"), info.mtu)?;
    let added = device::tun::add_client_routes("mcvpnc0", server_ip, &route_mode)?;
    if !added.is_empty() {
        handle.set_cleanup(Box::new(move || {
            device::tun::del_client_routes("mcvpnc0", &added);
        }));
    }
    Ok(handle)
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn make_os_device(
    _info: &TunnelInfo,
    _server_ip: Option<IpAddr>,
) -> mcvpn::VpnResult<device::DeviceHandle> {
    Err(mcvpn::VpnError::Device(
        "no device backend for this OS".into(),
    ))
}

fn make_device(
    info: &TunnelInfo,
    server_ip: Option<IpAddr>,
    mock: bool,
) -> mcvpn::VpnResult<device::DeviceHandle> {
    if mock {
        let (a, peer) = device::mock::mock_pair();
        std::mem::forget(peer); // keep the mock peer alive
        return Ok(a);
    }
    make_os_device(info, server_ip)
}

impl App {
    fn new() -> Self {
        let path = config_path();
        let mut app = App {
            server: String::new(),
            port: "25565".into(),
            token: String::new(),
            state: Arc::new(Mutex::new(UiState::Idle)),
            driver: None,
            last_stats: (0, 0),
            up_rate: 0.0,
            down_rate: 0.0,
            rtt_ms: None,
            totals: (0, 0),
            probe_seen: false,
            connecting_since: None,
            last_poll: Instant::now(),
            config_path: path.clone(),
            log_path: log_path(),
            status_msg: String::new(),
            show_log: false,
            copied_at: None,
        };
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(cfg) = toml::from_str::<ClientConfig>(&text) {
                app.server = cfg.server;
                app.port = cfg.port.to_string();
                app.token = cfg.token;
            }
        }
        app
    }

    fn save_config(&self) {
        let cfg = ClientConfig {
            server: self.server.clone(),
            port: self.port.parse().unwrap_or(25565),
            token: self.token.clone(),
            ..Default::default()
        };
        if let Some(parent) = self.config_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(
            &self.config_path,
            toml::to_string_pretty(&cfg).unwrap_or_default(),
        );
    }

    fn connect(&mut self) {
        // Same forgiving parsing every client uses: trims invisible junk from
        // a pasted token, accepts "ip:port" and mcvpn://token@host:port links.
        let raw = ClientConfig {
            server: self.server.clone(),
            port: self.port.trim().parse().unwrap_or(25565),
            token: self.token.clone(),
            ..Default::default()
        };
        let cfg = raw.normalized();
        self.server = cfg.server.clone();
        self.port = cfg.port.to_string();
        self.token = cfg.token.clone();
        if cfg.server.is_empty() || cfg.token.is_empty() {
            self.status_msg = "Fill in server and token (or paste an mcvpn:// link)".into();
            return;
        }
        self.save_config();
        *self.state.lock().unwrap() = UiState::Connecting;
        self.connecting_since = Some(Instant::now());
        self.probe_seen = false;
        self.status_msg.clear();
        tracing::info!("user pressed Connect");

        let state = Arc::clone(&self.state);
        let stats: SharedStats = Arc::new(mcvpn::stats::Stats::default());
        let stats_driver = Arc::clone(&stats);
        let shared_info: Arc<Mutex<Option<(TunnelInfo, Instant)>>> = Arc::new(Mutex::new(None));
        let factory_info = Arc::clone(&shared_info);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let mock = std::env::var("MCVPN_MOCK_DEVICE").is_ok();

        let thread = std::thread::Builder::new()
            .name("mcvpn-driver".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .expect("tokio runtime");
                rt.block_on(async move {
                    client::run_client(
                        cfg,
                        stats_driver,
                        move |info: &TunnelInfo, server_ip: Option<IpAddr>| {
                            let r = make_device(info, server_ip, mock);
                            if r.is_ok() {
                                *factory_info.lock().unwrap() =
                                    Some((info.clone(), Instant::now()));
                            }
                            r
                        },
                        shutdown_rx,
                        move |s| match s {
                            ClientState::Connecting => *state.lock().unwrap() = UiState::Connecting,
                            ClientState::Connected => {
                                *state.lock().unwrap() = UiState::Connected;
                                // Prove the OS really routes traffic into the tunnel:
                                // one datagram to a TEST-NET address must show up in
                                // the tunnel device a moment later.
                                std::thread::spawn(|| {
                                    std::thread::sleep(Duration::from_millis(1200));
                                    client::send_route_probe();
                                });
                            }
                            ClientState::Disconnected => {
                                *state.lock().unwrap() = UiState::Disconnected
                            }
                            ClientState::Error(e) => {
                                *state.lock().unwrap() = UiState::Error(e.clone())
                            }
                            ClientState::Waiting(_) => {}
                        },
                    )
                    .await;
                });
            })
            .expect("spawn driver");
        self.driver = Some(Driver {
            shutdown: shutdown_tx,
            stats,
            info: shared_info,
            thread: Some(thread),
            mock,
        });
    }

    fn disconnect(&mut self) {
        tracing::info!("user pressed Disconnect");
        if let Some(d) = &mut self.driver {
            let _ = d.shutdown.send(true);
        }
        *self.state.lock().unwrap() = UiState::Idle;
        self.connecting_since = None;
    }

    /// Leave the OS clean: wait (briefly) for the driver to remove routes and
    /// the adapter before the process exits.
    fn shutdown_and_wait(&mut self) {
        if let Some(d) = &mut self.driver {
            let _ = d.shutdown.send(true);
            if let Some(t) = d.thread.take() {
                let deadline = Instant::now() + Duration::from_secs(4);
                while !t.is_finished() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }

    fn poll_stats(&mut self) {
        if let Some(d) = &self.driver {
            let snap = d.stats.snapshot();
            let dt = self.last_poll.elapsed().as_secs_f64().max(0.001);
            self.up_rate = snap.up_bytes.saturating_sub(self.last_stats.0) as f64 / dt;
            self.down_rate = snap.down_bytes.saturating_sub(self.last_stats.1) as f64 / dt;
            self.rtt_ms = if snap.rtt_ms == 0 {
                None
            } else {
                Some(snap.rtt_ms)
            };
            self.totals = (snap.up_bytes, snap.down_bytes);
            self.probe_seen = snap.probe_seen;
            self.last_stats = (snap.up_bytes, snap.down_bytes);
            self.last_poll = Instant::now();
        }
    }
}

fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::none()
        .fill(CARD)
        .rounding(10.0)
        .inner_margin(egui::Margin::same(14.0))
        .show(ui, add)
        .inner
}

fn status_dot(ui: &mut egui::Ui, color: egui::Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 5.0, color);
}

fn field_label(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).color(MUTED).size(11.5));
}

fn big_button(ui: &mut egui::Ui, text: &str, fill: egui::Color32) -> bool {
    ui.add_sized(
        [ui.available_width(), 40.0],
        egui::Button::new(
            egui::RichText::new(text)
                .strong()
                .size(15.0)
                .color(egui::Color32::from_rgb(10, 12, 16)),
        )
        .fill(fill)
        .rounding(8.0),
    )
    .clicked()
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_stats();
        ctx.request_repaint_after(Duration::from_millis(250));

        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(BG)
                    .inner_margin(egui::Margin::same(16.0)),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        self.ui(ui, ctx);
                    });
            });
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.shutdown_and_wait();
    }
}

impl App {
    fn ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            ui.heading(
                egui::RichText::new("mcvpn")
                    .strong()
                    .size(24.0)
                    .color(ACCENT),
            );
            ui.label(
                egui::RichText::new("Minecraft-compatible VPN")
                    .color(MUTED)
                    .size(12.0),
            );
        });
        ui.add_space(10.0);

        let state = self.state.lock().unwrap().clone();
        let busy = matches!(state, UiState::Connecting | UiState::Connected);

        card(ui, |ui| {
            ui.add_enabled_ui(!busy, |ui| {
                field_label(ui, "SERVER  (host, ip:port, or paste an mcvpn:// link)");
                ui.add(
                    egui::TextEdit::singleline(&mut self.server)
                        .hint_text("203.0.113.5")
                        .desired_width(f32::INFINITY),
                );
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        field_label(ui, "PORT");
                        ui.add(egui::TextEdit::singleline(&mut self.port).desired_width(70.0));
                    });
                    ui.vertical(|ui| {
                        field_label(ui, "TOKEN");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.token)
                                .password(true)
                                .desired_width(f32::INFINITY),
                        );
                    });
                });
            });
        });
        ui.add_space(10.0);

        match &state {
            UiState::Connected => {
                if big_button(ui, "DISCONNECT", ERR) {
                    self.disconnect();
                }
            }
            UiState::Connecting => {
                let secs = self
                    .connecting_since
                    .map(|t| t.elapsed().as_secs())
                    .unwrap_or(0);
                if big_button(ui, &format!("CANCEL  ({secs}s)"), WARN) {
                    self.disconnect();
                }
            }
            _ => {
                if big_button(ui, "CONNECT", ACCENT) {
                    self.connect();
                }
            }
        }
        ui.add_space(10.0);

        // Status line
        let (color, text) = match &state {
            UiState::Idle => (MUTED, "idle".to_string()),
            UiState::Connecting => (WARN, "connecting…".to_string()),
            UiState::Connected => (OK, "connected".to_string()),
            UiState::Disconnected => (MUTED, "disconnected".to_string()),
            UiState::Error(_) => (ERR, "error".to_string()),
        };
        ui.horizontal(|ui| {
            status_dot(ui, color);
            ui.label(egui::RichText::new(text).color(color).strong());
            if !self.status_msg.is_empty() {
                ui.label(egui::RichText::new(&self.status_msg).color(WARN));
            }
        });

        if let UiState::Error(e) = &state {
            ui.add_space(6.0);
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(52, 24, 26))
                .rounding(8.0)
                .inner_margin(egui::Margin::same(10.0))
                .show(ui, |ui| {
                    // Selectable, wrapped: the exact text is what a bug report needs.
                    ui.add(
                        egui::TextEdit::multiline(&mut e.as_str())
                            .desired_width(f32::INFINITY)
                            .desired_rows(2)
                            .text_color(egui::Color32::from_rgb(255, 190, 190))
                            .frame(false),
                    );
                });
        }

        if state == UiState::Connected {
            ui.add_space(8.0);
            let (ip, uptime) = self
                .driver
                .as_ref()
                .and_then(|d| d.info.lock().unwrap().clone())
                .map(|(info, since)| {
                    (
                        format!(
                            "{}.{}.{}.{}",
                            info.ip[0], info.ip[1], info.ip[2], info.ip[3]
                        ),
                        since.elapsed(),
                    )
                })
                .unwrap_or_else(|| ("-".into(), Duration::ZERO));
            card(ui, |ui| {
                egui::Grid::new("stats")
                    .num_columns(2)
                    .spacing([24.0, 6.0])
                    .show(ui, |ui| {
                        let row = |ui: &mut egui::Ui, k: &str, v: String| {
                            ui.label(egui::RichText::new(k).color(MUTED));
                            ui.label(egui::RichText::new(v).monospace());
                            ui.end_row();
                        };
                        row(ui, "Tunnel IP", ip);
                        row(ui, "Uptime", fmt_duration(uptime));
                        row(
                            ui,
                            "Upload",
                            format!(
                                "{:.0} KB/s   ({:.2} MB)",
                                self.up_rate / 1024.0,
                                self.totals.0 as f64 / 1048576.0
                            ),
                        );
                        row(
                            ui,
                            "Download",
                            format!(
                                "{:.0} KB/s   ({:.2} MB)",
                                self.down_rate / 1024.0,
                                self.totals.1 as f64 / 1048576.0
                            ),
                        );
                        row(
                            ui,
                            "Ping",
                            self.rtt_ms
                                .map(|r| format!("{r} ms"))
                                .unwrap_or_else(|| "…".into()),
                        );
                    });
            });

            let mock = self.driver.as_ref().map(|d| d.mock).unwrap_or(false);
            if !mock && uptime > Duration::from_secs(5) && !self.probe_seen {
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(
                        "⚠ Windows is not sending traffic into the VPN (the routes did not \
                         apply). Open the log below and send it to support.",
                    )
                    .color(WARN),
                );
            }
            if self.totals.0 > 0 && self.totals.1 == 0 && uptime > Duration::from_secs(8) {
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(
                        "⚠ Nothing is coming back through the tunnel — the server side may \
                         be misconfigured. On the server: journalctl -u mcvpn -n 50",
                    )
                    .color(WARN),
                );
            }
        }

        // Diagnostics
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui
                .button(if self.show_log {
                    "Hide log"
                } else {
                    "Show log"
                })
                .clicked()
            {
                self.show_log = !self.show_log;
            }
            let recently_copied = self
                .copied_at
                .map(|t| t.elapsed() < Duration::from_secs(2))
                .unwrap_or(false);
            if ui
                .button(if recently_copied {
                    "Copied ✓"
                } else {
                    "Copy log"
                })
                .clicked()
            {
                ctx.copy_text(mcvpn::logbuf::snapshot());
                self.copied_at = Some(Instant::now());
            }
        });
        if self.show_log {
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(format!("log file: {}", self.log_path.display()))
                    .color(MUTED)
                    .size(10.5),
            );
            let log = mcvpn::logbuf::snapshot();
            egui::ScrollArea::vertical()
                .max_height(220.0)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut log.as_str())
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY),
                    );
                });
        }
    }
}

fn main() -> eframe::Result<()> {
    let args = <Args as clap::Parser>::parse();

    // Ring-buffer + file log: the app has no console, so this is how a
    // failed connection stays diagnosable.
    mcvpn::logbuf::init(Some(log_path()));
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "mcvpn starting");

    if args.cli {
        if let Err(e) = cli_mode(args) {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
        return Ok(());
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([460.0_f32, 560.0_f32])
            .with_min_inner_size([420.0_f32, 420.0_f32]),
        ..Default::default()
    };
    eframe::run_native(
        "mcvpn",
        options,
        Box::new(|cc| {
            let mut visuals = egui::Visuals::dark();
            visuals.panel_fill = BG;
            visuals.widgets.noninteractive.rounding = 6.0.into();
            visuals.widgets.inactive.rounding = 6.0.into();
            visuals.widgets.hovered.rounding = 6.0.into();
            visuals.widgets.active.rounding = 6.0.into();
            visuals.selection.bg_fill = ACCENT.gamma_multiply(0.45);
            cc.egui_ctx.set_visuals(visuals);
            Ok(Box::new(App::new()))
        }),
    )
}

fn fmt_duration(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m {}s", s / 60, s % 60)
    } else {
        format!("{}h {}m", s / 3600, (s % 3600) / 60)
    }
}

fn cli_mode(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    // Single-executable UX: the GUI binary is also a working CLI client.
    let server = args
        .server
        .or_else(|| std::env::var("MCVPN_SERVER").ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--server required in --cli mode",
            )
        })?;
    let token = args
        .token
        .or_else(|| std::env::var("MCVPN_TOKEN").ok())
        .unwrap_or_default();
    let cfg = ClientConfig {
        server,
        port: args.port,
        token,
        ..Default::default()
    };
    let mock = args.mock_device || std::env::var("MCVPN_MOCK_DEVICE").is_ok();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let stats: SharedStats = Arc::new(mcvpn::stats::Stats::default());
        let printer = Arc::clone(&stats);
        let printer_task = tokio::spawn(async move {
            let mut last = (0u64, 0u64);
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let s = printer.snapshot();
                println!(
                    "up {} KB/s  down {} KB/s  rtt {}ms",
                    s.up_bytes.saturating_sub(last.0) / 1024,
                    s.down_bytes.saturating_sub(last.1) / 1024,
                    if s.rtt_ms == 0 {
                        String::from("-")
                    } else {
                        s.rtt_ms.to_string()
                    }
                );
                last = (s.up_bytes, s.down_bytes);
            }
        });
        let handle = tokio::spawn(client::run_client(
            cfg,
            Arc::clone(&stats),
            move |info: &TunnelInfo, server_ip: Option<IpAddr>| make_device(info, server_ip, mock),
            shutdown_rx,
            |s| match s {
                ClientState::Connecting => println!("[state] connecting..."),
                ClientState::Connected => println!("[state] connected"),
                ClientState::Disconnected => println!("[state] disconnected"),
                ClientState::Error(e) => println!("[state] error: {e}"),
                ClientState::Waiting(d) => println!("[state] retrying in {d:?}"),
            },
        ));
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                let _ = shutdown_tx.send(true);
                // let the driver remove routes / the adapter
                tokio::time::sleep(Duration::from_millis(1500)).await;
            }
            _ = handle => {}
        }
        printer_task.abort();
    });
    Ok(())
}
