// Hide the console window in release Windows builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use mcvpn::client::{self, ClientState};
use mcvpn::config::ClientConfig;
use mcvpn::device;
use mcvpn::stats::SharedStats;
use mcvpn::tunnel::TunnelInfo;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
    last_poll: Instant,
    config_path: PathBuf,
    status_msg: String,
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
            last_poll: Instant::now(),
            config_path: path.clone(),
            status_msg: String::new(),
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
        let _ = std::fs::write(&self.config_path, toml::to_string_pretty(&cfg).unwrap_or_default());
    }

    fn connect(&mut self) {
        let cfg = ClientConfig {
            server: self.server.trim().trim_end_matches("/").to_string(),
            port: self.port.parse().unwrap_or(25565),
            token: self.token.clone(),
            ..Default::default()
        };
        if cfg.server.is_empty() || cfg.token.is_empty() {
            self.status_msg = "Fill in server and token".into();
            return;
        }
        self.save_config();
        *self.state.lock().unwrap() = UiState::Connecting;
        self.status_msg.clear();

        let state = Arc::clone(&self.state);
        let stats: SharedStats = Arc::new(mcvpn::stats::Stats::default());
        let stats_driver = Arc::clone(&stats);
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
                    move |info: &TunnelInfo| -> mcvpn::VpnResult<device::DeviceHandle> {
                        if mock {
                            let (a, _b) = device::mock::mock_pair();
                            Ok(a)
                        } else {
                            #[cfg(target_os = "windows")]
                            return device::wintun::open(info);
                            #[cfg(not(target_os = "windows"))]
                            {
                                let ip = std::net::Ipv4Addr::from(info.ip);
                                let mask = std::net::Ipv4Addr::from(info.netmask);
                                let prefix = u32::from(mask).count_ones() as u8;
                                device::tun::open("mcvpnc0", &format!("{ip}/{prefix}"), info.mtu)
                            }
                        }
                    },
                    shutdown_rx,
                    move |s| match s {
                        ClientState::Connecting => *state.lock().unwrap() = UiState::Connecting,
                        ClientState::Connected => *state.lock().unwrap() = UiState::Connected,
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
        let _ = thread; // detaches; the OS cleans up when the app exits
        self.driver = Some(Driver { shutdown: shutdown_tx, stats });
    }

    fn disconnect(&mut self) {
        if let Some(d) = &mut self.driver {
            let _ = d.shutdown.send(true);
            *self.state.lock().unwrap() = UiState::Idle;
        }
    }

    fn poll_stats(&mut self) {
        if let Some(d) = &self.driver {
            let snap = d.stats.snapshot();
            let dt = self.last_poll.elapsed().as_secs_f64().max(0.001);
            self.up_rate = (snap.up_bytes - self.last_stats.0) as f64 / dt;
            self.down_rate = (snap.down_bytes - self.last_stats.1) as f64 / dt;
            self.rtt_ms = if snap.rtt_ms == 0 { None } else { Some(snap.rtt_ms) };
            self.last_stats = (snap.up_bytes, snap.down_bytes);
            self.last_poll = Instant::now();
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_stats();
        ctx.request_repaint_after(Duration::from_millis(250));

        egui::CentralPanel::default()
            .frame(egui::Frame::default().fill(egui::Color32::from_rgb(18, 18, 22)))
            .show(ctx, |ui| {
                ui.add_space(8.0);
                ui.heading(egui::RichText::new("mcvpn").strong().size(22.0));
                ui.label(
                    egui::RichText::new("Minecraft-camouflaged VPN · 1.8.9 protocol · port 25565")
                        .weak()
                        .size(11.0),
                );
                ui.add_space(14.0);

                let state = self.state.lock().unwrap().clone();
                let busy = matches!(state, UiState::Connecting | UiState::Connected);

                ui.add_enabled_ui(!busy, |ui| {
                    ui.horizontal(|ui| {
                        ui.add_sized([60.0, 18.0], egui::Label::new("Server:"));
                        ui.add(egui::TextEdit::singleline(&mut self.server).desired_width(260.0));
                    });
                    ui.horizontal(|ui| {
                        ui.add_sized([60.0, 18.0], egui::Label::new("Port:"));
                        ui.add(egui::TextEdit::singleline(&mut self.port).desired_width(80.0));
                    });
                    ui.horizontal(|ui| {
                        ui.add_sized([60.0, 18.0], egui::Label::new("Token:"));
                        ui.add(
                            egui::TextEdit::singleline(&mut self.token)
                                .password(true)
                                .desired_width(260.0),
                        );
                    });
                });

                ui.add_space(12.0);
                match state {
                    UiState::Connected => {
                        if ui
                            .add(egui::Button::new(egui::RichText::new("DISCONNECT").strong()).min_size(egui::vec2(160.0, 34.0)))
                            .clicked()
                        {
                            self.disconnect();
                        }
                        ui.add_space(8.0);
                        ui.monospace(format!(
                            "up {:.0} KB/s   down {:.0} KB/s   rtt {} ms",
                            self.up_rate / 1024.0,
                            self.down_rate / 1024.0,
                            self.rtt_ms
                                .map(|r| r.to_string())
                                .unwrap_or_else(|| "-".into())
                        ));
                    }
                    UiState::Connecting => {
                        ui.add_enabled(false, egui::Button::new("CONNECTING...").min_size(egui::vec2(160.0, 34.0)));
                    }
                    _ => {
                        if ui
                            .add(
                                egui::Button::new(egui::RichText::new("CONNECT").strong())
                                    .min_size(egui::vec2(160.0, 34.0)),
                            )
                            .clicked()
                        {
                            self.connect();
                        }
                    }
                }

                ui.add_space(10.0);
                let color = match state {
                    UiState::Connected => egui::Color32::from_rgb(80, 200, 120),
                    UiState::Error(_) => egui::Color32::from_rgb(220, 80, 80),
                    UiState::Connecting => egui::Color32::from_rgb(220, 180, 60),
                    _ => egui::Color32::from_rgb(120, 120, 130),
                };
                ui.horizontal(|ui| {
                    ui.ctx().style_mut(|s| s.visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0_f32, color));
                    let text = match &state {
                        UiState::Idle => "● idle".into(),
                        UiState::Connecting => "● connecting...".into(),
                        UiState::Connected => "● connected".into(),
                        UiState::Error(e) => format!("● error: {e}"),
                        UiState::Disconnected => "● disconnected".into(),
                    };
                    ui.colored_label(color, text);
                });
                if !self.status_msg.is_empty() {
                    ui.label(egui::RichText::new(&self.status_msg).weak());
                }
            });
    }
}

fn main() -> eframe::Result<()> {
    let args = <Args as clap::Parser>::parse();

    if args.cli {
        if let Err(e) = cli_mode(args) {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mcvpn=info".into()),
        )
        .init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([440.0_f32, 400.0_f32]),
        ..Default::default()
    };
    eframe::run_native("mcvpn", options, Box::new(|_cc| Ok(Box::new(App::new()))))
}

fn cli_mode(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    // Single-executable UX: the GUI binary is also a working CLI client.
    let server = args
        .server
        .or_else(|| std::env::var("MCVPN_SERVER").ok())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "--server required in --cli mode")
        })?;
    let token = args
        .token
        .or_else(|| std::env::var("MCVPN_TOKEN").ok())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "--token required in --cli mode")
        })?;
    let cfg = ClientConfig { server, port: args.port, token, ..Default::default() };
    let mock = args.mock_device || std::env::var("MCVPN_MOCK_DEVICE").is_ok();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
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
                    (s.up_bytes - last.0) / 1024,
                    (s.down_bytes - last.1) / 1024,
                    if s.rtt_ms == 0 { String::from("-") } else { s.rtt_ms.to_string() }
                );
                last = (s.up_bytes, s.down_bytes);
            }
        });
        let handle = tokio::spawn(client::run_client(
            cfg,
            Arc::clone(&stats),
            move |info: &TunnelInfo| -> mcvpn::VpnResult<device::DeviceHandle> {
                if mock {
                    let (a, _b) = device::mock::mock_pair();
                    Ok(a)
                } else {
                    #[cfg(target_os = "windows")]
                    return device::wintun::open(info);
                    #[cfg(not(target_os = "windows"))]
                    {
                        let ip = std::net::Ipv4Addr::from(info.ip);
                        let mask = std::net::Ipv4Addr::from(info.netmask);
                        let prefix = u32::from(mask).count_ones() as u8;
                        device::tun::open("mcvpnc0", &format!("{ip}/{prefix}"), info.mtu)
                    }
                }
            },
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
            }
            _ = handle => {}
        }
        printer_task.abort();
    });
    Ok(())
}
