use clap::Parser;
use mcvpn::client::{self, ClientState};
use mcvpn::device;
use mcvpn::tunnel::TunnelInfo;
use std::time::Duration;
use tokio::sync::watch;

#[derive(Parser, Debug)]
#[command(name = "mcvpn-cli", about = "mcvpn client (CLI mode)")]
struct Args {
    /// Server host[:port]
    #[arg(long)]
    server: Option<String>,
    /// Server port
    #[arg(long, default_value_t = 25565)]
    port: u16,
    /// Auth token
    #[arg(long)]
    token: Option<String>,
    /// In-memory device (loopback smoke test)
    #[arg(long)]
    mock_device: bool,
    /// TOML config file path
    #[arg(long)]
    config: Option<std::path::PathBuf>,
}

#[derive(serde::Deserialize, Default)]
struct ClientFile {
    server: Option<String>,
    port: Option<u16>,
    token: Option<String>,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mcvpn=info".into()),
        )
        .init();
    let args = Args::parse();

    let file: ClientFile = match &args.config {
        Some(p) => toml::from_str(&std::fs::read_to_string(p)?)?,
        None => Default::default(),
    };
    let server = args
        .server
        .or(file.server)
        .ok_or_else(|| anyhow::anyhow!("--server or config file required"))?;
    let token = args
        .token
        .or(file.token)
        .ok_or_else(|| anyhow::anyhow!("--token or config file required"))?;
    let port = file.port.unwrap_or(args.port);

    let cfg = mcvpn::config::ClientConfig {
        server,
        port,
        token,
        ..Default::default()
    };

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let stats = std::sync::Arc::new(mcvpn::stats::Stats::default());

        let printer_stats = std::sync::Arc::clone(&stats);
        let stats_printer = tokio::spawn(async move {
            let mut last = (0u64, 0u64);
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let s = printer_stats.snapshot();
                let up = s.up_bytes.saturating_sub(last.0);
                let down = s.down_bytes.saturating_sub(last.1);
                last = (s.up_bytes, s.down_bytes);
                println!(
                    "up {} KB/s  down {} KB/s  rtt {}ms",
                    up / 1024,
                    down / 1024,
                    if s.rtt_ms == 0 {
                        String::from("-")
                    } else {
                        s.rtt_ms.to_string()
                    }
                );
            }
        });

        let mock = args.mock_device;
        let factory = move |info: &TunnelInfo| -> mcvpn::VpnResult<device::DeviceHandle> {
            if mock {
                let (a, _b) = device::mock::mock_pair();
                Ok(a)
            } else {
                #[cfg(target_os = "linux")]
                {
                    let ip = std::net::Ipv4Addr::from(info.ip);
                    let mask = std::net::Ipv4Addr::from(info.netmask);
                    let prefix = u32::from(mask).count_ones() as u8;
                    Ok(device::tun::open(
                        "mcvpnc0",
                        &format!("{ip}/{prefix}"),
                        info.mtu,
                    )?)
                }
                #[cfg(not(target_os = "linux"))]
                Err(mcvpn::VpnError::Device(
                    "real device on this OS is provided by mcvpn-gui / the Android app".into(),
                ))
            }
        };

        let handle = tokio::spawn(client::run_client(
            cfg,
            stats,
            move |info| factory(info),
            shutdown_rx,
            move |state| match state {
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
        stats_printer.abort();
    });
    Ok(())
}
