mod discovery;
mod protocol;
mod receive;
mod send;
mod util;
mod webshare;

use clap::{Parser, Subcommand};
use discovery::{DiscoveryOptions, TargetSelector};
use protocol::{DeviceInfo, DeviceType, Protocol};
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "localsend-cli",
    version,
    about = "Headless LocalSend CLI",
    long_about = "A fully non-interactive LocalSend CLI for automation and LLM control.\n\nCapabilities:\n  - Discover devices on the local network\n  - Send text, files, directories, or globbed file lists\n  - Receive files with auto-accept and optional PIN\n  - QR web-share fallback when discovery fails\n\nAll options are provided as flags; no prompts are used.",
    after_help = "Examples:\n  localsend-cli list\n  localsend-cli list --json\n  localsend-cli search --to \"alex-thinkpad-2024\"\n  localsend-cli send --to \"Alice\" --file ./photo.jpg\n  localsend-cli send --to 192.168.1.42 --text \"hello\"\n  localsend-cli send --to \"office-pc\" --dir ./project\n  localsend-cli send --direct 192.168.1.50:53317 --file ./report.pdf\n  localsend-cli send --to \"Alice\" --file ./photo.jpg --qr\n  localsend-cli receive --output ./downloads\n  localsend-cli receive --pin 123456"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Device alias shown to peers.
    #[arg(long, global = true)]
    alias: Option<String>,

    /// Device type reported to peers (mobile|desktop|web|headless|server).
    #[arg(long, global = true, default_value = "headless")]
    device_type: DeviceType,

    /// Protocol to advertise for our discovery server (http|https).
    #[arg(long, global = true, default_value = "https")]
    protocol: Protocol,

    /// Port to bind for discovery/register/receive.
    #[arg(long, global = true, default_value_t = 53317)]
    port: u16,

    /// Bind IP for servers (default 0.0.0.0).
    #[arg(long, global = true, default_value = "0.0.0.0")]
    bind: IpAddr,

    /// Output JSON instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Discover devices on the local network.
    List {
        /// Discovery timeout in seconds.
        #[arg(long, default_value_t = 3)]
        timeout: u64,

        /// Attempt IP range scan in addition to multicast discovery.
        #[arg(long, default_value_t = false)]
        scan: bool,
    },
    /// Send text/files/directories to a device.
    Send {
        /// Device selector: id, alias, hostname, or IP address.
        #[arg(long)]
        to: String,

        /// Optional pin (if receiver requires one).
        #[arg(long)]
        pin: Option<String>,

        /// Send plain text.
        #[arg(long)]
        text: Option<String>,

        /// Files to send.
        #[arg(long, value_name = "FILE")]
        file: Vec<PathBuf>,

        /// Directories to send (will be zipped).
        #[arg(long, value_name = "DIR")]
        dir: Vec<PathBuf>,

        /// Glob patterns to expand and send.
        #[arg(long, value_name = "GLOB")]
        glob: Vec<String>,

        /// Timeout in seconds for discovery + transfers.
        #[arg(long, default_value_t = 10)]
        timeout: u64,

        /// Skip discovery and send directly to this host:port (e.g. 192.168.1.10:53317).
        #[arg(long)]
        direct: Option<String>,

        /// If no matching device is found, start a QR web share fallback (HTTPS, auto-accept).
        #[arg(long, default_value_t = false)]
        qr: bool,
    },
    /// Receive files (auto-accept) and save to a directory.
    Receive {
        /// Directory to save incoming files.
        #[arg(long, default_value = ".")]
        output: PathBuf,

        /// Optional pin to require from senders.
        #[arg(long)]
        pin: Option<String>,

        /// Send a multicast announcement on startup.
        #[arg(long, default_value_t = true)]
        announce: bool,
    },
    /// Search for a single device (multicast first, then scan). Preferred on multi-network setups.
    Search {
        /// Device selector: id, alias, hostname, or IP address.
        #[arg(long)]
        to: String,

        /// Timeout in seconds for discovery and scan.
        #[arg(long, default_value_t = 5)]
        timeout: u64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::aws_lc_rs::default_provider(),
        );
    }

    let cli = Cli::parse();
    let alias = cli
        .alias
        .unwrap_or_else(|| util::default_alias().unwrap_or_else(|| "localsend-cli".to_string()));

    let identity = util::build_identity(cli.protocol)?;
    let device_info = DeviceInfo::new(
        alias,
        cli.device_type,
        cli.protocol,
        cli.port,
        identity.fingerprint.clone(),
    );

    match cli.command {
        Commands::List { timeout, scan } => {
            let options = DiscoveryOptions {
                timeout_secs: timeout,
                scan,
            };
            let devices = discovery::discover_devices(
                device_info,
                identity.tls.clone(),
                cli.bind,
                cli.port,
                options,
            )
            .await?;
            util::print_devices(&devices, cli.json);
        }
        Commands::Send {
            to,
            pin,
            text,
            file,
            dir,
            glob,
            timeout,
            direct,
            qr,
        } => {
            let selector = TargetSelector::new(to, direct);
            let mut temp_files = Vec::new();
            let items = send::build_items(text, file, dir, glob, &mut temp_files).await?;
            match send::resolve_target(
                selector,
                device_info.clone(),
                identity.tls.clone(),
                cli.bind,
                cli.port,
                timeout,
            )
            .await
            {
                Ok(target) => {
                    send::send_prepared_items(
                        target,
                        items,
                        device_info,
                        timeout,
                        pin,
                        cli.json,
                    )
                    .await?;
                }
                Err(err) if qr && err.downcast_ref::<send::NoMatchingDevice>().is_some() => {
                    webshare::run_web_share(
                        items,
                        device_info,
                        identity.tls.clone(),
                        cli.bind,
                        cli.port,
                        pin,
                        cli.json,
                    )
                    .await?;
                }
                Err(err) => return Err(err),
            }
        }
        Commands::Receive {
            output,
            pin,
            announce,
        } => {
            receive::run_receiver(
                device_info,
                identity.tls.clone(),
                cli.bind,
                cli.port,
                output,
                pin,
                announce,
                cli.json,
            )
            .await?;
        }
        Commands::Search { to, timeout } => {
            let selector = TargetSelector::new(to, None);
            let options = DiscoveryOptions {
                timeout_secs: timeout,
                scan: false,
            };
            let mut devices = discovery::discover_devices(
                device_info.clone(),
                identity.tls.clone(),
                cli.bind,
                cli.port,
                options,
            )
            .await?;
            if let Some(found) = devices
                .iter()
                .find(|device| discovery::match_selector(&selector.to, device))
                .cloned()
            {
                util::print_device(&found, cli.json);
                return Ok(());
            }

            if let Some(found) =
                discovery::search_tailscale_peer(&selector.to, &device_info, timeout).await?
            {
                util::print_device(&found, cli.json);
                return Ok(());
            }

            let options = DiscoveryOptions {
                timeout_secs: timeout,
                scan: true,
            };
            devices = discovery::discover_devices(
                device_info,
                identity.tls.clone(),
                cli.bind,
                cli.port,
                options,
            )
            .await?;
            if let Some(found) = devices
                .iter()
                .find(|device| discovery::match_selector(&selector.to, device))
                .cloned()
            {
                util::print_device(&found, cli.json);
                return Ok(());
            }
            anyhow::bail!("no matching device found");
        }
    }

    Ok(())
}
