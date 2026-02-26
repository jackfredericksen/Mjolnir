use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use mjolnir_core::scan::{ScanProgress, ScanRequest, ScanType};
use mjolnir_quarantine::QuarantineVault;
use mjolnir_scanner::ScanPipeline;

#[derive(Parser)]
#[command(
    name = "mjolnir",
    about = "Mjolnir - Cross-platform antivirus with quantum-enhanced detection",
    version,
    long_about = "A powerful antivirus engine featuring YARA signatures, heuristic analysis,\n\
                   quantum annealing-inspired ML classification, and post-quantum cryptography."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan files or directories for threats
    Scan {
        /// Paths to scan
        #[arg(required = true)]
        targets: Vec<PathBuf>,

        /// Directory containing YARA rules
        #[arg(long, default_value = "rules")]
        rules_dir: PathBuf,

        /// Quick scan mode (scan common locations)
        #[arg(short, long)]
        quick: bool,
    },

    /// Manage quarantined files
    Quarantine {
        #[command(subcommand)]
        action: QuarantineAction,
    },

    /// Check for signature updates
    Update {
        /// Update server URL
        #[arg(long, default_value = "https://updates.mjolnir.local/api/v1")]
        server: String,
    },

    /// Show system status and info
    Status,
}

#[derive(Subcommand)]
enum QuarantineAction {
    /// List quarantined files
    List,
    /// Restore a quarantined file
    Restore {
        /// UUID of the quarantined file
        id: String,
    },
    /// Permanently delete a quarantined file
    Delete {
        /// UUID of the quarantined file
        id: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("mjolnir=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            targets,
            rules_dir,
            quick: _,
        } => {
            println!("\n  ⚡ Mjolnir Antivirus Scanner\n");

            // Initialize pipeline
            let pipeline = if rules_dir.exists() {
                ScanPipeline::new(&rules_dir)?
            } else {
                println!("  [i] No rules directory found, using defaults");
                ScanPipeline::with_defaults()?
            };

            let progress = ScanProgress::new();

            let request = ScanRequest {
                targets,
                scan_type: ScanType::Custom,
                engines: vec![],
            };

            println!("  [*] Starting scan...\n");

            let report = pipeline.execute_scan(&request, &progress)?;

            // Print results
            println!("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("  Scan Complete");
            println!("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("  Files scanned:  {}", report.files_scanned);
            println!("  Files infected: {}", report.files_infected);
            println!("  Threats found:  {}", report.total_detections);
            println!("  Duration:       {}ms", report.duration_ms);
            println!();

            if !report.detections.is_empty() {
                println!("  Detections:");
                println!("  ──────────────────────────────────────────");
                for detection in &report.detections {
                    println!(
                        "  [{:?}] {} - {}",
                        detection.severity,
                        detection.file_path.display(),
                        detection.threat_name
                    );
                    println!(
                        "         Engine: {:?} | Confidence: {:.0}%",
                        detection.source,
                        detection.confidence * 100.0
                    );
                    println!("         {}", detection.details);
                    println!();
                }
            } else {
                println!("  No threats detected. System is clean.\n");
            }
        }

        Commands::Quarantine { action } => {
            let vault_dir =
                dirs_path().join("quarantine");
            let vault = QuarantineVault::new(&vault_dir)?;

            match action {
                QuarantineAction::List => {
                    let entries = vault.list()?;
                    if entries.is_empty() {
                        println!("\n  No files in quarantine.\n");
                    } else {
                        println!("\n  Quarantined Files:");
                        println!("  ──────────────────────────────────────────");
                        for entry in &entries {
                            println!("  ID:       {}", entry.id);
                            println!("  Original: {}", entry.original_path.display());
                            println!("  Threat:   {}", entry.threat_name);
                            println!("  Date:     {}", entry.quarantine_time);
                            println!("  Size:     {} bytes", entry.file_size);
                            println!();
                        }
                    }
                }
                QuarantineAction::Restore { id } => {
                    let uuid = uuid::Uuid::parse_str(&id)?;
                    let path = vault.restore(&uuid)?;
                    println!("\n  Restored to: {}\n", path.display());
                }
                QuarantineAction::Delete { id } => {
                    let uuid = uuid::Uuid::parse_str(&id)?;
                    vault.delete(&uuid)?;
                    println!("\n  Permanently deleted from quarantine.\n");
                }
            }
        }

        Commands::Update { server } => {
            println!("\n  Checking for updates...");
            let client = mjolnir_updater::UpdateClient::new(&server);

            match client.check_for_update().await {
                Ok(Some(info)) => {
                    println!("  Update available: v{}", info.version);
                    println!("  Description: {}", info.description);
                    println!("  Size: {} bytes", info.size_bytes);
                }
                Ok(None) => {
                    println!("  Signatures are up to date.\n");
                }
                Err(e) => {
                    println!("  Could not check for updates: {}\n", e);
                }
            }
        }

        Commands::Status => {
            println!("\n  ⚡ Mjolnir Antivirus Status");
            println!("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("  Version:          {}", env!("CARGO_PKG_VERSION"));
            println!("  Engines:          Signature, Heuristic, QAIO ML");
            println!("  Crypto:           Ed25519 + Dilithium3 (hybrid)");
            println!("  Key Exchange:     CRYSTALS-Kyber1024");
            println!("  Encryption:       AES-256-GCM");
            println!("  Hashing:          BLAKE3");
            println!();

            let vault_dir = dirs_path().join("quarantine");
            if vault_dir.exists() {
                let vault = QuarantineVault::new(&vault_dir)?;
                let entries = vault.list()?;
                println!("  Quarantined:      {} files", entries.len());
            }
            println!();
        }
    }

    Ok(())
}

fn dirs_path() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".mjolnir")
}
