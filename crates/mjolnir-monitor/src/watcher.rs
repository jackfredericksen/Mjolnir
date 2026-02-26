use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

use mjolnir_core::error::{MjolnirError, Result};
use mjolnir_core::scan::FileScanResult;
use mjolnir_scanner::ScanPipeline;

/// Real-time filesystem monitor that scans files on creation/modification
pub struct RealtimeMonitor {
    _watcher: RecommendedWatcher,
    shutdown_tx: mpsc::Sender<()>,
}

/// Event emitted when real-time monitoring detects something
#[derive(Debug, Clone)]
pub struct MonitorEvent {
    pub path: PathBuf,
    pub result: FileScanResult,
}

impl RealtimeMonitor {
    /// Start monitoring the given paths for file changes.
    /// Returns the monitor handle and a channel for receiving scan results.
    pub fn start(
        watch_paths: &[PathBuf],
        excluded_paths: Vec<PathBuf>,
        scanner: Arc<ScanPipeline>,
    ) -> Result<(Self, mpsc::Receiver<MonitorEvent>)> {
        let (event_tx, event_rx) = mpsc::channel::<MonitorEvent>(256);
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        // Create a channel for filesystem events
        let (fs_tx, fs_rx) = std::sync::mpsc::channel();

        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if let Ok(event) = res {
                let _ = fs_tx.send(event);
            }
        })
        .map_err(|e| MjolnirError::Io(std::io::Error::other(e.to_string())))?;

        // Watch all paths
        for path in watch_paths {
            if path.exists() {
                watcher
                    .watch(path, RecursiveMode::Recursive)
                    .map_err(|e| MjolnirError::Io(std::io::Error::other(e.to_string())))?;
                tracing::info!("Monitoring: {}", path.display());
            }
        }

        // Spawn processing task
        let excluded = excluded_paths;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        tracing::info!("Real-time monitor shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                        // Process filesystem events
                        while let Ok(event) = fs_rx.try_recv() {
                            match event.kind {
                                EventKind::Create(_) | EventKind::Modify(_) => {
                                    for path in &event.paths {
                                        // Skip excluded paths
                                        if excluded.iter().any(|e| path.starts_with(e)) {
                                            continue;
                                        }

                                        // Skip non-files
                                        if !path.is_file() {
                                            continue;
                                        }

                                        // Scan the file
                                        match scanner.scan_file(path) {
                                            Ok(result) => {
                                                if !result.is_clean() {
                                                    tracing::warn!(
                                                        "Threat detected in real-time: {} ({} detections)",
                                                        path.display(),
                                                        result.detections.len()
                                                    );
                                                }
                                                let _ = event_tx.send(MonitorEvent {
                                                    path: path.clone(),
                                                    result,
                                                }).await;
                                            }
                                            Err(e) => {
                                                tracing::debug!(
                                                    "Could not scan {}: {}",
                                                    path.display(),
                                                    e
                                                );
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        });

        Ok((
            Self {
                _watcher: watcher,
                shutdown_tx,
            },
            event_rx,
        ))
    }

    /// Stop the monitor
    pub async fn stop(self) {
        let _ = self.shutdown_tx.send(()).await;
    }
}
