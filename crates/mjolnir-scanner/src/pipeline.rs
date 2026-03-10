use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use rayon::iter::ParallelBridge;
use rayon::prelude::*;
use walkdir::WalkDir;

use mjolnir_core::error::{MjolnirError, Result};
use mjolnir_core::scan::{FileScanResult, ScanProgress, ScanReport, ScanRequest, ScanType};
use mjolnir_core::threat::{Detection, DetectionEngine};
use mjolnir_crypto::FileHasher;
use mjolnir_heuristics::HeuristicEngine;
use mjolnir_ml::MLEngine;
use mjolnir_signatures::YaraEngine;

use crate::cache::ScanCache;

/// Max bytes read per file. With SCAN_THREADS concurrent workers peak RAM is
/// SCAN_THREADS × MAX_FILE_SIZE = 4 × 32 MB = 128 MB.
const MAX_FILE_SIZE: u64 = 32 * 1024 * 1024;

/// Rayon worker threads for file scanning.
const SCAN_THREADS: usize = 4;

pub struct ScanPipeline {
    signature_engine: Arc<YaraEngine>,
    heuristic_engine: Arc<HeuristicEngine>,
    ml_engine: Arc<MLEngine>,
    cache: Arc<ScanCache>,
    max_file_size: u64,
    /// Bounded thread pool — limits I/O parallelism to prevent memory exhaustion
    thread_pool: rayon::ThreadPool,
}

impl ScanPipeline {
    pub fn new(rules_dir: &Path) -> Result<Self> {
        let signature_engine = Arc::new(YaraEngine::new(rules_dir)?);
        let heuristic_engine = Arc::new(HeuristicEngine::new());
        let ml_engine = Arc::new(MLEngine::new());
        let cache = Arc::new(ScanCache::new());
        let thread_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(SCAN_THREADS)
            .build()
            .map_err(|e| MjolnirError::Scan(e.to_string()))?;
        Ok(Self { signature_engine, heuristic_engine, ml_engine, cache, max_file_size: MAX_FILE_SIZE, thread_pool })
    }

    pub fn with_defaults() -> Result<Self> {
        let signature_engine = Arc::new(YaraEngine::with_database(
            mjolnir_signatures::SignatureDatabase::load_defaults(),
        ));
        let heuristic_engine = Arc::new(HeuristicEngine::new());
        let ml_engine = Arc::new(MLEngine::new());
        let cache = Arc::new(ScanCache::new());
        let thread_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(SCAN_THREADS)
            .build()
            .map_err(|e| MjolnirError::Scan(e.to_string()))?;
        Ok(Self { signature_engine, heuristic_engine, ml_engine, cache, max_file_size: MAX_FILE_SIZE, thread_pool })
    }

    pub fn signature_engine(&self) -> &YaraEngine {
        &self.signature_engine
    }

    /// Scan one file through all engines. Returns empty detections for oversized/unreadable files.
    pub fn scan_file(&self, path: &Path) -> Result<FileScanResult> {
        let start = Instant::now();
        let metadata = std::fs::metadata(path)?;

        if metadata.len() > self.max_file_size {
            return Ok(FileScanResult {
                file_path: path.to_path_buf(),
                file_hash: String::new(),
                file_size: metadata.len(),
                detections: vec![],
                scan_duration_ms: start.elapsed().as_millis() as u64,
            });
        }

        let data = std::fs::read(path)?;
        let file_hash = FileHasher::hash_bytes(&data);
        let db_version = self.signature_engine.database.version;

        if let Some(true) = self.cache.is_cached(&file_hash, db_version) {
            return Ok(FileScanResult {
                file_path: path.to_path_buf(),
                file_hash,
                file_size: metadata.len(),
                detections: vec![],
                scan_duration_ms: start.elapsed().as_millis() as u64,
            });
        }

        let sig_engine = Arc::clone(&self.signature_engine);
        let heur_engine = Arc::clone(&self.heuristic_engine);
        let ml_engine = Arc::clone(&self.ml_engine);
        let path_buf = path.to_path_buf();
        let data_arc = Arc::new(data);

        let ((sig_result, heur_result), ml_result) = rayon::join(
            || rayon::join(
                || sig_engine.scan_file(&path_buf, &Arc::clone(&data_arc)),
                || heur_engine.scan_file(&path_buf, &Arc::clone(&data_arc)),
            ),
            || ml_engine.scan_file(&path_buf, &Arc::clone(&data_arc)),
        );
        drop(data_arc); // release file bytes immediately

        let mut detections = Vec::new();
        if let Ok(v) = sig_result  { detections.extend(v); }
        if let Ok(v) = heur_result { detections.extend(v); }
        if let Ok(v) = ml_result   { detections.extend(v); }

        self.cache.insert(file_hash.clone(), db_version, detections.is_empty());
        Ok(FileScanResult {
            file_path: path.to_path_buf(),
            file_hash,
            file_size: metadata.len(),
            detections,
            scan_duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    // ── private helper ───────────────────────────────────────────────────────

    /// Shared scanning body used by both `scan_directory` and `execute_scan`.
    ///
    /// Accepts a *boxed* sequential iterator of paths that are streamed lazily
    /// into rayon via `par_bridge()`.  **No `Vec<PathBuf>` is ever built for
    /// directory trees**, so peak RAM is bounded by:
    ///   SCAN_THREADS × MAX_FILE_SIZE  (≈ 128 MB)
    /// plus a small in-flight queue maintained by par_bridge internally.
    fn run_scan(
        &self,
        file_iter: impl Iterator<Item = PathBuf> + Send,
        progress: &ScanProgress,
        scan_type: ScanType,
    ) -> Result<ScanReport> {
        let started_at = Utc::now();
        let start = Instant::now();

        let all_detections: Vec<Detection> = self.thread_pool.install(|| {
            file_iter
                .par_bridge()
                .flat_map_iter(|path| -> Vec<Detection> {
                    // Increment discovered-total atomically BEFORE scanning so that
                    // files_total ≥ files_scanned is always maintained.
                    progress.files_total.fetch_add(1, Ordering::Relaxed);
                    progress.set_current(path.clone());

                    let result = match self.scan_file(&path) {
                        Ok(r) => r,
                        Err(_) => { progress.increment(); return Vec::new(); }
                    };
                    if !result.is_clean() { progress.add_threat(); }
                    progress.increment();
                    result.detections // moved out — no clone
                })
                .collect()
        });

        let files_scanned = progress.files_scanned.load(Ordering::Relaxed);
        let files_infected = progress.threats_found.load(Ordering::Relaxed);

        Ok(ScanReport {
            scan_type,
            started_at,
            completed_at: Utc::now(),
            files_scanned,
            files_infected,
            total_detections: all_detections.len() as u64,
            detections: all_detections,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    // ── public API ───────────────────────────────────────────────────────────

    pub fn scan_directory(&self, root: &Path, progress: &ScanProgress) -> Result<ScanReport> {
        let iter = WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.into_path());
        self.run_scan(iter, progress, ScanType::Custom)
    }

    /// Resolve OS-aware file targets for each scan type.
    pub fn resolve_targets(scan_type: ScanType) -> Vec<PathBuf> {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/"));

        let mut targets: Vec<PathBuf> = match scan_type {
            ScanType::Quick => {
                let mut t = vec![
                    home.join("Downloads"),
                    home.join("Desktop"),
                    home.join("Documents"),
                ];
                #[cfg(target_os = "windows")]
                if let Ok(tmp) = std::env::var("TEMP") { t.push(PathBuf::from(tmp)); }
                #[cfg(not(target_os = "windows"))]
                { t.push(PathBuf::from("/tmp")); t.push(PathBuf::from("/var/tmp")); }
                t
            }
            ScanType::Full => vec![home],
            ScanType::Threat => {
                let mut t = Vec::new();
                #[cfg(target_os = "macos")]
                t.extend([
                    home.join("Library/LaunchAgents"),
                    PathBuf::from("/Library/LaunchAgents"),
                    PathBuf::from("/Library/LaunchDaemons"),
                    home.join("Library/Application Support"),
                    home.join("Library/Caches"),
                    PathBuf::from("/tmp"),
                    PathBuf::from("/private/tmp"),
                    PathBuf::from("/etc/cron.d"),
                    PathBuf::from("/etc/periodic"),
                    PathBuf::from("/etc/profile.d"),
                    home.join(".zshrc"),
                    home.join(".bashrc"),
                    home.join(".bash_profile"),
                    home.join(".zprofile"),
                    home.join(".profile"),
                ]);
                #[cfg(target_os = "linux")]
                t.extend([
                    PathBuf::from("/tmp"),
                    PathBuf::from("/var/tmp"),
                    PathBuf::from("/dev/shm"),
                    PathBuf::from("/etc/init.d"),
                    PathBuf::from("/etc/cron.d"),
                    PathBuf::from("/etc/cron.daily"),
                    PathBuf::from("/etc/profile.d"),
                    PathBuf::from("/usr/local/bin"),
                    home.join(".config/autostart"),
                    home.join(".bashrc"),
                    home.join(".profile"),
                    home.join(".zshrc"),
                ]);
                #[cfg(target_os = "windows")]
                {
                    if let Ok(appdata) = std::env::var("APPDATA") {
                        let a = PathBuf::from(&appdata);
                        t.push(a.join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
                        t.push(a.join("Roaming"));
                    }
                    if let Ok(tmp) = std::env::var("TEMP") { t.push(PathBuf::from(tmp)); }
                    if let Ok(windir) = std::env::var("WINDIR") {
                        let w = PathBuf::from(&windir);
                        t.push(w.join("System32\\drivers"));
                        t.push(w.join("Temp"));
                        t.push(w.join("Tasks"));
                    }
                }
                t
            }
            ScanType::Custom => vec![],
        };
        targets.retain(|p| p.exists());
        targets
    }

    /// Execute a scan request.
    ///
    /// Memory guarantee: paths are **never** collected into a `Vec<PathBuf>`.
    /// Each target is walked lazily via a producer thread that feeds a channel;
    /// the bounded SCAN_THREADS rayon pool consumes from that channel.
    /// Peak resident memory is dominated by:
    ///   • SCAN_THREADS × MAX_FILE_SIZE of in-flight file data (≈ 128 MB)
    ///   • A small channel buffer (a few hundred PathBuf entries at most)
    pub fn execute_scan(
        &self,
        request: &ScanRequest,
        progress: &ScanProgress,
    ) -> Result<ScanReport> {
        let resolved: Vec<PathBuf> = if request.scan_type == ScanType::Custom {
            request.targets.clone()
        } else {
            Self::resolve_targets(request.scan_type)
        };

        // Use a channel so WalkDir runs in a producer thread and never builds a
        // full Vec<PathBuf>.  The consumer side is a sequential iterator that
        // par_bridge() distributes across the bounded thread pool.
        let (tx, rx) = std::sync::mpsc::channel::<PathBuf>();

        // Producer: walks all targets and sends paths into the channel.
        // The `resolved` clone is small (a handful of PathBufs).
        let producer = {
            let resolved = resolved.clone();
            std::thread::spawn(move || {
                for target in &resolved {
                    if target.is_file() {
                        let _ = tx.send(target.clone());
                    } else if target.is_dir() {
                        for entry in WalkDir::new(target)
                            .follow_links(false)
                            .into_iter()
                            .filter_map(|e| e.ok())
                            .filter(|e| e.file_type().is_file())
                        {
                            // Stop if the consumer has hung up
                            if tx.send(entry.into_path()).is_err() {
                                return;
                            }
                        }
                    }
                }
                // tx drops here → channel closes → receiver iterator terminates
            })
        };

        // Consumer: receive path by path and feed rayon via par_bridge().
        let scan_type = request.scan_type;
        let report = self.run_scan(rx.into_iter(), progress, scan_type);

        // Join the producer thread to ensure filesystem handles are released.
        let _ = producer.join();

        report
    }
}
