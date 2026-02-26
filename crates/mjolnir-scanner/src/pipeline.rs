use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use rayon::prelude::*;
use walkdir::WalkDir;

use mjolnir_core::error::Result;
use mjolnir_core::scan::{FileScanResult, ScanProgress, ScanReport, ScanRequest, ScanType};
use mjolnir_core::threat::{Detection, DetectionEngine};
use mjolnir_crypto::FileHasher;
use mjolnir_heuristics::HeuristicEngine;
use mjolnir_ml::MLEngine;
use mjolnir_signatures::YaraEngine;

use crate::cache::ScanCache;

/// The main scan pipeline that orchestrates all detection engines
pub struct ScanPipeline {
    signature_engine: Arc<YaraEngine>,
    heuristic_engine: Arc<HeuristicEngine>,
    ml_engine: Arc<MLEngine>,
    cache: Arc<ScanCache>,
    max_file_size: u64,
}

impl ScanPipeline {
    pub fn new(rules_dir: &Path) -> Result<Self> {
        let signature_engine = Arc::new(YaraEngine::new(rules_dir)?);
        let heuristic_engine = Arc::new(HeuristicEngine::new());
        let ml_engine = Arc::new(MLEngine::new());
        let cache = Arc::new(ScanCache::new());

        Ok(Self {
            signature_engine,
            heuristic_engine,
            ml_engine,
            cache,
            max_file_size: 512 * 1024 * 1024, // 512 MB
        })
    }

    /// Create with default settings (no YARA rules directory)
    pub fn with_defaults() -> Result<Self> {
        let signature_engine = Arc::new(YaraEngine::with_database(
            mjolnir_signatures::SignatureDatabase::load_defaults(),
        ));
        let heuristic_engine = Arc::new(HeuristicEngine::new());
        let ml_engine = Arc::new(MLEngine::new());
        let cache = Arc::new(ScanCache::new());

        Ok(Self {
            signature_engine,
            heuristic_engine,
            ml_engine,
            cache,
            max_file_size: 512 * 1024 * 1024,
        })
    }

    /// Get reference to signature engine
    pub fn signature_engine(&self) -> &YaraEngine {
        &self.signature_engine
    }

    /// Scan a single file through all engines
    pub fn scan_file(&self, path: &Path) -> Result<FileScanResult> {
        let start = Instant::now();

        // Read file
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

        // Check cache
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

        // Run all engines in parallel
        let sig_engine = Arc::clone(&self.signature_engine);
        let heur_engine = Arc::clone(&self.heuristic_engine);
        let ml_engine = Arc::clone(&self.ml_engine);

        let path_buf = path.to_path_buf();
        let data_arc = Arc::new(data);

        let ((sig_result, heur_result), ml_result) = rayon::join(
            || {
                rayon::join(
                    || {
                        let data = Arc::clone(&data_arc);
                        sig_engine.scan_file(&path_buf, &data)
                    },
                    || {
                        let data = Arc::clone(&data_arc);
                        heur_engine.scan_file(&path_buf, &data)
                    },
                )
            },
            || {
                let data = Arc::clone(&data_arc);
                ml_engine.scan_file(&path_buf, &data)
            },
        );

        // Merge detections
        let mut detections = Vec::new();

        if let Ok(sigs) = sig_result {
            detections.extend(sigs);
        }
        if let Ok(heurs) = heur_result {
            detections.extend(heurs);
        }
        if let Ok(mls) = ml_result {
            detections.extend(mls);
        }

        // Update cache
        self.cache
            .insert(file_hash.clone(), db_version, detections.is_empty());

        Ok(FileScanResult {
            file_path: path.to_path_buf(),
            file_hash,
            file_size: metadata.len(),
            detections,
            scan_duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Scan a directory tree using rayon for parallelism
    pub fn scan_directory(
        &self,
        root: &Path,
        progress: &ScanProgress,
    ) -> Result<ScanReport> {
        let started_at = Utc::now();
        let start = Instant::now();

        // Collect all files
        let files: Vec<PathBuf> = WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.into_path())
            .collect();

        progress.set_total(files.len() as u64);

        // Scan in parallel
        let results: Vec<FileScanResult> = files
            .par_iter()
            .filter_map(|path| {
                progress.set_current(path.clone());
                let result = self.scan_file(path).ok()?;
                if !result.is_clean() {
                    progress.add_threat();
                }
                progress.increment();
                Some(result)
            })
            .collect();

        // Build report
        let all_detections: Vec<Detection> = results
            .iter()
            .flat_map(|r| r.detections.clone())
            .collect();

        let files_infected = results.iter().filter(|r| !r.is_clean()).count() as u64;

        Ok(ScanReport {
            scan_type: ScanType::Custom,
            started_at,
            completed_at: Utc::now(),
            files_scanned: results.len() as u64,
            files_infected,
            total_detections: all_detections.len() as u64,
            detections: all_detections,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Resolve scan targets based on scan type.
    /// Returns paths that exist on the current OS; Custom returns empty (caller provides targets).
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
                if let Ok(tmp) = std::env::var("TEMP") {
                    t.push(PathBuf::from(tmp));
                }
                #[cfg(not(target_os = "windows"))]
                {
                    t.push(PathBuf::from("/tmp"));
                    t.push(PathBuf::from("/var/tmp"));
                }
                t
            }

            ScanType::Full => vec![home],

            ScanType::Threat => {
                let mut t = Vec::new();

                #[cfg(target_os = "macos")]
                {
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
                }

                #[cfg(target_os = "linux")]
                {
                    t.extend([
                        PathBuf::from("/tmp"),
                        PathBuf::from("/var/tmp"),
                        PathBuf::from("/dev/shm"),
                        PathBuf::from("/etc/init.d"),
                        PathBuf::from("/etc/cron.d"),
                        PathBuf::from("/etc/cron.daily"),
                        PathBuf::from("/etc/cron.weekly"),
                        PathBuf::from("/etc/profile.d"),
                        PathBuf::from("/usr/local/bin"),
                        home.join(".config/autostart"),
                        home.join(".bashrc"),
                        home.join(".bash_profile"),
                        home.join(".profile"),
                        home.join(".zshrc"),
                    ]);
                }

                #[cfg(target_os = "windows")]
                {
                    if let Ok(appdata) = std::env::var("APPDATA") {
                        let appdata = PathBuf::from(&appdata);
                        t.push(
                            appdata.join(
                                "Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                            ),
                        );
                        t.push(appdata.join("Roaming"));
                    }
                    if let Ok(tmp) = std::env::var("TEMP") {
                        t.push(PathBuf::from(tmp));
                    }
                    if let Ok(windir) = std::env::var("WINDIR") {
                        let windir = PathBuf::from(&windir);
                        t.push(windir.join("System32\\drivers"));
                        t.push(windir.join("Temp"));
                        t.push(windir.join("Tasks"));
                    }
                    if let Ok(programdata) = std::env::var("PROGRAMDATA") {
                        t.push(PathBuf::from(programdata));
                    }
                }

                t
            }

            ScanType::Custom => vec![],
        };

        targets.retain(|p| p.exists());
        targets
    }

    /// Scan specific targets from a scan request
    pub fn execute_scan(
        &self,
        request: &ScanRequest,
        progress: &ScanProgress,
    ) -> Result<ScanReport> {
        let started_at = Utc::now();
        let start = Instant::now();

        // Resolve targets: for typed scans use OS locations; for Custom use provided targets
        let resolved: Vec<PathBuf> = if request.scan_type == ScanType::Custom {
            request.targets.clone()
        } else {
            Self::resolve_targets(request.scan_type)
        };

        // Collect all files from all resolved targets
        let mut all_files: Vec<PathBuf> = Vec::new();
        for target in &resolved {
            if target.is_file() {
                all_files.push(target.clone());
            } else if target.is_dir() {
                let files: Vec<PathBuf> = WalkDir::new(target)
                    .follow_links(false)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().is_file())
                    .map(|e| e.into_path())
                    .collect();
                all_files.extend(files);
            }
        }

        progress.set_total(all_files.len() as u64);

        let results: Vec<FileScanResult> = all_files
            .par_iter()
            .filter_map(|path| {
                progress.set_current(path.clone());
                let result = self.scan_file(path).ok()?;
                if !result.is_clean() {
                    progress.add_threat();
                }
                progress.increment();
                Some(result)
            })
            .collect();

        let all_detections: Vec<Detection> = results
            .iter()
            .flat_map(|r| r.detections.clone())
            .collect();

        let files_infected = results.iter().filter(|r| !r.is_clean()).count() as u64;

        Ok(ScanReport {
            scan_type: request.scan_type,
            started_at,
            completed_at: Utc::now(),
            files_scanned: results.len() as u64,
            files_infected,
            total_detections: all_detections.len() as u64,
            detections: all_detections,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}
