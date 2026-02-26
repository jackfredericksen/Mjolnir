use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::State;

use mjolnir_core::scan::{ScanProgress, ScanRequest, ScanType};
use mjolnir_quarantine::QuarantineVault;
use mjolnir_scanner::ScanPipeline;

struct AppState {
    scanner: Arc<ScanPipeline>,
    quarantine: Arc<QuarantineVault>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScanResult {
    files_scanned: u64,
    files_infected: u64,
    total_detections: u64,
    duration_ms: u64,
    detections: Vec<DetectionInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DetectionInfo {
    file_path: String,
    threat_name: String,
    severity: String,
    source: String,
    confidence: f64,
    details: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct QuarantineInfo {
    id: String,
    original_path: String,
    threat_name: String,
    quarantine_time: String,
    file_size: u64,
}

#[tauri::command]
async fn start_scan(
    state: State<'_, AppState>,
    targets: Vec<String>,
) -> Result<ScanResult, String> {
    let paths: Vec<PathBuf> = targets.iter().map(PathBuf::from).collect();
    let progress = ScanProgress::new();

    let request = ScanRequest {
        targets: paths,
        scan_type: ScanType::Custom,
        engines: vec![],
    };

    let report = state
        .scanner
        .execute_scan(&request, &progress)
        .map_err(|e| e.to_string())?;

    let detections: Vec<DetectionInfo> = report
        .detections
        .iter()
        .map(|d| DetectionInfo {
            file_path: d.file_path.display().to_string(),
            threat_name: d.threat_name.clone(),
            severity: format!("{}", d.severity),
            source: format!("{}", d.source),
            confidence: d.confidence,
            details: d.details.clone(),
        })
        .collect();

    Ok(ScanResult {
        files_scanned: report.files_scanned,
        files_infected: report.files_infected,
        total_detections: report.total_detections,
        duration_ms: report.duration_ms,
        detections,
    })
}

#[tauri::command]
async fn get_quarantine_list(
    state: State<'_, AppState>,
) -> Result<Vec<QuarantineInfo>, String> {
    let entries = state.quarantine.list().map_err(|e| e.to_string())?;

    Ok(entries
        .iter()
        .map(|e| QuarantineInfo {
            id: e.id.to_string(),
            original_path: e.original_path.display().to_string(),
            threat_name: e.threat_name.clone(),
            quarantine_time: e.quarantine_time.to_rfc3339(),
            file_size: e.file_size,
        })
        .collect())
}

#[tauri::command]
async fn restore_from_quarantine(
    state: State<'_, AppState>,
    id: String,
) -> Result<String, String> {
    let uuid = uuid::Uuid::parse_str(&id).map_err(|e| e.to_string())?;
    let path = state
        .quarantine
        .restore(&uuid)
        .map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}

#[tauri::command]
async fn delete_from_quarantine(
    state: State<'_, AppState>,
    id: String,
) -> Result<(), String> {
    let uuid = uuid::Uuid::parse_str(&id).map_err(|e| e.to_string())?;
    state
        .quarantine
        .delete(&uuid)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn select_folder() -> Result<Option<String>, String> {
    // This will be handled by tauri-plugin-dialog in the frontend
    Ok(None)
}

pub fn run() {
    // Initialize scanner
    let scanner = ScanPipeline::with_defaults()
        .expect("Failed to initialize scan pipeline");

    // Initialize quarantine vault
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    let vault_dir = PathBuf::from(home).join(".mjolnir").join("quarantine");
    let quarantine =
        QuarantineVault::new(&vault_dir).expect("Failed to initialize quarantine vault");

    let state = AppState {
        scanner: Arc::new(scanner),
        quarantine: Arc::new(quarantine),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            start_scan,
            get_quarantine_list,
            restore_from_quarantine,
            delete_from_quarantine,
            select_folder,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
