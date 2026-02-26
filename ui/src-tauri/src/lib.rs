use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{Emitter, State};

use mjolnir_core::scan::{ScanProgress, ScanRequest, ScanType};
use mjolnir_quarantine::QuarantineVault;
use mjolnir_scanner::ScanPipeline;

struct AppState {
    scanner: Arc<ScanPipeline>,
    quarantine: Arc<QuarantineVault>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScanResult {
    scan_type: String,
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
    app_handle: tauri::AppHandle,
    state: State<'_, AppState>,
    scan_type: String,
    targets: Vec<String>,
) -> Result<ScanResult, String> {
    let scan_type_enum = match scan_type.as_str() {
        "quick" => ScanType::Quick,
        "full" => ScanType::Full,
        "threat" => ScanType::Threat,
        _ => ScanType::Custom,
    };

    let paths: Vec<PathBuf> = targets.iter().map(PathBuf::from).collect();
    let progress = Arc::new(ScanProgress::new());

    // Spawn a task that emits progress snapshots to the frontend every 150 ms
    let progress_for_emitter = Arc::clone(&progress);
    let app_for_emitter = app_handle.clone();
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut stop_rx => break,
                _ = tokio::time::sleep(Duration::from_millis(150)) => {
                    let snapshot = progress_for_emitter.snapshot();
                    let _ = app_for_emitter.emit("scan-progress", snapshot);
                }
            }
        }
    });

    // Run the blocking scan on a thread-pool thread
    let scanner = Arc::clone(&state.scanner);
    let progress_for_scan = Arc::clone(&progress);
    let request = ScanRequest {
        targets: paths,
        scan_type: scan_type_enum,
        engines: vec![],
    };

    let report = tokio::task::spawn_blocking(move || {
        scanner.execute_scan(&request, &progress_for_scan)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;

    // Stop emitter and push a final snapshot
    let _ = stop_tx.send(());
    let _ = app_handle.emit("scan-progress", progress.snapshot());

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
        scan_type,
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
async fn select_folder(app_handle: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let result = tokio::task::spawn_blocking(move || {
        app_handle.dialog().file().blocking_pick_folder()
    })
    .await
    .map_err(|e| e.to_string())?;

    Ok(result.map(|p| p.to_string()))
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
