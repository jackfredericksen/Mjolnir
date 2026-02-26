export type ViewType = 'dashboard' | 'scan' | 'quarantine' | 'settings'

export type ThreatSeverity = 'Low' | 'Medium' | 'High' | 'Critical'

export type DetectionSource = 'Signature' | 'Heuristic' | 'MachineLearning' | 'StaticAnalysis'

export interface Detection {
  id: string
  file_path: string
  file_hash: string
  threat_name: string
  severity: ThreatSeverity
  source: DetectionSource
  confidence: number
  details: string
  timestamp: string
}

export interface ScanProgressSnapshot {
  files_scanned: number
  files_total: number
  threats_found: number
  current_file: string
  elapsed: number
}

export interface ScanReport {
  scan_type: string
  started_at: string
  completed_at: string
  files_scanned: number
  files_infected: number
  total_detections: number
  detections: Detection[]
  duration_ms: number
}

export interface QuarantineEntry {
  id: string
  original_path: string
  threat_name: string
  quarantine_time: string
  file_hash: string
  file_size: number
}

export interface SystemStatus {
  version: string
  engines: string[]
  realtime_enabled: boolean
  signature_db_version: number
  quarantine_count: number
  last_scan: string | null
}
