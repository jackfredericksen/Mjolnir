import { useState, useEffect, useRef } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import {
  BoltIcon,
  MagnifyingGlassIcon,
  ShieldExclamationIcon,
  FolderOpenIcon,
  PlayIcon,
  StopCircleIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  DocumentMagnifyingGlassIcon,
} from '@heroicons/react/24/outline'
import { useAppStore } from '../store'
import { SCAN_TYPES } from '../types'
import type { ScanType, ScanProgressSnapshot } from '../types'
import toast from 'react-hot-toast'

const SCAN_ICONS: Record<ScanType, React.ElementType> = {
  quick: BoltIcon,
  full: MagnifyingGlassIcon,
  threat: ShieldExclamationIcon,
  custom: FolderOpenIcon,
}

const SCAN_COLORS: Record<ScanType, string> = {
  quick: 'mjolnir',
  full: 'purple',
  threat: 'orange',
  custom: 'gray',
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  const m = Math.floor(ms / 60000)
  const s = Math.floor((ms % 60000) / 1000)
  return `${m}m ${s}s`
}

function formatElapsed(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(0)}s`
  const m = Math.floor(ms / 60000)
  const s = Math.floor((ms % 60000) / 1000)
  return `${m}m ${s}s`
}

export function ScanView() {
  const {
    isScanning,
    setIsScanning,
    selectedScanType,
    setSelectedScanType,
    scanProgress,
    setScanProgress,
    lastReport,
    setLastReport,
    addDetections,
    clearDetections,
  } = useAppStore()

  const [customPath, setCustomPath] = useState('')
  const unlistenRef = useRef<(() => void) | null>(null)

  // Subscribe to real-time progress events from Rust
  useEffect(() => {
    let active = true
    listen<ScanProgressSnapshot>('scan-progress', (event) => {
      if (active) setScanProgress(event.payload)
    }).then((unlisten) => {
      unlistenRef.current = unlisten
    })
    return () => {
      active = false
      unlistenRef.current?.()
    }
  }, [setScanProgress])

  // Whether we're still in the file-enumeration phase (files haven't been counted yet)
  const isEnumerating = isScanning && (!scanProgress || scanProgress.files_total === 0)

  const progressPercent =
    scanProgress && scanProgress.files_total > 0
      ? Math.min(100, Math.round((scanProgress.files_scanned / scanProgress.files_total) * 100))
      : 0

  const filesPerSec =
    scanProgress && scanProgress.elapsed > 0
      ? Math.round((scanProgress.files_scanned / (scanProgress.elapsed / 1000)))
      : 0

  const startScan = async () => {
    if (selectedScanType === 'custom' && !customPath.trim()) {
      toast.error('Please enter a path to scan')
      return
    }

    setIsScanning(true)
    setScanProgress(null)
    clearDetections()
    const toastId = toast.loading('Initialising scan...')

    try {
      const report = await invoke<any>('start_scan', {
        scanType: selectedScanType,
        targets: selectedScanType === 'custom' ? [customPath.trim()] : [],
      })

      setLastReport(report)
      setScanProgress(null)

      if (report.total_detections > 0) {
        addDetections(report.detections)
        toast.error(`Found ${report.total_detections} threat(s)!`, { id: toastId })
      } else {
        toast.success('Scan complete — no threats found', { id: toastId })
      }
    } catch (error) {
      toast.error(`Scan failed: ${error}`, { id: toastId })
    } finally {
      setIsScanning(false)
    }
  }

  const selectFolder = async () => {
    try {
      const selected = await invoke<string | null>('select_folder')
      if (selected) setCustomPath(selected)
    } catch {
      // dialog cancelled
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Scan</h2>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
          Choose a scan type to protect your system
        </p>
      </div>

      {/* Scan Type Cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {SCAN_TYPES.map((config) => {
          const Icon = SCAN_ICONS[config.id]
          const color = SCAN_COLORS[config.id]
          const isSelected = selectedScanType === config.id

          return (
            <button
              key={config.id}
              onClick={() => !isScanning && setSelectedScanType(config.id)}
              disabled={isScanning}
              className={`relative text-left p-5 rounded-xl border-2 transition-all duration-200 ${
                isSelected
                  ? color === 'mjolnir'
                    ? 'border-mjolnir-500 bg-mjolnir-50 dark:bg-mjolnir-950/40'
                    : color === 'purple'
                    ? 'border-purple-500 bg-purple-50 dark:bg-purple-950/40'
                    : color === 'orange'
                    ? 'border-orange-500 bg-orange-50 dark:bg-orange-950/40'
                    : 'border-gray-500 bg-gray-50 dark:bg-gray-800/60'
                  : 'border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 hover:border-gray-300 dark:hover:border-gray-600'
              } ${isScanning ? 'opacity-60 cursor-not-allowed' : 'cursor-pointer'}`}
            >
              {/* Selected indicator */}
              {isSelected && (
                <span className="absolute top-3 right-3 w-2 h-2 rounded-full bg-current opacity-70" />
              )}

              {/* Icon */}
              <div
                className={`w-10 h-10 rounded-lg flex items-center justify-center mb-3 ${
                  isSelected
                    ? color === 'mjolnir'
                      ? 'bg-mjolnir-100 dark:bg-mjolnir-900/60 text-mjolnir-600 dark:text-mjolnir-400'
                      : color === 'purple'
                      ? 'bg-purple-100 dark:bg-purple-900/60 text-purple-600 dark:text-purple-400'
                      : color === 'orange'
                      ? 'bg-orange-100 dark:bg-orange-900/60 text-orange-600 dark:text-orange-400'
                      : 'bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-300'
                    : 'bg-gray-100 dark:bg-gray-800 text-gray-500 dark:text-gray-400'
                }`}
              >
                <Icon className="w-5 h-5" />
              </div>

              {/* Label + estimate */}
              <div className="font-semibold text-gray-900 dark:text-white text-sm">
                {config.label}
              </div>
              <div className="flex items-center space-x-1 mt-0.5 mb-2">
                <ClockIcon className="w-3 h-3 text-gray-400" />
                <span className="text-xs text-gray-400">{config.estimate}</span>
              </div>

              {/* Description */}
              <p className="text-xs text-gray-500 dark:text-gray-400 leading-snug mb-3">
                {config.description}
              </p>

              {/* Coverage chips */}
              <div className="flex flex-wrap gap-1">
                {config.coverage.map((item) => (
                  <span
                    key={item}
                    className="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400"
                  >
                    {item}
                  </span>
                ))}
              </div>
            </button>
          )
        })}
      </div>

      {/* Custom path input */}
      {selectedScanType === 'custom' && (
        <div className="flex space-x-3">
          <input
            type="text"
            value={customPath}
            onChange={(e) => setCustomPath(e.target.value)}
            placeholder="Enter path to scan (e.g. /Users/you/Downloads)"
            className="flex-1 px-4 py-3 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-xl text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-mjolnir-500"
            disabled={isScanning}
          />
          <button
            onClick={selectFolder}
            disabled={isScanning}
            title="Browse for folder"
            className="px-4 py-3 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800 text-gray-600 dark:text-gray-300 rounded-xl transition-colors disabled:opacity-50"
          >
            <FolderOpenIcon className="w-5 h-5" />
          </button>
        </div>
      )}

      {/* Start button */}
      <button
        onClick={isScanning ? undefined : startScan}
        disabled={isScanning}
        className={`w-full py-4 rounded-xl font-semibold text-base flex items-center justify-center space-x-3 transition-all duration-200 ${
          isScanning
            ? 'bg-red-600/20 text-red-400 border border-red-600/30 cursor-not-allowed'
            : 'bg-mjolnir-600 hover:bg-mjolnir-700 text-white shadow-lg shadow-mjolnir-900/20'
        }`}
      >
        {isScanning ? (
          <>
            <StopCircleIcon className="w-5 h-5 animate-pulse" />
            <span>Scanning in progress…</span>
          </>
        ) : (
          <>
            <PlayIcon className="w-5 h-5" />
            <span>
              Start{' '}
              {SCAN_TYPES.find((t) => t.id === selectedScanType)?.label ?? 'Scan'}
            </span>
          </>
        )}
      </button>

      {/* Live Progress Panel */}
      {isScanning && (
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-gray-900 dark:text-white flex items-center space-x-2">
              <DocumentMagnifyingGlassIcon className="w-4 h-4 text-mjolnir-500" />
              <span>Scanning…</span>
            </h3>
            <div className="flex items-center space-x-4 text-xs text-gray-500 dark:text-gray-400">
              {scanProgress && (
                <>
                  <span>{filesPerSec} files/s</span>
                  <span>{formatElapsed(scanProgress.elapsed)} elapsed</span>
                </>
              )}
            </div>
          </div>

          {/* Progress bar */}
          <div>
            <div className="flex justify-between text-xs text-gray-500 dark:text-gray-400 mb-1.5">
              {isEnumerating ? (
                <span className="italic text-gray-400">Enumerating files…</span>
              ) : (
                <span>
                  {scanProgress?.files_scanned ?? 0} /{' '}
                  {scanProgress?.files_total ?? '…'} files
                </span>
              )}
              {!isEnumerating && <span>{progressPercent}%</span>}
            </div>
            <div className="w-full bg-gray-100 dark:bg-gray-800 rounded-full h-2 overflow-hidden">
              {isEnumerating ? (
                /* Indeterminate animated bar while counting files */
                <div className="h-2 w-full rounded-full bg-gradient-to-r from-mjolnir-500 via-mjolnir-400 to-mjolnir-500 bg-[length:200%_100%] animate-pulse" />
              ) : (
                <div
                  className="h-2 rounded-full bg-gradient-to-r from-mjolnir-500 to-mjolnir-400 transition-all duration-300"
                  style={{ width: `${progressPercent}%` }}
                />
              )}
            </div>
          </div>

          {/* Stats row */}
          <div className="grid grid-cols-3 gap-3">
            <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3 text-center">
              <div className="text-lg font-bold text-gray-900 dark:text-white">
                {isEnumerating ? (
                  <span className="text-gray-400 animate-pulse">…</span>
                ) : (
                  scanProgress?.files_scanned ?? 0
                )}
              </div>
              <div className="text-[11px] text-gray-500">Files scanned</div>
            </div>
            <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3 text-center">
              <div className="text-lg font-bold text-red-500">
                {scanProgress?.threats_found ?? 0}
              </div>
              <div className="text-[11px] text-gray-500">Threats found</div>
            </div>
            <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3 text-center">
              <div className="text-lg font-bold text-gray-900 dark:text-white">
                {scanProgress ? formatElapsed(scanProgress.elapsed) : '—'}
              </div>
              <div className="text-[11px] text-gray-500">Elapsed</div>
            </div>
          </div>

          {/* Current file */}
          {scanProgress?.current_file && (
            <p className="text-[11px] text-gray-400 dark:text-gray-500 font-mono truncate">
              {scanProgress.current_file}
            </p>
          )}
        </div>
      )}

      {/* Results */}
      {lastReport && !isScanning && (
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6 space-y-5">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-semibold text-gray-900 dark:text-white">
              Scan Results
            </h3>
            <span className="text-xs text-gray-400 capitalize">
              {lastReport.scan_type} scan
            </span>
          </div>

          {/* Summary stats */}
          <div className="grid grid-cols-4 gap-3">
            {[
              { label: 'Files Scanned', value: lastReport.files_scanned, color: 'text-gray-900 dark:text-white' },
              { label: 'Infected', value: lastReport.files_infected, color: 'text-red-600 dark:text-red-400' },
              { label: 'Detections', value: lastReport.total_detections, color: 'text-orange-600 dark:text-orange-400' },
              { label: 'Duration', value: formatDuration(lastReport.duration_ms), color: 'text-gray-900 dark:text-white' },
            ].map(({ label, value, color }) => (
              <div
                key={label}
                className="bg-gray-50 dark:bg-gray-800 rounded-xl p-4 text-center"
              >
                <div className={`text-2xl font-bold ${color}`}>{value}</div>
                <div className="text-xs text-gray-500 mt-0.5">{label}</div>
              </div>
            ))}
          </div>

          {/* Clean / Threat list */}
          {lastReport.total_detections === 0 ? (
            <div className="flex items-center space-x-3 p-4 bg-green-50 dark:bg-green-950/40 border border-green-200 dark:border-green-800/50 rounded-xl">
              <CheckCircleIcon className="w-6 h-6 text-green-500 shrink-0" />
              <div>
                <p className="text-sm font-medium text-green-800 dark:text-green-200">
                  No threats detected
                </p>
                <p className="text-xs text-green-600 dark:text-green-400 mt-0.5">
                  Scanned {lastReport.files_scanned} file
                  {lastReport.files_scanned !== 1 ? 's' : ''} in{' '}
                  {formatDuration(lastReport.duration_ms)}
                </p>
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              {lastReport.detections.map((detection: any, i: number) => (
                <div
                  key={i}
                  className="p-4 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800/50 rounded-xl"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center space-x-2 min-w-0">
                      <ExclamationTriangleIcon className="w-4 h-4 text-red-500 shrink-0" />
                      <span className="font-medium text-red-800 dark:text-red-200 text-sm truncate">
                        {detection.threat_name}
                      </span>
                    </div>
                    <SeverityBadge severity={detection.severity} />
                  </div>

                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-2 font-mono truncate">
                    {detection.file_path}
                  </p>

                  <div className="flex items-center space-x-3 mt-2 text-xs text-gray-400">
                    <span className="px-1.5 py-0.5 rounded bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-300">
                      {detection.source}
                    </span>
                    <span>
                      {Math.round(detection.confidence * 100)}% confidence
                    </span>
                    {detection.details && (
                      <span className="truncate text-gray-400">{detection.details}</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function SeverityBadge({ severity }: { severity: string }) {
  const classes: Record<string, string> = {
    Critical:
      'bg-red-200 text-red-800 dark:bg-red-900/60 dark:text-red-200',
    High: 'bg-orange-200 text-orange-800 dark:bg-orange-900/60 dark:text-orange-200',
    Medium:
      'bg-yellow-200 text-yellow-800 dark:bg-yellow-900/60 dark:text-yellow-200',
    Low: 'bg-gray-200 text-gray-700 dark:bg-gray-700 dark:text-gray-300',
  }
  return (
    <span
      className={`shrink-0 text-[11px] px-2 py-0.5 rounded-full font-semibold ${
        classes[severity] ?? classes.Low
      }`}
    >
      {severity}
    </span>
  )
}
