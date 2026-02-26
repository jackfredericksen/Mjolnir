import { useState } from 'react'
import { invoke } from '@tauri-apps/api/core'
import {
  FolderOpenIcon,
  PlayIcon,
  StopIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
} from '@heroicons/react/24/outline'
import { useAppStore } from '../store'
import toast from 'react-hot-toast'

export function ScanView() {
  const {
    isScanning,
    setIsScanning,
    scanProgress,
    lastReport,
    setLastReport,
    addDetections,
    clearDetections,
  } = useAppStore()

  const [scanPath, setScanPath] = useState('')

  const startScan = async () => {
    if (!scanPath.trim()) {
      toast.error('Please enter a path to scan')
      return
    }

    setIsScanning(true)
    clearDetections()
    const toastId = toast.loading('Scanning...')

    try {
      const report = await invoke<any>('start_scan', {
        targets: [scanPath.trim()],
      })

      setLastReport(report)
      if (report.detections?.length > 0) {
        addDetections(report.detections)
        toast.error(`Found ${report.total_detections} threat(s)!`, { id: toastId })
      } else {
        toast.success('Scan complete - no threats found', { id: toastId })
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
      if (selected) {
        setScanPath(selected)
      }
    } catch {
      // Dialog cancelled or not available
    }
  }

  const progressPercent =
    scanProgress && scanProgress.files_total > 0
      ? Math.round((scanProgress.files_scanned / scanProgress.files_total) * 100)
      : 0

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
          Scan
        </h2>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
          Scan files and directories for threats
        </p>
      </div>

      {/* Scan Input */}
      <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6">
        <div className="flex space-x-3">
          <input
            type="text"
            value={scanPath}
            onChange={(e) => setScanPath(e.target.value)}
            placeholder="Enter path to scan (e.g., ~/Downloads)"
            className="flex-1 px-4 py-3 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-mjolnir-500"
            disabled={isScanning}
          />
          <button
            onClick={selectFolder}
            disabled={isScanning}
            className="px-4 py-3 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg transition-colors disabled:opacity-50"
          >
            <FolderOpenIcon className="w-5 h-5" />
          </button>
          <button
            onClick={isScanning ? undefined : startScan}
            disabled={isScanning && false}
            className={`px-6 py-3 rounded-lg font-medium transition-colors flex items-center space-x-2 ${
              isScanning
                ? 'bg-red-600 hover:bg-red-700 text-white'
                : 'bg-mjolnir-600 hover:bg-mjolnir-700 text-white'
            }`}
          >
            {isScanning ? (
              <>
                <StopIcon className="w-5 h-5" />
                <span>Scanning...</span>
              </>
            ) : (
              <>
                <PlayIcon className="w-5 h-5" />
                <span>Scan</span>
              </>
            )}
          </button>
        </div>

        {/* Progress Bar */}
        {isScanning && scanProgress && (
          <div className="mt-4 space-y-2">
            <div className="flex justify-between text-sm text-gray-500 dark:text-gray-400">
              <span>
                {scanProgress.files_scanned} / {scanProgress.files_total} files
              </span>
              <span>{progressPercent}%</span>
            </div>
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
              <div
                className="bg-mjolnir-600 h-2 rounded-full transition-all duration-300"
                style={{ width: `${progressPercent}%` }}
              />
            </div>
            <p className="text-xs text-gray-400 dark:text-gray-500 truncate">
              {scanProgress.current_file}
            </p>
          </div>
        )}
      </div>

      {/* Scan Results */}
      {lastReport && (
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Scan Results
          </h3>

          <div className="grid grid-cols-4 gap-4 mb-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-gray-900 dark:text-white">
                {lastReport.files_scanned}
              </div>
              <div className="text-xs text-gray-500">Files Scanned</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-red-600 dark:text-red-400">
                {lastReport.files_infected}
              </div>
              <div className="text-xs text-gray-500">Infected</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-orange-600 dark:text-orange-400">
                {lastReport.total_detections}
              </div>
              <div className="text-xs text-gray-500">Detections</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-gray-900 dark:text-white">
                {(lastReport.duration_ms / 1000).toFixed(1)}s
              </div>
              <div className="text-xs text-gray-500">Duration</div>
            </div>
          </div>

          {lastReport.detections.length === 0 ? (
            <div className="flex items-center space-x-3 p-4 bg-green-50 dark:bg-green-950 rounded-lg">
              <CheckCircleIcon className="w-6 h-6 text-green-600 dark:text-green-400" />
              <span className="text-green-800 dark:text-green-200 font-medium">
                No threats detected
              </span>
            </div>
          ) : (
            <div className="space-y-3">
              {lastReport.detections.map((detection: any, i: number) => (
                <div
                  key={i}
                  className="p-4 bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-800 rounded-lg"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-center space-x-2">
                      <ExclamationTriangleIcon className="w-5 h-5 text-red-600 dark:text-red-400" />
                      <span className="font-medium text-red-800 dark:text-red-200">
                        {detection.threat_name}
                      </span>
                    </div>
                    <span
                      className={`text-xs px-2 py-1 rounded-full font-medium ${
                        detection.severity === 'Critical'
                          ? 'bg-red-200 text-red-800 dark:bg-red-900 dark:text-red-200'
                          : detection.severity === 'High'
                          ? 'bg-orange-200 text-orange-800 dark:bg-orange-900 dark:text-orange-200'
                          : detection.severity === 'Medium'
                          ? 'bg-yellow-200 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
                          : 'bg-gray-200 text-gray-800 dark:bg-gray-700 dark:text-gray-200'
                      }`}
                    >
                      {detection.severity}
                    </span>
                  </div>
                  <p className="text-sm text-red-600 dark:text-red-400 mt-1 truncate">
                    {detection.file_path}
                  </p>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                    Engine: {detection.source} | Confidence:{' '}
                    {Math.round(detection.confidence * 100)}%
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
