import {
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  DocumentMagnifyingGlassIcon,
  ClockIcon,
} from '@heroicons/react/24/outline'
import { useAppStore } from '../store'

export function Dashboard() {
  const { detections, lastReport, realtimeEnabled, setCurrentView } = useAppStore()

  const threatCount = detections.length
  const isClean = threatCount === 0

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
          Dashboard
        </h2>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
          System protection overview
        </p>
      </div>

      {/* Status Banner */}
      <div
        className={`p-6 rounded-xl ${
          isClean
            ? 'bg-green-50 dark:bg-green-950 border border-green-200 dark:border-green-800'
            : 'bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800'
        }`}
      >
        <div className="flex items-center space-x-4">
          {isClean ? (
            <ShieldCheckIcon className="w-12 h-12 text-green-600 dark:text-green-400" />
          ) : (
            <ExclamationTriangleIcon className="w-12 h-12 text-red-600 dark:text-red-400" />
          )}
          <div>
            <h3
              className={`text-xl font-bold ${
                isClean
                  ? 'text-green-800 dark:text-green-200'
                  : 'text-red-800 dark:text-red-200'
              }`}
            >
              {isClean ? 'System Protected' : `${threatCount} Threat${threatCount > 1 ? 's' : ''} Detected`}
            </h3>
            <p
              className={`text-sm ${
                isClean
                  ? 'text-green-600 dark:text-green-400'
                  : 'text-red-600 dark:text-red-400'
              }`}
            >
              {isClean
                ? 'No threats detected. Your system is secure.'
                : 'Action required. Review and quarantine detected threats.'}
            </p>
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard
          icon={<DocumentMagnifyingGlassIcon className="w-6 h-6" />}
          label="Files Scanned"
          value={lastReport?.files_scanned?.toString() ?? '0'}
          color="blue"
        />
        <StatCard
          icon={<ExclamationTriangleIcon className="w-6 h-6" />}
          label="Threats Found"
          value={threatCount.toString()}
          color={threatCount > 0 ? 'red' : 'green'}
        />
        <StatCard
          icon={<ClockIcon className="w-6 h-6" />}
          label="Last Scan"
          value={lastReport ? `${(lastReport.duration_ms / 1000).toFixed(1)}s` : 'Never'}
          color="gray"
        />
      </div>

      {/* Quick Actions */}
      <div>
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
          Quick Actions
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <button
            onClick={() => setCurrentView('scan')}
            className="flex items-center space-x-3 p-4 bg-mjolnir-600 hover:bg-mjolnir-700 text-white rounded-xl transition-colors"
          >
            <DocumentMagnifyingGlassIcon className="w-6 h-6" />
            <div className="text-left">
              <div className="font-semibold">Start Scan</div>
              <div className="text-xs text-mjolnir-200">
                Scan files and directories
              </div>
            </div>
          </button>
          <button
            onClick={() => setCurrentView('quarantine')}
            className="flex items-center space-x-3 p-4 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-900 dark:text-white rounded-xl transition-colors"
          >
            <ShieldCheckIcon className="w-6 h-6" />
            <div className="text-left">
              <div className="font-semibold">View Quarantine</div>
              <div className="text-xs text-gray-500 dark:text-gray-400">
                Manage quarantined files
              </div>
            </div>
          </button>
        </div>
      </div>

      {/* Engine Status */}
      <div>
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
          Detection Engines
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <EngineStatus name="Signature Engine" status="YARA + Hash DB" active />
          <EngineStatus name="Heuristic Engine" status="Behavioral Analysis" active />
          <EngineStatus
            name="QAIO ML Engine"
            status="Quantum Annealing-Inspired"
            active
          />
          <EngineStatus
            name="Real-time Monitor"
            status={realtimeEnabled ? 'Active' : 'Inactive'}
            active={realtimeEnabled}
          />
        </div>
      </div>

      {/* Crypto Status */}
      <div>
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
          Post-Quantum Cryptography
        </h3>
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-4">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-gray-500 dark:text-gray-400">Signatures:</span>
              <span className="ml-2 text-gray-900 dark:text-white font-medium">
                Ed25519 + Dilithium3
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-gray-400">Key Exchange:</span>
              <span className="ml-2 text-gray-900 dark:text-white font-medium">
                CRYSTALS-Kyber1024
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-gray-400">Encryption:</span>
              <span className="ml-2 text-gray-900 dark:text-white font-medium">
                AES-256-GCM
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-gray-400">Hashing:</span>
              <span className="ml-2 text-gray-900 dark:text-white font-medium">
                BLAKE3
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function StatCard({
  icon,
  label,
  value,
  color,
}: {
  icon: React.ReactNode
  label: string
  value: string
  color: string
}) {
  const colorClasses: Record<string, string> = {
    blue: 'bg-blue-50 dark:bg-blue-950 text-blue-600 dark:text-blue-400',
    red: 'bg-red-50 dark:bg-red-950 text-red-600 dark:text-red-400',
    green: 'bg-green-50 dark:bg-green-950 text-green-600 dark:text-green-400',
    gray: 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400',
  }

  return (
    <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-4">
      <div className="flex items-center space-x-3">
        <div className={`p-2 rounded-lg ${colorClasses[color] ?? colorClasses.gray}`}>
          {icon}
        </div>
        <div>
          <div className="text-2xl font-bold text-gray-900 dark:text-white">
            {value}
          </div>
          <div className="text-xs text-gray-500 dark:text-gray-400">{label}</div>
        </div>
      </div>
    </div>
  )
}

function EngineStatus({
  name,
  status,
  active,
}: {
  name: string
  status: string
  active: boolean
}) {
  return (
    <div className="flex items-center justify-between bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-3">
      <div>
        <div className="text-sm font-medium text-gray-900 dark:text-white">
          {name}
        </div>
        <div className="text-xs text-gray-500 dark:text-gray-400">{status}</div>
      </div>
      <div
        className={`w-2.5 h-2.5 rounded-full ${
          active ? 'bg-green-500' : 'bg-gray-300 dark:bg-gray-600'
        }`}
      />
    </div>
  )
}
