import { useAppStore } from '../store'

export function SettingsView() {
  const { realtimeEnabled, setRealtimeEnabled, darkMode } = useAppStore()

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
          Settings
        </h2>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
          Configure Mjolnir antivirus
        </p>
      </div>

      {/* Real-time Protection */}
      <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Real-time Protection
        </h3>
        <div className="flex items-center justify-between">
          <div>
            <div className="text-sm font-medium text-gray-900 dark:text-white">
              Enable real-time monitoring
            </div>
            <div className="text-xs text-gray-500 dark:text-gray-400">
              Automatically scan files when created or modified
            </div>
          </div>
          <button
            onClick={() => setRealtimeEnabled(!realtimeEnabled)}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
              realtimeEnabled ? 'bg-mjolnir-600' : 'bg-gray-300 dark:bg-gray-600'
            }`}
          >
            <span
              className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                realtimeEnabled ? 'translate-x-6' : 'translate-x-1'
              }`}
            />
          </button>
        </div>
      </div>

      {/* Scan Settings */}
      <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Scan Settings
        </h3>
        <div className="space-y-4">
          <SettingRow
            label="Max file size"
            description="Skip files larger than this"
            value="512 MB"
          />
          <SettingRow
            label="Thread count"
            description="0 = auto-detect CPU cores"
            value="Auto"
          />
          <SettingRow
            label="Detection engines"
            description="Active scanning engines"
            value="Signature, Heuristic, QAIO ML"
          />
        </div>
      </div>

      {/* Crypto Info */}
      <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Cryptographic Configuration
        </h3>
        <div className="space-y-4">
          <SettingRow
            label="Hybrid signatures"
            description="Post-quantum resistant digital signatures"
            value="Ed25519 + Dilithium3"
          />
          <SettingRow
            label="Key encapsulation"
            description="Quantum-safe key exchange for updates"
            value="CRYSTALS-Kyber1024"
          />
          <SettingRow
            label="Quarantine encryption"
            description="Authenticated encryption for isolated files"
            value="AES-256-GCM"
          />
          <SettingRow
            label="File hashing"
            description="Cryptographic hash for file identification"
            value="BLAKE3"
          />
        </div>
      </div>

      {/* Update Settings */}
      <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Updates
        </h3>
        <div className="space-y-4">
          <SettingRow
            label="Auto-update"
            description="Automatically download signature updates"
            value="Enabled"
          />
          <SettingRow
            label="Check interval"
            description="How often to check for updates"
            value="Every 6 hours"
          />
          <SettingRow
            label="Update channel"
            description="Secured with post-quantum encryption"
            value="Kyber1024 + AES-256-GCM"
          />
        </div>
      </div>

      {/* About */}
      <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          About
        </h3>
        <div className="space-y-2 text-sm">
          <div className="flex justify-between">
            <span className="text-gray-500 dark:text-gray-400">Version</span>
            <span className="text-gray-900 dark:text-white font-medium">
              0.1.0
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500 dark:text-gray-400">Platform</span>
            <span className="text-gray-900 dark:text-white font-medium">
              Cross-platform (Rust + Tauri)
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500 dark:text-gray-400">ML Model</span>
            <span className="text-gray-900 dark:text-white font-medium">
              QAIO (Quantum Annealing-Inspired)
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}

function SettingRow({
  label,
  description,
  value,
}: {
  label: string
  description: string
  value: string
}) {
  return (
    <div className="flex items-center justify-between py-2">
      <div>
        <div className="text-sm font-medium text-gray-900 dark:text-white">
          {label}
        </div>
        <div className="text-xs text-gray-500 dark:text-gray-400">
          {description}
        </div>
      </div>
      <span className="text-sm text-gray-600 dark:text-gray-300 font-medium">
        {value}
      </span>
    </div>
  )
}
