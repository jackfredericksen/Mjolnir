import {
  ShieldCheckIcon,
  MagnifyingGlassIcon,
  ArchiveBoxIcon,
  Cog6ToothIcon,
} from '@heroicons/react/24/outline'
import { useAppStore } from '../store'
import type { ViewType } from '../types'

const navItems: { id: ViewType; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: ShieldCheckIcon },
  { id: 'scan', label: 'Scan', icon: MagnifyingGlassIcon },
  { id: 'quarantine', label: 'Quarantine', icon: ArchiveBoxIcon },
  { id: 'settings', label: 'Settings', icon: Cog6ToothIcon },
]

export function Sidebar() {
  const { currentView, setCurrentView, isScanning } = useAppStore()

  return (
    <div className="w-64 bg-white dark:bg-gray-900 border-r border-gray-200 dark:border-gray-800 flex flex-col">
      <div className="p-4 border-b border-gray-200 dark:border-gray-800">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 bg-mjolnir-600 rounded-lg flex items-center justify-center">
            <span className="text-white text-xl">&#9889;</span>
          </div>
          <div>
            <h2 className="text-sm font-bold text-gray-900 dark:text-white">
              Mjolnir AV
            </h2>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              Quantum-Enhanced
            </p>
          </div>
        </div>
      </div>

      <nav className="flex-1 p-3 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon
          const isActive = currentView === item.id

          return (
            <button
              key={item.id}
              onClick={() => setCurrentView(item.id)}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-mjolnir-50 dark:bg-mjolnir-950 text-mjolnir-700 dark:text-mjolnir-400'
                  : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800'
              }`}
            >
              <Icon className="w-5 h-5" />
              <span>{item.label}</span>
              {item.id === 'scan' && isScanning && (
                <div className="ml-auto w-2 h-2 bg-green-500 rounded-full animate-pulse" />
              )}
            </button>
          )
        })}
      </nav>

      <div className="p-4 border-t border-gray-200 dark:border-gray-800">
        <div className="flex items-center space-x-2">
          <div className="w-2 h-2 bg-green-500 rounded-full" />
          <span className="text-xs text-gray-500 dark:text-gray-400">
            Protection Active
          </span>
        </div>
      </div>
    </div>
  )
}
