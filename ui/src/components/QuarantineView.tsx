import { useEffect } from 'react'
import { invoke } from '@tauri-apps/api/core'
import {
  ArchiveBoxIcon,
  ArrowPathIcon,
  TrashIcon,
} from '@heroicons/react/24/outline'
import { useAppStore } from '../store'
import toast from 'react-hot-toast'

export function QuarantineView() {
  const { quarantineEntries, setQuarantineEntries } = useAppStore()

  const loadEntries = async () => {
    try {
      const entries = await invoke<any[]>('get_quarantine_list')
      setQuarantineEntries(entries)
    } catch {
      // Not connected to Tauri backend
    }
  }

  useEffect(() => {
    loadEntries()
  }, [])

  const restoreFile = async (id: string) => {
    try {
      await invoke('restore_from_quarantine', { id })
      toast.success('File restored successfully')
      loadEntries()
    } catch (error) {
      toast.error(`Failed to restore: ${error}`)
    }
  }

  const deleteFile = async (id: string) => {
    try {
      await invoke('delete_from_quarantine', { id })
      toast.success('File permanently deleted')
      loadEntries()
    } catch (error) {
      toast.error(`Failed to delete: ${error}`)
    }
  }

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
            Quarantine
          </h2>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
            Isolated threats encrypted with AES-256-GCM
          </p>
        </div>
        <button
          onClick={loadEntries}
          className="p-2 text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg"
        >
          <ArrowPathIcon className="w-5 h-5" />
        </button>
      </div>

      {quarantineEntries.length === 0 ? (
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-12 text-center">
          <ArchiveBoxIcon className="w-12 h-12 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">
            No quarantined files
          </h3>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
            Detected threats will be encrypted and stored here
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {quarantineEntries.map((entry) => (
            <div
              key={entry.id}
              className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-4"
            >
              <div className="flex items-start justify-between">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center space-x-2">
                    <span className="font-medium text-red-600 dark:text-red-400">
                      {entry.threat_name}
                    </span>
                  </div>
                  <p className="text-sm text-gray-500 dark:text-gray-400 truncate mt-1">
                    {entry.original_path}
                  </p>
                  <div className="flex items-center space-x-4 mt-2 text-xs text-gray-400">
                    <span>{formatSize(entry.file_size)}</span>
                    <span>{new Date(entry.quarantine_time).toLocaleString()}</span>
                    <span className="font-mono">{entry.id.slice(0, 8)}...</span>
                  </div>
                </div>

                <div className="flex items-center space-x-2 ml-4">
                  <button
                    onClick={() => restoreFile(entry.id)}
                    className="p-2 text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-950 rounded-lg transition-colors"
                    title="Restore file"
                  >
                    <ArrowPathIcon className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => deleteFile(entry.id)}
                    className="p-2 text-red-600 hover:bg-red-50 dark:hover:bg-red-950 rounded-lg transition-colors"
                    title="Permanently delete"
                  >
                    <TrashIcon className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
