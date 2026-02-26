import { useEffect } from 'react'
import { Toaster } from 'react-hot-toast'
import { SunIcon, MoonIcon } from '@heroicons/react/24/outline'
import { motion } from 'framer-motion'
import { Sidebar } from './components/Sidebar'
import { Dashboard } from './components/Dashboard'
import { ScanView } from './components/ScanView'
import { QuarantineView } from './components/QuarantineView'
import { SettingsView } from './components/SettingsView'
import { useAppStore } from './store'

function App() {
  const { currentView, darkMode, toggleDarkMode } = useAppStore()

  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
  }, [darkMode])

  const getViewContent = () => {
    switch (currentView) {
      case 'dashboard':
        return <Dashboard />
      case 'scan':
        return <ScanView />
      case 'quarantine':
        return <QuarantineView />
      case 'settings':
        return <SettingsView />
      default:
        return <Dashboard />
    }
  }

  return (
    <div className={darkMode ? 'dark' : ''}>
      <div className="flex h-screen bg-gray-50 dark:bg-gray-950">
        <Sidebar />

        <div className="flex-1 flex flex-col overflow-hidden">
          <header className="flex-shrink-0 bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800 px-6 py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <span className="text-2xl">&#9889;</span>
                <h1 className="text-xl font-bold text-gray-900 dark:text-white">
                  Mjolnir
                </h1>
                <span className="text-xs px-2 py-0.5 bg-mjolnir-600 text-white rounded-full font-medium">
                  v0.1.0
                </span>
              </div>

              <button
                onClick={toggleDarkMode}
                className="p-2 text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-colors"
              >
                {darkMode ? (
                  <SunIcon className="w-5 h-5" />
                ) : (
                  <MoonIcon className="w-5 h-5" />
                )}
              </button>
            </div>
          </header>

          <main className="flex-1 overflow-y-auto p-6">
            <motion.div
              key={currentView}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.15 }}
            >
              {getViewContent()}
            </motion.div>
          </main>
        </div>
      </div>

      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: darkMode ? '#1f2937' : '#ffffff',
            color: darkMode ? '#ffffff' : '#000000',
            border: `1px solid ${darkMode ? '#374151' : '#e5e7eb'}`,
          },
        }}
      />
    </div>
  )
}

export default App
