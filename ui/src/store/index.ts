import { create } from 'zustand'
import type {
  ViewType,
  ScanType,
  Detection,
  ScanReport,
  QuarantineEntry,
  SystemStatus,
  ScanProgressSnapshot,
} from '../types'

interface AppState {
  // Navigation
  currentView: ViewType
  setCurrentView: (view: ViewType) => void

  // Scanning
  isScanning: boolean
  setIsScanning: (scanning: boolean) => void
  selectedScanType: ScanType
  setSelectedScanType: (type: ScanType) => void
  scanProgress: ScanProgressSnapshot | null
  setScanProgress: (progress: ScanProgressSnapshot | null) => void
  lastReport: ScanReport | null
  setLastReport: (report: ScanReport | null) => void

  // Detections
  detections: Detection[]
  addDetections: (detections: Detection[]) => void
  clearDetections: () => void

  // Quarantine
  quarantineEntries: QuarantineEntry[]
  setQuarantineEntries: (entries: QuarantineEntry[]) => void

  // System
  systemStatus: SystemStatus | null
  setSystemStatus: (status: SystemStatus) => void
  realtimeEnabled: boolean
  setRealtimeEnabled: (enabled: boolean) => void

  // Theme
  darkMode: boolean
  toggleDarkMode: () => void

  // Sidebar
  isSidebarOpen: boolean
  toggleSidebar: () => void
}

export const useAppStore = create<AppState>((set) => ({
  // Navigation
  currentView: 'dashboard',
  setCurrentView: (view) => set({ currentView: view }),

  // Scanning
  isScanning: false,
  setIsScanning: (scanning) => set({ isScanning: scanning }),
  selectedScanType: 'quick',
  setSelectedScanType: (type) => set({ selectedScanType: type }),
  scanProgress: null,
  setScanProgress: (progress) => set({ scanProgress: progress }),
  lastReport: null,
  setLastReport: (report) => set({ lastReport: report }),

  // Detections
  detections: [],
  addDetections: (newDetections) =>
    set((state) => ({
      detections: [...state.detections, ...newDetections],
    })),
  clearDetections: () => set({ detections: [] }),

  // Quarantine
  quarantineEntries: [],
  setQuarantineEntries: (entries) => set({ quarantineEntries: entries }),

  // System
  systemStatus: null,
  setSystemStatus: (status) => set({ systemStatus: status }),
  realtimeEnabled: false,
  setRealtimeEnabled: (enabled) => set({ realtimeEnabled: enabled }),

  // Theme
  darkMode: true,
  toggleDarkMode: () =>
    set((state) => {
      const newDark = !state.darkMode
      if (newDark) {
        document.documentElement.classList.add('dark')
      } else {
        document.documentElement.classList.remove('dark')
      }
      return { darkMode: newDark }
    }),

  // Sidebar
  isSidebarOpen: true,
  toggleSidebar: () => set((state) => ({ isSidebarOpen: !state.isSidebarOpen })),
}))
