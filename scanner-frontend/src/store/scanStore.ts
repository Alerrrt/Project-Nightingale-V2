import { create } from 'zustand';

interface ScanResult {
  url: string;
  module_id: string;
  severity: string;
  snippet: string;
  description: string;
  timestamp: string;
}

interface ScanState {
  totalUrls: number;
  completedUrls: number;
  totalModules: number;
  completedModules: number;
  results: ScanResult[];
  setTotalUrls: (total: number) => void;
  setCompletedUrls: (completed: number) => void;
  setTotalModules: (total: number) => void;
  setCompletedModules: (completed: number) => void;
  addResult: (result: ScanResult) => void;
  reset: () => void;
}

export const useScanStore = create<ScanState>((set) => ({
  totalUrls: 0,
  completedUrls: 0,
  totalModules: 0,
  completedModules: 0,
  results: [],
  
  setTotalUrls: (total) => set({ totalUrls: total }),
  setCompletedUrls: (completed) => set({ completedUrls: completed }),
  setTotalModules: (total) => set({ totalModules: total }),
  setCompletedModules: (completed) => set({ completedModules: completed }),
  addResult: (result) => set((state) => ({ 
    results: [result, ...state.results] 
  })),
  reset: () => set({
    totalUrls: 0,
    completedUrls: 0,
    totalModules: 0,
    completedModules: 0,
    results: []
  })
})); 