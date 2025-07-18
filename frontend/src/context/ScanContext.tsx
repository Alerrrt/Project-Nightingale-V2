// @refresh reset
import React, { createContext, useContext, useState, useEffect, ReactNode, useRef } from 'react';
import type { VulnerabilityData, GroupedVulnerability } from '../components/VulnerabilityList';
import type { ScanProgressData } from '../components/ScanProgress';
import type { ScanStats } from '../components/StatsCards';
import type { ModuleStatus } from '../components/ModuleStatusGrid';

interface LogEntry {
  timestamp: string;
  message: string;
}

interface ScanContextType {
  isScanning: boolean;
  setIsScanning: (v: boolean) => void;
  scanProgress: ScanProgressData;
  setScanProgress: (v: ScanProgressData) => void;
  scanStats: ScanStats;
  setScanStats: (v: ScanStats) => void;
  vulnerabilities: VulnerabilityData[];
  setVulnerabilities: (v: VulnerabilityData[]) => void;
  selectedVuln: GroupedVulnerability | null;
  setSelectedVuln: (v: GroupedVulnerability | null) => void;
  filterSeverity: string;
  setFilterSeverity: (v: string) => void;
  modules: ModuleStatus[];
  setModules: (v: ModuleStatus[]) => void;
  activityLogs: LogEntry[];
  setActivityLogs: (v: LogEntry[]) => void;
  scanId: string | null;
  setScanId: (v: string | null) => void;
  loading: boolean;
  error: string | null;
  stopScan: () => void;
}

const ScanContext = createContext<ScanContextType | undefined>(undefined);

export const useScan = () => {
  const ctx = useContext(ScanContext);
  if (!ctx) throw new Error('useScan must be used within a ScanProvider');
  return ctx;
};

interface ScanProviderProps {
  children: ReactNode;
}

// Default/empty values for state
const defaultScanProgress: ScanProgressData = {
  phase: '',
  progress: 0,
  currentUrl: '',
  foundVulns: 0,
  scannedUrls: 0,
  totalUrls: 0,
  eta: '',
};
const defaultScanStats: ScanStats = {
  totalVulnerabilities: 0,
  criticalCount: 0,
  highCount: 0,
  mediumCount: 0,
  lowCount: 0,
  infoCount: 0,
  scanDuration: '',
  urlsScanned: 0,
  lastScan: '',
  target: '',
};

export const ScanProvider: React.FC<ScanProviderProps> = ({ children }) => {
  const [isScanning, setIsScanning] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanProgress, setScanProgress] = useState<ScanProgressData>(defaultScanProgress);
  const [scanStats, setScanStats] = useState<ScanStats>(defaultScanStats);
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityData[]>([]);
  const [selectedVuln, setSelectedVuln] = useState<GroupedVulnerability | null>(null);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [modules, setModules] = useState<ModuleStatus[]>([]);
  const [activityLogs, setActivityLogs] = useState<LogEntry[]>([]);
  const [loading] = useState(false); // setLoading was removed here
  const [error, setError] = useState<string | null>(null);
  const ws = useRef<WebSocket | null>(null);
  const scanStartTime = useRef<Date | null>(null);

  const stopScan = () => {
    if (ws.current && ws.current.readyState === WebSocket.OPEN && scanId) {
      ws.current.send(JSON.stringify({ type: 'stop_scan', data: { scan_id: scanId } }));
      setIsScanning(false);
      console.log('Sent stop_scan message to backend');
    }
  };

  useEffect(() => {
    if (scanId && isScanning) {
      // Use the 'ws' scheme for WebSocket connections
      // The host is the same as the window, and Vite will proxy it.
      const wsUrl = `ws://${window.location.host}/api/ws/${scanId}`;
      ws.current = new WebSocket(wsUrl);

      ws.current.onopen = () => {
        setError(null);
        console.log('WebSocket connection established');
        scanStartTime.current = new Date();
      };

      ws.current.onmessage = (event) => {
        const message = JSON.parse(event.data);
        const { type, data, timestamp } = message; // Destructure the message

        // Handle different types of messages from the backend
        if (type === 'scan_progress') {
          const now = new Date();
          const elapsedMs = now.getTime() - (scanStartTime.current?.getTime() || now.getTime());
          const progress = data.progress;
          let eta = '...';

          if (progress > 0 && elapsedMs > 0) {
            const totalEstimatedTimeMs = (elapsedMs / progress) * 100;
            const remainingTimeMs = totalEstimatedTimeMs - elapsedMs;
            
            const remainingSeconds = Math.round(remainingTimeMs / 1000);
            const minutes = Math.floor(remainingSeconds / 60);
            const seconds = remainingSeconds % 60;
            
            if (remainingTimeMs > 0) {
              eta = `${minutes}m ${seconds}s`;
            } else {
              eta = '< 1s';
            }
          }
          
          setScanProgress(prev => ({ ...prev, progress: data.progress, eta }));
        } else if (type === 'current_target_url') {
          setScanProgress(prev => ({ ...prev, currentUrl: data.url }));
        } else if (type === 'new_finding') {
          setVulnerabilities((prev) => [...prev, data]);
          setActivityLogs((prev) => [
            ...prev,
            { message: `[+] New finding: ${data.title} (${data.severity})`, timestamp },
          ]);
        } else if (type === 'module_status') {
          setModules((prev) => {
            const existing = prev.find(m => m.name === data.name);
            if (existing) {
              return prev.map(m => m.name === data.name ? data : m);
            }
            return [...prev, data];
          });
          const logMessage = `[${data.name}] => ${data.status}${data.error ? ` | ERROR: ${data.error}` : ''}`;
          setActivityLogs((prev) => [...prev, { message: logMessage, timestamp }]);
        } else if (type === 'activity_log') {
          setActivityLogs((prev) => [...prev, { message: data.message, timestamp }]);
        } else if (type === 'scan_completed') {
          setIsScanning(false);
          if (data.results) {
            setVulnerabilities(data.results);
          }
          if (ws.current) {
            ws.current.close();
          }
        } else if (type === 'status' && data.status === 'completed') {
          setIsScanning(false);
          if (data.results) {
            setVulnerabilities(data.results);
          }
        } else if (type === 'status' && data.status.startsWith('failed')) {
          setError(`Scan failed: ${data.status}`);
          setIsScanning(false);
        }
      };

      ws.current.onclose = () => {
        console.log('WebSocket connection closed');
        if (isScanning) {
          setError('Real-time connection to the server was lost.');
          setIsScanning(false);
        }
      };

      ws.current.onerror = (err) => {
        console.error('WebSocket error:', err);
        setError('A real-time connection error occurred.');
        setIsScanning(false);
      };
    }

    return () => {
      if (ws.current && ws.current.readyState === WebSocket.OPEN) {
        ws.current.close();
      }
    };
  }, [scanId, isScanning]);

  return (
    <ScanContext.Provider
      value={{
        isScanning,
        setIsScanning,
        scanProgress,
        setScanProgress,
        scanStats,
        setScanStats,
        vulnerabilities,
        setVulnerabilities,
        selectedVuln,
        setSelectedVuln,
        filterSeverity,
        setFilterSeverity,
        modules,
        setModules,
        activityLogs,
        setActivityLogs,
        scanId,
        setScanId,
        loading,
        error,
        stopScan,
      }}
    >
      {children}
    </ScanContext.Provider>
  );
};