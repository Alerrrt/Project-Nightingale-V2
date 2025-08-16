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

export { defaultScanProgress, defaultScanStats };

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
  const pollingTimer = useRef<number | null>(null);
  const wsHeartbeat = useRef<number | null>(null);
  const fallbackTimeout = useRef<number | null>(null);
  const lastWsMessageAt = useRef<number>(0);

  const stopScan = () => {
    if (ws.current && ws.current.readyState === WebSocket.OPEN && scanId) {
      ws.current.send(JSON.stringify({ type: 'stop_scan', data: { scan_id: scanId } }));
      setIsScanning(false);
      console.log('Sent stop_scan message to backend');
    }
  };

  useEffect(() => {
    if (scanId && isScanning) {
      // Use the correct WebSocket endpoint exposed under /api in the backend
      const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
      const wsUrl = `${scheme}://${window.location.host}/api/ws/${scanId}`;
      ws.current = new WebSocket(wsUrl);

      ws.current.onopen = () => {
        setError(null);
        console.log('WebSocket connection established');
        scanStartTime.current = new Date();

        // Start a short grace window: if we don't get any WS messages, enable polling fallback
        if (fallbackTimeout.current == null) {
          fallbackTimeout.current = window.setTimeout(() => {
            if (lastWsMessageAt.current === 0) {
              // No messages received within grace window — start polling as fallback
              if (pollingTimer.current == null) {
                pollingTimer.current = window.setInterval(async () => {
                  try {
                    const res = await fetch(`/api/scans/${scanId}`);
                    if (!res.ok) return;
                    const json = await res.json();
                    setScanProgress(prev => ({
                      ...prev,
                      progress: typeof json.progress === 'number' ? json.progress : (prev?.progress || 0),
                      completedModules: json.completed_modules ?? prev.completedModules,
                      totalModules: json.total_modules ?? prev.totalModules,
                      phase: (json.progress > 0 && (!prev?.phase || prev.phase.trim().length === 0)) ? 'Running scanners…' : (prev?.phase || ''),
                    }));
                  } catch {}
                }, 2000);
              }
            }
          }, 4000);
        }

        // Lightweight heartbeat ping to keep proxies from idling the socket
        if (wsHeartbeat.current == null) {
          wsHeartbeat.current = window.setInterval(() => {
            try {
              if (ws.current && ws.current.readyState === WebSocket.OPEN) {
                ws.current.send(JSON.stringify({ type: 'ping' }));
              }
            } catch {}
          }, 25000);
        }
      };

      ws.current.onmessage = (event) => {
        const message = JSON.parse(event.data);
        const { type, data, timestamp } = message; // Destructure the message

        // Mark that we are receiving WS data; if polling is running, stop it
        lastWsMessageAt.current = Date.now();
        if (pollingTimer.current != null) {
          clearInterval(pollingTimer.current);
          pollingTimer.current = null;
        }
        if (fallbackTimeout.current != null) {
          clearTimeout(fallbackTimeout.current);
          fallbackTimeout.current = null;
        }

        // Handle different types of messages from the backend
        if (type === 'scan_phase') {
          setScanProgress(prev => ({
            ...(prev || ({} as any)),
            phase: (data && data.phase) || 'Running scanners…'
          }));
        } else if (type === 'scan_progress') {
          const progress = data.progress;
          // Use backend-provided ETA if available, otherwise fall back to frontend calculation
          let eta = data.eta_formatted || '...';
          
          // Fallback calculation if backend doesn't provide ETA
          if (!data.eta_formatted && progress > 0) {
            const now = new Date();
            const elapsedMs = now.getTime() - (scanStartTime.current?.getTime() || now.getTime());
            
            if (elapsedMs > 0) {
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
          }
          
          setScanProgress(prev => ({ 
            ...prev, 
            progress: typeof data.progress === 'number' ? data.progress : (prev?.progress || 0), 
            // If backend hasn't sent phase yet, infer it when progress > 0
            phase: (prev?.phase && prev.phase.trim().length > 0)
              ? prev.phase
              : (typeof progress === 'number' && progress > 0 ? 'Running scanners…' : 'Initializing...'),
            eta,
            completedModules: data.completed_modules ?? prev.completedModules,
            totalModules: data.total_modules ?? prev.totalModules
          }));
        } else if (type === 'current_target_url') {
          setScanProgress(prev => ({ ...prev, currentUrl: data.url }));
        } else if (type === 'new_finding') {
          setVulnerabilities((prev) => [...prev, data]);
          setActivityLogs((prev) => {
            const newLog = { message: `[+] New finding: ${data.title} (${data.severity})`, timestamp };
            // Keep only the last 100 logs to prevent memory issues
            const updatedLogs = [...prev, newLog];
            return updatedLogs.slice(-100);
          });
        } else if (type === 'module_status') {
          setModules((prev) => {
            const existing = prev.find(m => m.name === data.name);
            if (existing) {
              return prev.map(m => m.name === data.name ? data : m);
            }
            return [...prev, data];
          });
          const logMessage = `[${data.name}] => ${data.status}${data.error ? ` | ERROR: ${data.error}` : ''}`;
          setActivityLogs((prev) => {
            const newLog = { message: logMessage, timestamp };
            // Keep only the last 100 logs to prevent memory issues
            const updatedLogs = [...prev, newLog];
            return updatedLogs.slice(-100);
          });
        } else if (type === 'activity_log') {
          setActivityLogs((prev) => {
            const newLog = { message: data.message, timestamp };
            // Keep only the last 100 logs to prevent memory issues
            const updatedLogs = [...prev, newLog];
            return updatedLogs.slice(-100);
          });
        } else if (type === 'scan_completed') {
          console.log('Received scan_completed event', data);
          setIsScanning(false);
          setScanProgress(prev => ({ ...prev, progress: 100, phase: 'Completed' }));
          if (data.results) {
            setVulnerabilities(data.results);
          }
          
          // Clean up old data to prevent memory leaks
          setTimeout(() => {
            setActivityLogs([]);
            setModules([]);
          }, 5000); // Keep logs for 5 seconds after completion
          
          if (ws.current) {
            ws.current.close();
          }
        } else if (type === 'status' && data.status === 'completed') {
          console.log('Received status completed event', data);
          setIsScanning(false);
          setScanProgress(prev => ({ ...prev, progress: 100, phase: 'Completed' }));
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
        // If socket closes during an active scan, enable polling fallback immediately
        if (isScanning) {
          if (pollingTimer.current == null) {
            pollingTimer.current = window.setInterval(async () => {
              try {
                const res = await fetch(`/api/scans/${scanId}`);
                if (!res.ok) return;
                const json = await res.json();
                setScanProgress(prev => ({
                  ...prev,
                  progress: typeof json.progress === 'number' ? json.progress : (prev?.progress || 0),
                  completedModules: json.completed_modules ?? prev.completedModules,
                  totalModules: json.total_modules ?? prev.totalModules,
                  phase: (json.progress > 0 && (!prev?.phase || prev.phase.trim().length === 0)) ? 'Running scanners…' : (prev?.phase || ''),
                }));
              } catch {}
            }, 2000);
          }
        }
      };

      ws.current.onerror = (err) => {
        console.error('WebSocket error:', err);
        setError('A real-time connection error occurred.');
        // Don't stop the scan on transient WS errors; switch to polling fallback
        if (pollingTimer.current == null) {
          pollingTimer.current = window.setInterval(async () => {
            try {
              const res = await fetch(`/api/scans/${scanId}`);
              if (!res.ok) return;
              const json = await res.json();
              setScanProgress(prev => ({
                ...prev,
                progress: typeof json.progress === 'number' ? json.progress : (prev?.progress || 0),
                completedModules: json.completed_modules ?? prev.completedModules,
                totalModules: json.total_modules ?? prev.totalModules,
                phase: (json.progress > 0 && (!prev?.phase || prev.phase.trim().length === 0)) ? 'Running scanners…' : (prev?.phase || ''),
              }));
            } catch {}
          }, 2000);
        }
      };
    }

    return () => {
      if (ws.current && ws.current.readyState === WebSocket.OPEN) {
        ws.current.close();
      }
      if (wsHeartbeat.current != null) {
        clearInterval(wsHeartbeat.current);
        wsHeartbeat.current = null;
      }
      if (pollingTimer.current != null) {
        clearInterval(pollingTimer.current);
        pollingTimer.current = null;
      }
      if (fallbackTimeout.current != null) {
        clearTimeout(fallbackTimeout.current);
        fallbackTimeout.current = null;
      }
      lastWsMessageAt.current = 0;
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