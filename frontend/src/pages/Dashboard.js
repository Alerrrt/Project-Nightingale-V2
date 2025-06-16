import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Grid, Alert, Snackbar } from '@mui/material';
import { UrlInput } from '../components/UrlInput';
import ScanProgress from '../components/ScanProgress';
import VulnerabilityTable from '../components/VulnerabilityTable';
import { DashboardSummary } from '../components/DashboardSummary';
import { HistoricalScans } from '../components/HistoricalScans';
import apiClient, { getWsUrl } from '../api/client';
import { motion } from 'framer-motion';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { JsVulnTable } from '../components/JsVulnTable';
import ModuleStatuses from '../components/ModuleStatuses';

const Dashboard = () => {
  const [scanResults, setScanResults] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [historicalScans, setHistoricalScans] = useState([]);
  const [moduleStatuses, setModuleStatuses] = useState([]);
  const [currentScanId, setCurrentScanId] = useState(null);
  const [error, setError] = useState(null);
  const [errorType, setErrorType] = useState('error');
  const [errorDetails, setErrorDetails] = useState(null);
  const wsRef = useRef(null);

  const handleScanStart = async (url) => {
    try {
      setIsScanning(true);
      setScanProgress(0);
      setScanResults([]);
      setModuleStatuses([]);
      setCurrentScanId(null);
      setError(null);
      setErrorType('error');
      setErrorDetails(null);

      if (wsRef.current) {
        console.log('Closing existing WebSocket connection before starting a new scan...');
        wsRef.current.close();
        wsRef.current = null;
      }

      const response = await apiClient.startScan(url);
      console.log('Data received from startScan:', response);
      
      if (!response || !response.scan_id) {
        throw new Error('Invalid response from scan initiation: scan_id missing.');
      }
      console.log('Scan ID is present:', response.scan_id);

      setCurrentScanId(response.scan_id);

      const wsUrl = getWsUrl(`/scans/${response.scan_id}/realtime`);
      const ws = new WebSocket(wsUrl);
      console.log('WebSocket object created:', ws);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log('WebSocket connected');
      };

      ws.onmessage = (event) => {
        try {
          const update = JSON.parse(event.data);
          console.log('Raw WebSocket message:', event.data);
          console.log('Parsed WebSocket update:', update);
          handleScanUpdate(update);
        } catch (error) {
          console.error('Error parsing WebSocket message:', error);
          setError('Failed to process scan update');
          setErrorType('error');
          setErrorDetails(error.message);
        }
      };

      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        setError('Connection error occurred');
        setErrorType('error');
        setErrorDetails('Failed to maintain real-time connection');
        setIsScanning(false);
        if (wsRef.current) {
          wsRef.current.close();
          wsRef.current = null;
        }
      };

      ws.onclose = () => {
        console.log('WebSocket closed');
        if (isScanning) {
          setError('Connection lost');
          setErrorType('warning');
          setErrorDetails('Real-time updates are no longer available');
        }
      };

    } catch (error) {
      console.error('Error starting scan:', error);
      setError(`Failed to start scan: ${error.message || 'Unknown error'}`);
      setErrorType('error');
      setErrorDetails(error.response?.data?.detail || 'Please check your input and try again');
      setIsScanning(false);
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    }
  };

  const fetchScanResults = useCallback(async (id) => {
    try {
      const data = await apiClient.getScanResults(id);
      setScanResults(data);
    } catch (error) {
      console.error('Error fetching scan results:', error);
      setError('Failed to fetch scan results');
    }
  }, []);

  useEffect(() => {
    const fetchHistoricalScans = async () => {
      try {
        const data = await apiClient.getHistoricalScans();
        setHistoricalScans(data);
      } catch (error) {
        console.error('Error fetching historical scans:', error);
        setError('Failed to fetch historical scans');
      }
    };

    fetchHistoricalScans();
  }, []);

  useEffect(() => {
    return () => {
      if (wsRef.current) {
        console.log('Cleaning up WebSocket on unmount.');
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, []);

  const handleScanUpdate = (update) => {
    console.log('Received WebSocket update:', update);
    switch (update.type) {
      case 'connection_status':
        console.log('WebSocket connection status:', update.data);
        break;
      case 'scan_progress':
        setScanProgress(update.data.overall);
        setModuleStatuses(update.data.modules);
        break;
      case 'new_finding':
        setScanResults(prev => [...prev, update.data]);
        break;
      case 'module_status':
        setModuleStatuses(prev => ({
          ...prev,
          [update.data.module_name]: update.data
        }));
        break;
      case 'status':
        if (update.data === 'completed') {
          setIsScanning(false);
          if (currentScanId) {
            fetchScanResults(currentScanId);
            apiClient.getHistoricalScans().then(setHistoricalScans).catch(console.error);
          }
        } else if (update.data.startsWith('failed:')) {
          setError(update.data);
          setIsScanning(false);
        }
        break;
      default:
        console.log('Unknown update type:', update.type);
    }
  };

  useEffect(() => {
    const scanId = currentScanId;
    if (!scanId) return;
    const wsUrl = getWsUrl(`/scans/${scanId}/realtime`);
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      // Optionally send a message or log
    };
    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'scan_progress' && msg.data && msg.data.modules) {
          const modulesArr = Object.entries(msg.data.modules).map(([id, m]) => ({
            id,
            status: m.status || 'pending',
            progress: m.progress ?? 0,
            lastRun: m.lastRun || '',
            findingsCount: m.findingsCount ?? 0,
          }));
          setModuleStatuses(modulesArr);
        }
      } catch (e) {
        // Ignore parse errors
      }
    };
    ws.onerror = () => {};
    ws.onclose = () => {};
    return () => {
      ws.close();
    };
  }, [currentScanId]);

  const handleCloseError = () => {
    setError(null);
    setErrorType('error');
    setErrorDetails(null);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-6 p-6"
    >
      <Snackbar 
        open={!!error} 
        autoHideDuration={6000} 
        onClose={handleCloseError}
        anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
      >
        <Alert 
          onClose={handleCloseError} 
          severity={errorType} 
          sx={{ width: '100%' }}
          variant="filled"
        >
          <div className="flex flex-col">
            <span className="font-medium">{error}</span>
            {errorDetails && (
              <span className="text-sm mt-1 opacity-90">{errorDetails}</span>
            )}
          </div>
        </Alert>
      </Snackbar>

      <Grid container spacing={4}>
        <Grid item xs={12} lg={6}>
          <Grid container spacing={4} className="h-full">
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <UrlInput onScanSubmit={handleScanStart} disabled={isScanning} />
                </CardContent>
              </Card>
            </Grid>
            
            {isScanning && (
              <>
                <Grid item xs={12}>
                  <Card>
                    <CardHeader>
                      <CardTitle>Scan Progress</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ScanProgress progress={scanProgress} />
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12}>
                  <Card>
                    <CardHeader>
                      <CardTitle>Module Statuses</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ModuleStatuses modules={moduleStatuses} />
                    </CardContent>
                  </Card>
                </Grid>
              </>
            )}

            <Grid item xs={12}>
              <Card className="h-full flex flex-col">
                <CardHeader>
                  <CardTitle>Scan Results</CardTitle>
                </CardHeader>
                <CardContent className="flex-grow">
                  <VulnerabilityTable findings={scanResults} isLoading={isScanning} />
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </Grid>

        <Grid item xs={12} lg={6}>
          <Grid container spacing={4} className="h-full">
            <Grid item xs={12}>
              <Card className="h-full flex flex-col">
                <CardHeader>
                  <CardTitle>Scan Summary</CardTitle>
                </CardHeader>
                <CardContent className="flex-grow">
                  <DashboardSummary scanResults={scanResults} isLoading={isScanning} />
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12}>
              <Card className="h-full flex flex-col">
                <CardHeader>
                  <CardTitle>Historical Scans</CardTitle>
                </CardHeader>
                <CardContent className="flex-grow">
                  <HistoricalScans 
                    historicalScans={historicalScans} 
                    onScanSelect={fetchScanResults} 
                    isLoading={!historicalScans.length && !error}
                  />
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12}>
              <Card className="h-full flex flex-col">
                <CardHeader>
                  <CardTitle>JavaScript Library Vulnerabilities</CardTitle>
                </CardHeader>
                <CardContent className="flex-grow">
                  <JsVulnTable 
                    findings={scanResults.filter(f => f.vulnerability_type === "Vulnerable JavaScript Library")}
                    isLoading={isScanning}
                  />
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </Grid>
      </Grid>
    </motion.div>
  );
};

export default Dashboard;