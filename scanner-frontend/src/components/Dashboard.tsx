import React, { useEffect, useRef } from 'react';
import { useParams } from 'react-router-dom';
import { useScanStore } from '../store/scanStore';
import { toast } from 'react-hot-toast';

const severityColors = {
  low: 'bg-yellow-100 text-yellow-800',
  medium: 'bg-orange-100 text-orange-800',
  high: 'bg-red-100 text-red-800'
};

export const Dashboard = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const wsRef = useRef<WebSocket | null>(null);
  const {
    totalUrls,
    completedUrls,
    totalModules,
    completedModules,
    results,
    setTotalUrls,
    setCompletedUrls,
    setTotalModules,
    setCompletedModules,
    addResult,
    reset
  } = useScanStore();

  useEffect(() => {
    // Reset state when component mounts
    reset();

    // Connect to WebSocket
    const ws = new WebSocket(`ws://${window.location.host}/ws/scans/${scanId}`);
    wsRef.current = ws;

    ws.onopen = () => {
      console.log('WebSocket connected');
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        addResult(data);
        
        // Update progress based on message type
        if (data.type === 'progress') {
          setTotalUrls(data.total_urls);
          setCompletedUrls(data.completed_urls);
          setTotalModules(data.total_modules);
          setCompletedModules(data.completed_modules);
        }
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
      }
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      toast.error('Connection error. Please refresh the page.');
    };

    ws.onclose = () => {
      console.log('WebSocket disconnected');
    };

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [scanId, addResult, reset, setCompletedModules, setCompletedUrls, setTotalModules, setTotalUrls]);

  const urlProgress = totalUrls > 0 ? (completedUrls / totalUrls) * 100 : 0;
  const moduleProgress = totalModules > 0 ? (completedModules / totalModules) * 100 : 0;

  return (
    <div className="w-full max-w-5xl mx-auto p-6">
      <h2 className="text-2xl font-bold mb-6">Scan Progress</h2>
      <div className="space-y-4 mb-8">
        <ProgressBar label="URLs Progress" value={urlProgress} max={100} />
        <ProgressBar label="Modules Progress" value={moduleProgress} max={100} color="bg-green-600" />
      </div>
      <div className="space-y-4">
        <h3 className="text-xl font-semibold mb-4">Scan Results</h3>
        <div className="max-h-[600px] overflow-y-auto space-y-4 pr-2">
          {results.map((result, index) => (
            <FindingCard key={`${result.timestamp}-${index}`} {...result} />
          ))}
        </div>
      </div>
    </div>
  );
};

type ProgressBarProps = {
  label: string;
  value: number;
  max: number;
  color?: string;
};

const ProgressBar = ({ label, value, max, color = "bg-blue-600" }: ProgressBarProps) => (
  <div>
    <div className="flex justify-between mb-1">
      <span className="text-sm font-medium text-gray-700">{label}</span>
      <span className="text-sm font-medium text-gray-700">{Math.round(value)}%</span>
    </div>
    <div className="w-full bg-gray-200 rounded-full h-2.5">
      <div
        className={`${color} h-2.5 rounded-full transition-all duration-300`}
        style={{ width: `${value}%` }}
        aria-valuenow={value}
        aria-valuemax={max}
        aria-label={label}
        role="progressbar"
      />
    </div>
  </div>
);

type FindingCardProps = {
  url: string;
  module_id: string;
  severity: string;
  snippet: string;
  description: string;
  timestamp: string;
};

const FindingCard = ({
  url,
  module_id,
  severity,
  snippet,
  description,
  timestamp
}: FindingCardProps) => (
  <div className="bg-white rounded-lg shadow p-4 border border-gray-200">
    <div className="flex justify-between items-start mb-2">
      <div>
        <h4 className="font-medium text-gray-900">{description}</h4>
        <p className="text-sm text-gray-500 break-all">{url}</p>
      </div>
      <span
        className={`px-2 py-1 rounded-full text-xs font-medium ${severityColors[severity as keyof typeof severityColors] || "bg-gray-100 text-gray-800"}`}
        tabIndex={0}
        aria-label={`Severity: ${severity}`}
      >
        {severity}
      </span>
    </div>
    <div className="mt-2">
      <p className="text-sm text-gray-600 font-mono bg-gray-50 p-2 rounded">{snippet}</p>
      <p className="text-xs text-gray-400 mt-1">{new Date(timestamp).toLocaleString()}</p>
    </div>
  </div>
); 