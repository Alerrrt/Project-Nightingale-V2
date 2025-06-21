import React, { useEffect, useState } from 'react';
import { RefreshCw, ArrowRight } from 'lucide-react';
import * as scanApi from '../api/scanApi';

interface ScanHistoryItem {
  scan_id: string;
  target: string;
  start_time: string;
  status: string;
  finding_count: number;
}

interface ScanHistoryProps {
  onViewAll: () => void;
  onSelectScan: (scanId: string) => void;
}

const ScanHistory: React.FC<ScanHistoryProps> = ({ onViewAll, onSelectScan }) => {
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await scanApi.fetchScanHistory();
      setHistory(data);
    } catch (err) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('An unknown error occurred');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  if (loading) return <div className="text-center text-gray-400 p-4">Loading...</div>;
  if (error) return <div className="text-center text-red-400 p-4">{error}</div>;

  return (
    <div className="w-full">
        <div className="flex justify-between items-center mb-4">
            <button
              onClick={onViewAll}
              className="text-sm text-primary hover:underline flex items-center"
            >
              View All <ArrowRight size={14} className="ml-1" />
            </button>
            <button
            className="p-2 rounded-md bg-surface hover:bg-gray-700 transition-colors"
            onClick={fetchHistory}
            disabled={loading}
            title="Refresh"
            >
                <RefreshCw size={18} className={loading ? 'animate-spin' : ''} />
            </button>
        </div>
        <div className="overflow-x-auto">
            <table className="min-w-full text-sm text-left">
                <thead className="text-gray-400">
                <tr>
                    <th className="p-2 font-semibold">Target</th>
                    <th className="p-2 font-semibold">Date</th>
                    <th className="p-2 font-semibold">Status</th>
                    <th className="p-2 font-semibold text-center">Findings</th>
                </tr>
                </thead>
                <tbody className="divide-y divide-border">
                {history.length === 0 ? (
                    <tr>
                    <td colSpan={4} className="py-4 text-center text-textSecondary">No scan history found.</td>
                    </tr>
                ) : (
                    history.slice(0, 5).map((item) => (
                    <tr 
                      key={item.scan_id} 
                      className="hover:bg-surface/50 cursor-pointer"
                      onClick={() => onSelectScan(item.scan_id)}
                    >
                        <td className="p-2 font-medium truncate max-w-[100px]" title={item.target}>{item.target}</td>
                        <td className="p-2 text-textSecondary">{new Date(item.start_time).toLocaleDateString()}</td>
                        <td className="p-2 capitalize">
                        <span className={`px-2 py-1 text-xs rounded-full ${
                            item.status === 'completed' ? 'bg-green-800 text-green-300' :
                            item.status === 'failed' ? 'bg-red-800 text-red-300' :
                            'bg-yellow-800 text-yellow-300'
                        }`}>
                            {item.status}
                        </span>
                        </td>
                        <td className="p-2 text-center text-text">{item.finding_count}</td>
                    </tr>
                    ))
                )}
                </tbody>
            </table>
        </div>
    </div>
  );
};

export default ScanHistory;