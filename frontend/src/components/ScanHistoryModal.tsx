import React, { useEffect, useState } from 'react';
import { RefreshCw, X, FileText } from 'lucide-react';
import * as scanApi from '../api/scanApi';

interface ScanHistoryItem {
  scan_id: string;
  target: string;
  start_time: string;
  status: string;
  finding_count: number;
}

interface ScanHistoryModalProps {
  onClose: () => void;
  onViewReport: (scanId: string) => void;
}

const ScanHistoryModal: React.FC<ScanHistoryModalProps> = ({ onClose, onViewReport }) => {
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
        setError('An unknown error occurred while fetching scan history.');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const getStatusClass = (status: string) => {
    switch (status.toLowerCase()) {
      case 'completed':
        return 'bg-green-800 text-green-300';
      case 'failed':
        return 'bg-red-800 text-red-300';
      case 'running':
        return 'bg-yellow-800 text-yellow-300 animate-pulse';
      default:
        return 'bg-gray-700 text-gray-300';
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-70 flex justify-center items-center z-50 p-4">
      <div className="bg-background text-text w-full max-w-6xl h-full max-h-[90vh] rounded-lg shadow-2xl flex flex-col">
        <header className="bg-surface p-4 flex justify-between items-center rounded-t-lg">
          <h1 className="text-2xl font-bold">Scan History</h1>
          <div className="flex items-center space-x-4">
            <button
              className="p-2 rounded-md bg-surface hover:bg-gray-700 transition-colors"
              onClick={fetchHistory}
              disabled={loading}
              title="Refresh History"
            >
              <RefreshCw size={18} className={loading ? 'animate-spin' : ''} />
            </button>
            <button onClick={onClose} className="p-2 rounded-full hover:bg-gray-700">
              <X size={24} />
            </button>
          </div>
        </header>

        <main className="p-6 overflow-y-auto">
          {error && (
            <div className="text-center text-red-400 p-4 mb-4 bg-red-800/20 rounded-md">{error}</div>
          )}
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm text-left">
              <thead className="text-textSecondary uppercase">
                <tr>
                  <th className="p-3 font-semibold">Target</th>
                  <th className="p-3 font-semibold">Date</th>
                  <th className="p-3 font-semibold">Status</th>
                  <th className="p-3 font-semibold text-center">Findings</th>
                  <th className="p-3 font-semibold text-center">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {loading && history.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-textSecondary">Loading history...</td>
                  </tr>
                ) : history.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-textSecondary">No scan history found.</td>
                  </tr>
                ) : (
                  history.map((item) => (
                    <tr key={item.scan_id} className="hover:bg-surface transition-colors">
                      <td className="p-3 font-medium truncate max-w-md" title={item.target}>{item.target}</td>
                      <td className="p-3 text-textSecondary">{new Date(item.start_time).toLocaleString()}</td>
                      <td className="p-3 capitalize">
                        <span className={`px-2 py-1 text-xs font-semibold rounded-full ${getStatusClass(item.status)}`}>
                          {item.status}
                        </span>
                      </td>
                      <td className="p-3 text-center font-mono text-text">{item.finding_count}</td>
                      <td className="p-3 text-center">
                        <button
                          onClick={() => onViewReport(item.scan_id)}
                          className="text-primary hover:underline disabled:text-textSecondary disabled:no-underline"
                          disabled={item.status !== 'completed'}
                          title={item.status !== 'completed' ? 'Report available only for completed scans' : 'View Report'}
                        >
                          <FileText size={18} />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </main>
      </div>
    </div>
  );
};

export default ScanHistoryModal; 