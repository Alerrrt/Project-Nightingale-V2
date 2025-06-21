import React from 'react';
import type { ScanStats } from './StatsCards';

interface ScanSummaryProps {
  scanStats: ScanStats;
}

const ScanSummary: React.FC<ScanSummaryProps> = ({ scanStats }) => {
  return (
    <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
      <h3 className="text-xl font-semibold mb-4 flex items-center">
        <span className="h-5 w-5 mr-2 bg-cyan-400 rounded-full inline-block" />
        Scan Summary
      </h3>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div>
          <p className="text-sm text-gray-400">Scan Duration</p>
          <p className="text-lg font-semibold">{scanStats.scanDuration}</p>
        </div>
        <div>
          <p className="text-sm text-gray-400">URLs Scanned</p>
          <p className="text-lg font-semibold">{scanStats.urlsScanned}</p>
        </div>
        <div>
          <p className="text-sm text-gray-400">Last Scan</p>
          <p className="text-lg font-semibold">{scanStats.lastScan}</p>
        </div>
        <div>
          <p className="text-sm text-gray-400">Target</p>
          <p className="text-lg font-semibold truncate">{scanStats.target}</p>
        </div>
      </div>
    </div>
  );
};

export default ScanSummary; 