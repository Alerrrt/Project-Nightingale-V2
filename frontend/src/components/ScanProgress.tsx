import React from 'react';

export interface ScanProgressData {
  phase: string;
  progress: number;
  currentUrl: string;
  foundVulns: number;
  scannedUrls: number;
  totalUrls: number;
  eta: string;
  completedModules?: number;
  totalModules?: number;
}

interface ScanProgressProps {
  scanProgress: ScanProgressData;
  isScanning: boolean;
}

const ScanProgress: React.FC<ScanProgressProps> = ({ scanProgress, isScanning }) => {
  if (!isScanning) return null;

  const progress = scanProgress.progress || 0;
  const phase = scanProgress.phase || "Initializing...";
  const scannedUrls = scanProgress.scannedUrls || 0;
  const totalUrls = scanProgress.totalUrls || 0;
  const foundVulns = scanProgress.foundVulns || 0;
  const currentUrl = scanProgress.currentUrl || "N/A";

  return (
    <div className="bg-surface rounded-lg p-6 mb-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-text">Scan in Progress...</h2>
        <span className="text-2xl font-mono font-bold text-primary">{Math.round(progress)}%</span>
      </div>

      <div className="w-full bg-background rounded-full h-3 mb-4">
        <div
          className="bg-primary h-3 rounded-full"
          style={{ width: `${progress}%`, transition: 'width 0.5s ease-in-out' }}
        />
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
        <div>
          <p className="text-sm text-textSecondary">Phase</p>
          <p className="text-lg font-semibold text-text">{phase}</p>
        </div>
        <div>
          <p className="text-sm text-textSecondary">URLs Scanned</p>
          <p className="text-lg font-semibold text-text">{scannedUrls} / {totalUrls > 0 ? totalUrls : '?'}</p>
        </div>
        <div>
          <p className="text-sm text-textSecondary">Vulns Found</p>
          <p className="text-lg font-semibold text-text">{foundVulns}</p>
        </div>
        <div>
          <p className="text-sm text-textSecondary">Est. Time Left</p>
          <p className="text-lg font-semibold text-text">{scanProgress.eta || 'N/A'}</p>
        </div>
        <div>
          <p className="text-sm text-textSecondary">Modules</p>
          <p className="text-lg font-semibold text-text">
            {scanProgress.completedModules || 0} / {scanProgress.totalModules || 0}
          </p>
        </div>
        <div className="col-span-2 md:col-span-2">
           <p className="text-sm text-textSecondary">Current Target</p>
           <p className="text-md font-mono text-text truncate" title={currentUrl}>{currentUrl}</p>
        </div>
      </div>
    </div>
  );
};

export default ScanProgress; 