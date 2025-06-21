import React, { useEffect, useState } from 'react';
import { X, Save, ShieldCheck, ShieldOff } from 'lucide-react';
import * as scanApi from '../api/scanApi';

interface ScannerMeta {
  name: string;
  description: string;
  owasp_category: string;
}

type ScannersApiResponse = Record<string, Omit<ScannerMeta, 'name'>>;

interface ScanConfigPanelProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: (selectedScanners: string[]) => void;
  initialSelectedScanners: string[];
}

const ScanConfigPanel: React.FC<ScanConfigPanelProps> = ({ isOpen, onClose, onSave, initialSelectedScanners }) => {
  const [scanners, setScanners] = useState<ScannerMeta[]>([]);
  const [selectedScanners, setSelectedScanners] = useState<Set<string>>(new Set(initialSelectedScanners));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchScanners = async () => {
      setLoading(true);
      setError(null);
      try {
        const data: ScannersApiResponse = await scanApi.fetchScannersList();
        const scannersArr = Object.entries(data).map(([name, meta]) => ({ name, ...meta }));
        setScanners(scannersArr);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load scanners.');
      } finally {
        setLoading(false);
      }
    };
    if (isOpen) {
      fetchScanners();
    }
  }, [isOpen]);

  useEffect(() => {
    setSelectedScanners(new Set(initialSelectedScanners));
  }, [initialSelectedScanners]);

  const handleToggleScanner = (scannerName: string) => {
    setSelectedScanners(prev => {
      const newSet = new Set(prev);
      if (newSet.has(scannerName)) {
        newSet.delete(scannerName);
      } else {
        newSet.add(scannerName);
      }
      return newSet;
    });
  };
  
  const handleSelectAll = () => {
    setSelectedScanners(new Set(scanners.map(s => s.name)));
  };

  const handleDeselectAll = () => {
    setSelectedScanners(new Set());
  };

  const handleSave = () => {
    onSave(Array.from(selectedScanners));
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-70 flex justify-center items-center z-50 p-4">
      <div className="bg-background text-text w-full max-w-2xl h-full max-h-[80vh] rounded-lg shadow-2xl flex flex-col">
        <header className="bg-surface p-4 flex justify-between items-center rounded-t-lg">
          <h1 className="text-xl font-bold">Scan Configuration</h1>
          <button onClick={onClose} className="p-2 rounded-full hover:bg-gray-700">
            <X size={24} />
          </button>
        </header>

        <main className="p-6 overflow-y-auto">
          {loading && <p className="text-center text-textSecondary">Loading scanners...</p>}
          {error && <p className="text-center text-error">{error}</p>}
          
          {!loading && !error && (
            <>
              <div className="flex justify-between items-center mb-4">
                <p className="text-sm text-textSecondary">{selectedScanners.size} of {scanners.length} scanners selected</p>
                <div className="flex space-x-2">
                  <button onClick={handleSelectAll} className="flex items-center text-xs bg-surface hover:bg-opacity-80 px-3 py-1 rounded">
                    <ShieldCheck size={14} className="mr-1" /> All
                  </button>
                  <button onClick={handleDeselectAll} className="flex items-center text-xs bg-surface hover:bg-opacity-80 px-3 py-1 rounded">
                    <ShieldOff size={14} className="mr-1" /> None
                  </button>
                </div>
              </div>
              <div className="space-y-2">
                {scanners.map(scanner => (
                  <div 
                    key={scanner.name}
                    onClick={() => handleToggleScanner(scanner.name)}
                    className="flex items-center p-3 bg-surface rounded-md cursor-pointer border-2 border-transparent hover:border-primary transition-all"
                  >
                    <input
                      type="checkbox"
                      checked={selectedScanners.has(scanner.name)}
                      readOnly
                      className="h-4 w-4 rounded bg-background border-gray-600 text-primary focus:ring-primary"
                    />
                    <div className="ml-3">
                      <p className="font-semibold text-sm text-text">{scanner.name}</p>
                      <p className="text-xs text-textSecondary">{scanner.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </main>

        <footer className="bg-surface p-4 mt-auto rounded-b-lg flex justify-end">
            <button 
              onClick={handleSave}
              className="bg-primary hover:bg-opacity-80 text-background font-bold py-2 px-4 rounded-md flex items-center"
            >
                <Save size={18} className="mr-2" />
                Save and Close
            </button>
        </footer>
      </div>
    </div>
  );
};

export default ScanConfigPanel; 