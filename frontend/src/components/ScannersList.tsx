import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ChevronDown } from 'lucide-react';
import * as scanApi from '../api/scanApi';

interface ScannerMeta {
  name: string;
  description: string;
  owasp_category: string;
}

type ScannersApiResponse = Record<string, Omit<ScannerMeta, 'name'>>;
type GroupedScanners = Record<string, ScannerMeta[]>;

interface ScannersListProps {
  onStartCustomScan: (selectedScanners: string[]) => void;
}

const ScannerAccordion: React.FC<{ 
  category: string; 
  scanners: ScannerMeta[];
  selectedScanners: string[];
  onScannerToggle: (scannerName: string) => void;
}> = ({ category, scanners, selectedScanners, onScannerToggle }) => {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <div className="border-b border-border">
      <button
        className="w-full flex justify-between items-center py-3 px-2 text-left text-sm font-semibold text-textSecondary hover:text-text transition-colors"
        onClick={() => setIsOpen(!isOpen)}
      >
        <span>{category} ({scanners.length})</span>
        <ChevronDown
          className={`transform transition-transform duration-300 ${isOpen ? 'rotate-180' : ''}`}
          size={16}
        />
      </button>
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease: 'easeInOut' }}
            className="overflow-hidden"
          >
            <div className="p-2 space-y-2">
              {scanners.map((scanner) => (
                <div key={scanner.name} className="flex items-center bg-surface rounded-md p-2">
                  <input
                    type="checkbox"
                    id={scanner.name}
                    checked={selectedScanners.includes(scanner.name)}
                    onChange={() => onScannerToggle(scanner.name)}
                    className="h-4 w-4 rounded border-gray-600 text-primary bg-surface focus:ring-primary mr-3"
                  />
                  <label htmlFor={scanner.name} className="flex-grow">
                    <p className="font-semibold text-xs text-primary truncate">{scanner.name}</p>
                    <p className="text-textSecondary text-xs mt-1">{scanner.description}</p>
                  </label>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

const ScannersList: React.FC<ScannersListProps> = ({ onStartCustomScan }) => {
  const [groupedScanners, setGroupedScanners] = useState<GroupedScanners>({});
  const [selectedScanners, setSelectedScanners] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleScannerToggle = (scannerName: string) => {
    setSelectedScanners(prev => 
      prev.includes(scannerName) 
        ? prev.filter(name => name !== scannerName)
        : [...prev, scannerName]
    );
  };

  const fetchScanners = async () => {
    setLoading(true);
    setError(null);
    try {
      const data: ScannersApiResponse = await scanApi.fetchScannersList();
      const scannersArr = Object.entries(data).map(([name, meta]) => ({ name, ...meta }));

      const grouped = scannersArr.reduce((acc: GroupedScanners, scanner) => {
        const category = scanner.owasp_category.startsWith('A') 
          ? scanner.owasp_category 
          : 'General Scanners';
        
        if (!acc[category]) {
          acc[category] = [];
        }
        acc[category].push(scanner);
        return acc;
      }, {});

      setGroupedScanners(grouped);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to fetch scanners list';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScanners();
  }, []);

  const sortedCategories = Object.keys(groupedScanners).sort((a, b) => {
    if (a === 'General Scanners') return 1;
    if (b === 'General Scanners') return -1;
    return a.localeCompare(b);
  });

  if (loading) {
    return <div className="text-center text-textSecondary text-sm p-4">Loading...</div>;
  }

  if (error) {
    return <div className="text-center text-error text-sm p-4">{error}</div>;
  }

  return (
    <div className="w-full flex flex-col h-full">
      <div className="flex-grow overflow-y-auto">
        {sortedCategories.map((category) => (
          <ScannerAccordion
            key={category}
            category={category}
            scanners={groupedScanners[category]}
            selectedScanners={selectedScanners}
            onScannerToggle={handleScannerToggle}
          />
        ))}
      </div>
      <div className="pt-4 mt-auto">
        <button
          onClick={() => onStartCustomScan(selectedScanners)}
          disabled={selectedScanners.length === 0}
          className="w-full bg-primary text-background font-bold py-2 px-4 rounded-md hover:bg-opacity-90 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Run Custom Scan ({selectedScanners.length})
        </button>
      </div>
    </div>
  );
};

export default ScannersList; 