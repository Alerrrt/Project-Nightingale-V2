import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ChevronDown, Clock } from 'lucide-react';
import Tooltip from './Tooltip';
import * as scanApi from '../api/scanApi';

interface ScannerMeta {
  key: string;
  name: string;
  description: string;
  owasp_category: string;
  longRunning?: boolean;
}

type ScannersApiResponse = Record<string, any>;
type GroupedScanners = Record<string, ScannerMeta[]>;

interface ScannersListProps {
  onStartCustomScan: (selectedScanners: string[]) => void;
}

const ScannerAccordion: React.FC<{ 
  category: string; 
  scanners: ScannerMeta[];
  selectedScanners: string[];
  onScannerToggle: (scannerKey: string) => void;
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
                <div key={scanner.key} className="flex items-center bg-surface rounded-md p-2">
                  <input
                    type="checkbox"
                    id={scanner.key}
                    checked={selectedScanners.includes(scanner.key)}
                    onChange={() => onScannerToggle(scanner.key)}
                    className="h-4 w-4 rounded border-gray-600 text-primary bg-surface focus:ring-primary mr-3"
                  />
                  <label htmlFor={scanner.key} className="flex-grow flex items-center">
                    <p className="font-semibold text-xs text-primary truncate flex items-center">
                      {scanner.name}
                      {scanner.longRunning && (
                        <Tooltip content="This scanner may take several minutes to complete." position="top">
                          <Clock className="inline-block ml-1 text-warning w-4 h-4" />
                        </Tooltip>
                      )}
                    </p>
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

  const handleScannerToggle = (scannerKey: string) => {
    setSelectedScanners(prev => 
      prev.includes(scannerKey) 
        ? prev.filter(key => key !== scannerKey)
        : [...prev, scannerKey]
    );
  };

  const fetchScanners = async () => {
    setLoading(true);
    setError(null);
    try {
      const data: ScannersApiResponse = await scanApi.fetchScannersList();
      const scannersArr = Object.entries(data).map(([key, meta]) => ({ key, name: (meta as any).name, description: (meta as any).description, owasp_category: (meta as any).owasp_category, longRunning: false }));

      // Hardcoded list of long-running scanners (can be refined)
      const longRunningScanners = [
        'automated_cve_lookup_scanner',
        'subdomain_dns_enumeration_scanner',
        'ssl_tls_configuration_audit_scanner',
        'api_fuzzing_scanner',
      ];
      const offByDefaultScanners = [
        'sql_injection_scanner',
        'broken_access_control_scanner',
        'broken_authentication_scanner',
        'open_redirect_scanner',
      ];
      scannersArr.forEach(scanner => {
        if (longRunningScanners.includes(scanner.key)) {
          scanner.longRunning = true;
        }
      });
      // Default: select only non-longRunning and not offByDefaultScanners
      if (selectedScanners.length === 0) {
        setSelectedScanners(
          scannersArr
            .filter(s => !s.longRunning && !offByDefaultScanners.includes(s.key))
            .map(s => s.key)
        );
      }

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