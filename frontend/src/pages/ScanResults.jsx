import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import { VulnerabilityAnalytics } from '../components/VulnerabilityAnalytics';

const ScanResults = () => {
  const { scanId } = useParams();
  const [findings, setFindings] = useState([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchFindings = async () => {
      try {
        const response = await fetch(`/api/scans/${scanId}/results`);
        if (!response.ok) throw new Error('Failed to fetch scan results');
        const data = await response.json();
        setFindings(data);
      } catch (error) {
        console.error('Error fetching scan results:', error);
      } finally {
        setIsLoading(false);
      }
    };

    fetchFindings();
  }, [scanId]);

  if (isLoading) {
    return (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="flex items-center justify-center min-h-screen"
      >
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
      </motion.div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="space-y-6"
    >
      <h1 className="text-2xl font-bold">Scan Results</h1>
      <VulnerabilityAnalytics findings={findings} />
      {/* Add more components as needed */}
    </motion.div>
  );
};

export default ScanResults; 