import React from 'react';
import { UrlInput } from '../components/UrlInput';

const NewScan = () => {
  const handleScanSubmit = (url) => {
    // Handle scan submission
    console.log('Starting scan for:', url);
  };

  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="text-2xl font-bold mb-6">New Scan</h1>
      <div className="max-w-2xl mx-auto">
        <UrlInput onScanSubmit={handleScanSubmit} />
      </div>
    </div>
  );
};

export default NewScan; 