// frontend/src/components/ScanForm.js
import React, { useState } from 'react';
import { startScan } from '../services/api';

function ScanForm() {
  const [domain, setDomain] = useState('');
  const [message, setMessage] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!domain) {
      setMessage('Please enter a domain.');
      return;
    }
    try {
      const response = await startScan(domain);
      setMessage(`Scan started successfully! Scan ID: ${response.data.id}`);
      setDomain('');
    } catch (error) {
      setMessage('Failed to start scan. Please try again.');
      console.error(error);
    }
  };

  return (
    <div>
      <h2>Start a New Scan</h2>
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
        />
        <button type="submit">Scan</button>
      </form>
      {message && <p>{message}</p>}
    </div>
  );
}

export default ScanForm;