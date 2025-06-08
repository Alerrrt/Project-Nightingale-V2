// frontend/src/services/api.js
import axios from 'axios';

const apiClient = axios.create({
  baseURL: 'http://localhost:8000', // URL of our FastAPI backend
  headers: {
    'Content-Type': 'application/json',
  },
});

export const startScan = (domain) => {
  return apiClient.post('/scans/', { domain });
};

export const getScanResults = (scanId) => {
  return apiClient.get(`/scans/${scanId}/vulnerabilities`);
};