import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
const WS_BASE_URL = process.env.REACT_APP_WS_URL || 'ws://localhost:8000';

export const getApiUrl = (endpoint) => `${API_BASE_URL}${endpoint}`;
export const getWsUrl = (endpoint) => `${WS_BASE_URL}${endpoint}`;

const apiClient = {
  startScan: async (target, scanType = "full_scan", options = {}) => {
    try {
      const response = await axios.post(getApiUrl('/scans/start'), { target, scan_type: scanType, options });
      return response.data;
    } catch (error) {
      console.error('Error starting scan:', error);
      throw new Error('Failed to start scan');
    }
  },

  getScanResults: async (scanId) => {
    try {
      const response = await axios.get(getApiUrl(`/scans/${scanId}/results`));
      return response.data;
    } catch (error) {
      console.error('Error fetching scan results:', error);
      throw new Error('Failed to fetch scan results');
    }
  },

  getHistoricalScans: async () => {
    try {
      const response = await axios.get(getApiUrl('/scans/history'));
      return response.data;
    } catch (error) {
      console.error('Error fetching historical scans:', error);
      throw new Error('Failed to fetch historical scans');
    }
  }
};

// Add request interceptor for debugging
axios.interceptors.request.use(
  (config) => {
    console.log('API Request:', config);
    return config;
  },
  (error) => {
    console.error('API Request Error:', error);
    return Promise.reject(error);
  }
);

// Add response interceptor for debugging
axios.interceptors.response.use(
  (response) => {
    console.log('API Response:', response);
    return response;
  },
  (error) => {
    console.error('API Response Error:', error);
    return Promise.reject(error);
  }
);

export default apiClient; 