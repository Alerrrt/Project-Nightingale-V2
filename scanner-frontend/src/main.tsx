import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { ScanWizard } from './components/ScanWizard';
import { Dashboard } from './components/Dashboard';

function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-gray-50">
        <Routes>
          <Route path="/" element={<ScanWizard />} />
          <Route path="/dashboard/:scanId" element={<Dashboard />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

ReactDOM.createRoot(document.getElementById('root')!).render(<App />); 