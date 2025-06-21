import React from 'react'
import ReactDOM from 'react-dom/client'
import './index.css'
import App from './App'
import { ScanProvider } from './context/ScanContext'
import { ToastProvider } from './components/ToastProvider'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ToastProvider>
      <ScanProvider>
        <App />
      </ScanProvider>
    </ToastProvider>
  </React.StrictMode>,
)
