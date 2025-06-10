import React from "react"
import { BrowserRouter, Routes, Route } from "react-router-dom"
import { ScanWizard } from "./components/ScanWizard"
import { Dashboard } from "./components/Dashboard"

export const App = () => (
  <BrowserRouter>
    <div className="min-h-screen bg-gray-50 flex flex-col">
      <header className="bg-indigo-700 text-white py-4 px-6 shadow">
        <h1 className="text-2xl font-bold tracking-tight">Vulnerability Scanner</h1>
      </header>
      <main className="flex-1 flex flex-col items-center justify-center">
        <Routes>
          <Route path="/" element={<ScanWizard />} />
          <Route path="/dashboard/:scanId" element={<Dashboard />} />
        </Routes>
      </main>
    </div>
  </BrowserRouter>
)
