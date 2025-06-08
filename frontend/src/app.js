import React from 'react';
import ScanForm from './components/ScanForm';
import './App.css';

function App() {
  return (
    <div className="App">
      <header className="App-header">
        <h1>Project Nightingale V2</h1>
      </header>
      <main>
        <ScanForm />
        {/* Later, you would add a component here to display scan results */}
      </main>
    </div>
  );
}

export default App;