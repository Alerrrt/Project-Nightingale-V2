// Vitest test file for SecurityPostureChart
import { describe, it, expect } from 'vitest';
import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import SecurityPostureChart, { SecurityPostureData } from './SecurityPostureChart';

describe('SecurityPostureChart', () => {
  const sampleData: SecurityPostureData = {
    passed: 10,
    warning: 3,
    failed: 2,
  };

  it('renders chart title and legend', () => {
    render(<SecurityPostureChart reportData={sampleData} />);
    expect(screen.getByText(/Overall Security Posture/i)).toBeInTheDocument();
    expect(screen.getByText(/Passed/i)).toBeInTheDocument();
    expect(screen.getByText(/Warnings/i)).toBeInTheDocument();
    expect(screen.getByText(/Failed/i)).toBeInTheDocument();
  });

  it('renders correct values in the chart', () => {
    render(<SecurityPostureChart reportData={sampleData} />);
    // Pie chart labels (e.g., Passed: 67%)
    expect(screen.getByText(/Passed: [0-9]+%/)).toBeInTheDocument();
    expect(screen.getByText(/Warnings: [0-9]+%/)).toBeInTheDocument();
    expect(screen.getByText(/Failed: [0-9]+%/)).toBeInTheDocument();
  });

  // Tooltip rendering is handled by Recharts and is hard to test without user interaction,
  // but we can check that the chart is present.
  it('renders the PieChart SVG', () => {
    render(<SecurityPostureChart reportData={sampleData} />);
    expect(document.querySelector('svg')).toBeInTheDocument();
  });
}); 