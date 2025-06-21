import React, { useEffect, useState } from 'react';
import { BarChart3, AlertTriangle, Flame, AlertCircle, Info, Eye } from 'lucide-react';
import Tooltip from './Tooltip';

export interface ScanStats {
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  scanDuration: string;
  urlsScanned: number;
  lastScan: string;
  target: string;
}

interface StatsCardsProps {
  scanStats: ScanStats;
}

// Animated number with bounce effect
const AnimatedNumber: React.FC<{ value: number }> = ({ value }) => {
  const [display, setDisplay] = useState(0);
  const [bounce, setBounce] = useState(false);
  useEffect(() => {
    let start = 0;
    const step = () => {
      start += Math.ceil((value - start) / 5);
      if (start >= value) {
        setDisplay(value);
        setBounce(true);
        setTimeout(() => setBounce(false), 400);
      } else {
        setDisplay(start);
        requestAnimationFrame(step);
      }
    };
    step();
     
  }, [value]);
  return <span className={bounce ? 'animate-bounce-once' : ''}>{display}</span>;
};

const cardData = [
  {
    label: 'Total',
    valueKey: 'totalVulnerabilities',
    text: 'text-cyan-200',
    border: 'border-cyan-700',
    icon: <BarChart3 className="h-10 w-10 text-cyan-300 animate-pulse-slow group-hover:scale-125 group-hover:rotate-6 transition-transform duration-300" aria-label="Total" />, // slow pulse
    tooltip: 'Total number of unique vulnerabilities found.',
  },
  {
    label: 'Critical',
    valueKey: 'criticalCount',
    text: 'text-red-400',
    border: 'border-red-700',
    icon: <AlertTriangle className="h-10 w-10 text-red-400 animate-pulse group-hover:scale-125 group-hover:-rotate-6 transition-transform duration-300" aria-label="Critical" />, // fast pulse
    tooltip: 'Critical vulnerabilities that should be addressed immediately.',
  },
  {
    label: 'High',
    valueKey: 'highCount',
    text: 'text-orange-400',
    border: 'border-orange-600',
    icon: <Flame className="h-10 w-10 text-orange-400 animate-flicker group-hover:scale-125 group-hover:rotate-12 transition-transform duration-300" aria-label="High" />, // custom flicker
    tooltip: 'High-impact vulnerabilities that are likely to be exploited.',
  },
  {
    label: 'Medium',
    valueKey: 'mediumCount',
    text: 'text-yellow-300',
    border: 'border-yellow-600',
    icon: <AlertCircle className="h-10 w-10 text-yellow-300 animate-bounce group-hover:scale-125 group-hover:-rotate-12 transition-transform duration-300" aria-label="Medium" />, // bounce
    tooltip: 'Medium-impact vulnerabilities that may lead to data exposure.',
  },
  {
    label: 'Low',
    valueKey: 'lowCount',
    text: 'text-blue-300',
    border: 'border-blue-700',
    icon: <Eye className="h-10 w-10 text-blue-300 animate-spin-slow group-hover:scale-125 group-hover:rotate-12 transition-transform duration-300" aria-label="Low" />, // slow spin
    tooltip: 'Low-impact vulnerabilities or misconfigurations.',
  },
  {
    label: 'Info',
    valueKey: 'infoCount',
    text: 'text-gray-300',
    border: 'border-gray-700',
    icon: <Info className="h-10 w-10 text-gray-300 animate-shimmer group-hover:scale-125 group-hover:-rotate-12 transition-transform duration-300" aria-label="Info" />, // custom shimmer
    tooltip: 'Informational findings that do not pose an immediate risk.',
  },
];

// Custom animation classes (add to your Tailwind config if needed)
// .animate-pulse-slow { animation: pulse 2.5s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
// .animate-flicker { animation: flicker 1.2s infinite alternate; }
// .animate-spin-slow { animation: spin 3s linear infinite; }
// .animate-shimmer { animation: shimmer 2s linear infinite; }

const StatsCards: React.FC<StatsCardsProps> = ({ scanStats }) => {
  return (
    <div className="w-full grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-10 animate-fade-in-up">
      {cardData.map((card, idx) => (
        <Tooltip key={card.label} content={card.tooltip} position="top">
          <div
            className={`group bg-[#181f2a] rounded-2xl border ${card.border} shadow-lg flex flex-col items-center justify-center px-12 py-12 text-center min-w-0 transition-transform duration-300 hover:scale-110 hover:shadow-2xl hover:border-2 hover:border-cyan-400/60 animate-fade-in-up`}
            tabIndex={0}
            aria-label={`${card.label} vulnerabilities: ${scanStats[card.valueKey as keyof ScanStats]}`}
            style={{ animationDelay: `${idx * 80}ms` }}
          >
            <div className="flex flex-row items-center justify-center gap-6 mb-7 w-full">
              {card.icon}
              <span className={`text-2xl font-semibold ${card.text}`}>{card.label}</span>
            </div>
            <div className={`text-6xl font-extrabold ${card.text} mt-5`}><AnimatedNumber value={scanStats[card.valueKey as keyof ScanStats] as number} /></div>
          </div>
        </Tooltip>
      ))}
    </div>
  );
};

export default StatsCards; 