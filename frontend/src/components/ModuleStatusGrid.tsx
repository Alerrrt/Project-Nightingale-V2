import React from 'react';
import { CheckCircle, AlertTriangle, Loader } from 'lucide-react';

export interface ModuleStatus {
  name: string;
  status: 'started' | 'completed' | 'failed' | 'running';
  error?: string;
  findings_count?: number;
}

interface ModuleStatusGridProps {
  modules: ModuleStatus[];
}

const statusConfig = {
  completed: {
    bgColor: 'bg-emerald-900/50',
    borderColor: 'border-emerald-500/60',
    textColor: 'text-emerald-400',
    icon: <CheckCircle className="h-4 w-4 text-emerald-500" />,
    label: 'Completed'
  },
  running: {
    bgColor: 'bg-blue-900/50',
    borderColor: 'border-blue-500/60',
    textColor: 'text-blue-400',
    icon: <Loader className="h-4 w-4 text-blue-500 animate-spin" />,
    label: 'Running'
  },
  started: {
    bgColor: 'bg-blue-900/50',
    borderColor: 'border-blue-500/60',
    textColor: 'text-blue-400',
    icon: <Loader className="h-4 w-4 text-blue-500 animate-spin" />,
    label: 'Running'
  },
  failed: {
    bgColor: 'bg-red-900/50',
    borderColor: 'border-red-500/60',
    textColor: 'text-red-400',
    icon: <AlertTriangle className="h-4 w-4 text-red-500" />,
    label: 'Failed'
  },
};

const ModuleStatusGrid: React.FC<ModuleStatusGridProps> = ({ modules }) => {
  if (modules.length === 0) return null;
  
  return (
    <div className="bg-surface rounded-lg p-4 mb-6">
      <h3 className="text-lg font-bold text-text mb-4">Live Module Status</h3>
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3">
        {modules.map((mod) => {
          const config = statusConfig[mod.status] || statusConfig.failed;
          const displayName = mod.name.replace(/_/g, ' ').replace(/ scanner/g, '').replace(/\b\w/g, l => l.toUpperCase());

          return (
            <div
              key={mod.name}
              className={`flex items-center space-x-3 p-3 rounded-md border ${config.bgColor} ${config.borderColor} transition-all duration-300`}
              title={mod.status === 'failed' && mod.error ? mod.error : `${displayName} - ${config.label}`}
            >
              {config.icon}
              <div className="flex-1 overflow-hidden">
                  <p className="font-medium text-sm text-text truncate">{displayName}</p>
                  <p className={`text-xs ${config.textColor}`}>{config.label}</p>
              </div>
              {mod.status === 'completed' && (
                <span className="text-xs font-bold text-emerald-400 bg-emerald-900/80 px-2 py-1 rounded-full">
                  {mod.findings_count ?? 0}
                </span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default React.memo(ModuleStatusGrid); 