import React from 'react';
import { cn } from '../../lib/utils';
import { AlertTriangle, AlertCircle, Info, Shield, Bug } from 'lucide-react';

export const SeverityBadge = ({ severity, className }) => {
  const getSeverityConfig = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return {
          color: 'bg-red-500 text-white',
          icon: <AlertTriangle className="h-3 w-3" />,
          label: 'Critical'
        };
      case 'high':
        return {
          color: 'bg-orange-500 text-white',
          icon: <AlertCircle className="h-3 w-3" />,
          label: 'High'
        };
      case 'medium':
        return {
          color: 'bg-yellow-500 text-white',
          icon: <Shield className="h-3 w-3" />,
          label: 'Medium'
        };
      case 'low':
        return {
          color: 'bg-blue-500 text-white',
          icon: <Info className="h-3 w-3" />,
          label: 'Low'
        };
      default:
        return {
          color: 'bg-gray-500 text-white',
          icon: <Bug className="h-3 w-3" />,
          label: severity
        };
    }
  };

  const config = getSeverityConfig(severity);

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium transition-colors',
        config.color,
        className
      )}
      role="status"
      aria-label={`Severity level: ${config.label}`}
    >
      {config.icon}
      {config.label}
    </span>
  );
};

export default SeverityBadge; 