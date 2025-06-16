import React from 'react';
import { Card } from './ui/Card';
import { cn } from '../lib/utils';
import { 
  Info, 
  Clock, 
  Loader2, 
  CheckCircle2, 
  AlertTriangle, 
  XCircle,
  AlertCircle,
  Shield,
  Bug,
  Lock,
  FileSearch,
  Network,
  Database,
  Code,
  Server
} from 'lucide-react';
import Tooltip from '@mui/material/Tooltip';
import LinearProgress from '@mui/material/LinearProgress';

// 1. Name mapping and metadata
export const SCANNER_LABELS = {
  sql_injection: 'SQL Injection',
  xss: 'Cross-Site Scripting (XSS)',
  csrf_token_checker: 'CSRF Token Checker',
  broken_authentication: 'Broken Authentication',
  security_misconfiguration: 'Security Misconfiguration',
  sensitive_data_exposure: 'Sensitive Data Exposure',
  ssrf: 'Server-Side Request Forgery (SSRF)',
  xxe: 'XML External Entity (XXE)',
  using_components_with_known_vulnerabilities: 'Vulnerable Components',
  insecure_design: 'Insecure Design',
  insufficient_logging_and_monitoring: 'Insufficient Logging & Monitoring',
  // ...add more as needed
};

export const SCANNER_METADATA = {
  sql_injection: { description: 'Detects SQL injection vulnerabilities by injecting common payloads and analyzing responses.' },
  xss: { description: 'Detects potential XSS vulnerabilities by searching for script tags and unescaped user input.' },
  csrf_token_checker: { description: 'Checks for the presence of anti-CSRF tokens in HTML forms.' },
  broken_authentication: { description: 'Detects missing authentication and weak credentials on common authentication endpoints.' },
  security_misconfiguration: { description: 'Detects common security misconfigurations such as exposed files and missing security headers.' },
  sensitive_data_exposure: { description: 'Detects exposure of sensitive data such as emails, API keys, and credentials in responses and headers.' },
  ssrf: { description: 'Detects SSRF vulnerabilities by attempting to access internal resources via user-controlled parameters.' },
  xxe: { description: 'Detects XXE vulnerabilities by sending crafted XML payloads.' },
  using_components_with_known_vulnerabilities: { description: 'Detects use of outdated or vulnerable client/server components by analyzing versions in HTML and headers.' },
  insecure_design: { description: 'Detects insecure design patterns such as missing security headers, weak password policies, and lack of rate limiting.' },
  insufficient_logging_and_monitoring: { description: 'Detects missing security headers and improper error handling that may indicate insufficient logging and monitoring.' },
  // ...add more as needed
};

// Scanner icons mapping
const SCANNER_ICONS = {
  sql_injection: <Database className="h-4 w-4" />,
  xss: <Code className="h-4 w-4" />,
  csrf_token_checker: <Shield className="h-4 w-4" />,
  broken_authentication: <Lock className="h-4 w-4" />,
  security_misconfiguration: <Server className="h-4 w-4" />,
  sensitive_data_exposure: <FileSearch className="h-4 w-4" />,
  ssrf: <Network className="h-4 w-4" />,
  xxe: <Code className="h-4 w-4" />,
  using_components_with_known_vulnerabilities: <Bug className="h-4 w-4" />,
  insecure_design: <AlertCircle className="h-4 w-4" />,
  insufficient_logging_and_monitoring: <Info className="h-4 w-4" />,
};

// Status icons with better visual feedback
const STATUS_ICONS = {
  pending: <Clock className="h-4 w-4 animate-pulse" aria-label="Pending" />,
  initializing: <Loader2 className="h-4 w-4 animate-spin" aria-label="Initializing" />,
  running: <Loader2 className="h-4 w-4 animate-spin" aria-label="Running" />,
  completed: <CheckCircle2 className="h-4 w-4 text-green-500" aria-label="Completed" />,
  failed: <XCircle className="h-4 w-4 text-red-500" aria-label="Failed" />,
  warning: <AlertTriangle className="h-4 w-4 text-yellow-500" aria-label="Warning" />,
};

// Status colors with better contrast
const STATUS_COLORS = {
  pending: 'bg-gray-400 text-white',
  running: 'bg-blue-500 text-white',
  completed: 'bg-green-500 text-white',
  failed: 'bg-red-500 text-white',
  initializing: 'bg-yellow-500 text-white',
  warning: 'bg-orange-500 text-white',
};

function Badge({ status, label }) {
  return (
    <span
      className={cn(
        'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold',
        STATUS_COLORS[status] || 'bg-gray-300 text-gray-800'
      )}
      aria-label={label + ' status: ' + status}
    >
      {STATUS_ICONS[status] || null}
      <span className="ml-1">{label}</span>
    </span>
  );
}

function formatDate(dateStr) {
  if (!dateStr) return 'N/A';
  const d = new Date(dateStr);
  return d.toLocaleString();
}

// 3. Grouping and sorting
function groupModules(modules) {
  const groups = {
    pending: [],
    running: [],
    completed: [],
    failed: [],
    initializing: [],
  };
  for (const m of modules) {
    const status =
      m.status === 'initializing' || m.status === 'pending'
        ? 'pending'
        : m.status === 'running'
        ? 'running'
        : m.status === 'completed'
        ? 'completed'
        : m.status === 'failed'
        ? 'failed'
        : m.status === 'initializing'
        ? 'initializing'
        : 'pending';
    groups[status] = groups[status] || [];
    groups[status].push(m);
  }
  // Sort each group alphabetically by label
  for (const key in groups) {
    groups[key] = groups[key].sort((a, b) => {
      const labelA = SCANNER_LABELS[a.id] || a.id;
      const labelB = SCANNER_LABELS[b.id] || b.id;
      return labelA.localeCompare(labelB);
    });
  }
  return groups;
}

// 4. Main component
export default function ModuleStatuses({ modules }) {
  const [expandedGroups, setExpandedGroups] = React.useState({});
  const [loadingGroups, setLoadingGroups] = React.useState({});
  const ITEMS_PER_PAGE = 5;

  const groups = groupModules(modules);
  const sections = [
    { key: 'pending', label: 'Pending', color: 'gray' },
    { key: 'running', label: 'In Progress', color: 'blue' },
    { key: 'completed', label: 'Done', color: 'green' },
    { key: 'failed', label: 'Failed', color: 'red' },
  ];

  const toggleGroup = async (groupKey) => {
    setLoadingGroups(prev => ({ ...prev, [groupKey]: true }));
    // Simulate a small delay for better UX
    await new Promise(resolve => setTimeout(resolve, 150));
    setExpandedGroups(prev => ({
      ...prev,
      [groupKey]: !prev[groupKey]
    }));
    setLoadingGroups(prev => ({ ...prev, [groupKey]: false }));
  };

  const getVisibleItems = (items, groupKey) => {
    if (!items) return [];
    return expandedGroups[groupKey] ? items : items.slice(0, ITEMS_PER_PAGE);
  };

  return (
    <div className="space-y-6">
      {sections.map(({ key, label }) =>
        groups[key] && groups[key].length > 0 ? (
          <div key={key} className="transition-all duration-300 ease-in-out">
            <h2 className={cn(
              'text-lg font-bold mb-2 flex items-center gap-2',
              key === 'pending' && 'text-gray-500',
              key === 'running' && 'text-blue-600',
              key === 'completed' && 'text-green-600',
              key === 'failed' && 'text-red-600'
            )}>
              {STATUS_ICONS[key]}
              {label}
              <span className="text-sm font-normal text-muted-foreground">
                ({groups[key].length})
              </span>
            </h2>
            <div 
              className={cn(
                "grid grid-cols-1 md:grid-cols-2 gap-4 transition-all duration-300 ease-in-out",
                !expandedGroups[key] && groups[key].length > ITEMS_PER_PAGE && "overflow-hidden"
              )}
              id={`${key}-group`}
            >
              {getVisibleItems(groups[key], key).map((m) => (
                <Card 
                  key={m.id} 
                  className="p-4 hover:shadow-lg transition-shadow"
                  role="article"
                  aria-label={`${SCANNER_LABELS[m.id] || m.id} module status`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      {SCANNER_ICONS[m.id] || <Bug className="h-4 w-4" />}
                      <Badge status={key} label={SCANNER_LABELS[m.id] || m.id} />
                    </div>
                    <Tooltip title={SCANNER_METADATA[m.id]?.description || 'No description available'} placement="top" arrow>
                      <Info 
                        className="h-4 w-4 text-muted-foreground cursor-pointer hover:text-primary transition-colors" 
                        aria-label="Module information" 
                      />
                    </Tooltip>
                  </div>
                  <LinearProgress 
                    variant="determinate" 
                    value={m.progress} 
                    sx={{ 
                      height: 8, 
                      borderRadius: 4,
                      backgroundColor: 'rgba(0,0,0,0.1)',
                      '& .MuiLinearProgress-bar': {
                        backgroundColor: key === 'failed' ? '#ef4444' : 
                                       key === 'completed' ? '#22c55e' : 
                                       key === 'running' ? '#3b82f6' : '#9ca3af'
                      }
                    }} 
                    aria-label={`Progress: ${m.progress}%`} 
                  />
                  <div className="flex justify-between text-xs mt-2 text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {formatDate(m.lastRun)}
                    </span>
                    <span className="flex items-center gap-1">
                      <Bug className="h-3 w-3" />
                      {m.findingsCount ?? 0} findings
                    </span>
                  </div>
                </Card>
              ))}
            </div>
            {groups[key].length > ITEMS_PER_PAGE && (
              <button
                onClick={() => toggleGroup(key)}
                className={cn(
                  "mt-4 text-sm text-primary hover:text-primary/80 transition-colors flex items-center gap-1",
                  "focus:outline-none focus:ring-2 focus:ring-primary/50 rounded-md px-2 py-1",
                  loadingGroups[key] && "opacity-50 cursor-not-allowed"
                )}
                disabled={loadingGroups[key]}
                aria-expanded={expandedGroups[key]}
                aria-controls={`${key}-group`}
              >
                {loadingGroups[key] ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Loading...
                  </>
                ) : expandedGroups[key] ? (
                  <>
                    Show Less
                    <svg 
                      className="h-4 w-4 transition-transform duration-300" 
                      fill="none" 
                      viewBox="0 0 24 24" 
                      stroke="currentColor"
                      aria-hidden="true"
                    >
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
                    </svg>
                  </>
                ) : (
                  <>
                    Show More ({groups[key].length - ITEMS_PER_PAGE} more)
                    <svg 
                      className="h-4 w-4 transition-transform duration-300" 
                      fill="none" 
                      viewBox="0 0 24 24" 
                      stroke="currentColor"
                      aria-hidden="true"
                    >
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                    </svg>
                  </>
                )}
              </button>
            )}
          </div>
        ) : null
      )}
    </div>
  );
} 