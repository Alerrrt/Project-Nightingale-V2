import { motion } from 'framer-motion';
import { AlertTriangle, CheckCircle2, Loader2, XCircle } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card';

const OWASP_MODULES = [
  { id: 'A01', name: 'Broken Access Control', description: 'Restrictions on what authenticated users are allowed to do' },
  { id: 'A02', name: 'Cryptographic Failures', description: 'Failures related to cryptography which often lead to sensitive data exposure' },
  { id: 'A03', name: 'Injection', description: 'SQL, NoSQL, OS, and LDAP injection vulnerabilities' },
  { id: 'A04', name: 'Insecure Design', description: 'Flaws in design and architecture' },
  { id: 'A05', name: 'Security Misconfiguration', description: 'Improperly configured permissions, security features, or default accounts' },
  { id: 'A06', name: 'Vulnerable Components', description: 'Using components with known vulnerabilities' },
  { id: 'A07', name: 'Auth Failures', description: 'Identification and authentication failures' },
  { id: 'A08', name: 'Software Integrity', description: 'Software and data integrity failures' },
  { id: 'A09', name: 'Logging Failures', description: 'Security logging and monitoring failures' },
  { id: 'A10', name: 'SSRF', description: 'Server-Side Request Forgery' }
];

const getStatusIcon = (status) => {
  switch (status) {
    case 'completed':
      return <CheckCircle2 className="h-5 w-5 text-green-500" />;
    case 'running':
      return <Loader2 className="h-5 w-5 text-blue-500 animate-spin" />;
    case 'failed':
      return <XCircle className="h-5 w-5 text-red-500" />;
    case 'initializing':
      return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
    default:
      return null;
  }
};

const ScanStatus = ({ moduleStatuses = [], overallProgress = 0, elapsedTime = 0 }) => {
  const formatTime = (seconds) => {
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = Math.floor(seconds % 60);
    return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
  };

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span>Scan Progress</span>
          <span className="text-sm text-muted-foreground">
            {formatTime(elapsedTime)}
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {/* Overall Progress */}
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span>Overall Progress</span>
              <span>{overallProgress}%</span>
            </div>
            <div className="h-2 w-full bg-secondary rounded-full overflow-hidden">
              <motion.div
                className="h-full bg-primary"
                initial={{ width: 0 }}
                animate={{ width: `${overallProgress}%` }}
                transition={{ duration: 0.3 }}
              />
            </div>
          </div>

          {/* Module Statuses */}
          <div className="space-y-2">
            {Object.entries(moduleStatuses).map(([moduleName, status]) => (
              <div key={moduleName} className="space-y-1">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    {getStatusIcon(status.status)}
                    <span className="text-sm font-medium capitalize">
                      {moduleName.replace(/_/g, ' ')}
                    </span>
                  </div>
                  <span className="text-sm text-muted-foreground">
                    {status.progress}%
                  </span>
                </div>
                <div className="h-1.5 w-full bg-secondary rounded-full overflow-hidden">
                  <motion.div
                    className="h-full bg-primary"
                    initial={{ width: 0 }}
                    animate={{ width: `${status.progress}%` }}
                    transition={{ duration: 0.3 }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default ScanStatus; 