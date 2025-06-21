import React from 'react';
import { Code2 } from 'lucide-react';
import { VulnerabilityData } from './VulnerabilityList'; // Reuse the interface

interface JavaScriptVulnerabilitiesProps {
  vulnerabilities: VulnerabilityData[];
}

const getSeverityClass = (severity: string) => {
  switch (severity.toLowerCase()) {
    case 'critical': return 'text-red-500 bg-red-500/10 border-red-500/20';
    case 'high': return 'text-orange-400 bg-orange-400/10 border-orange-400/20';
    case 'medium': return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/20';
    case 'low': return 'text-sky-400 bg-sky-400/10 border-sky-400/20';
    case 'info': return 'text-gray-400 bg-gray-400/10 border-gray-400/20';
    default: return 'text-gray-400 bg-gray-400/10 border-gray-400/20';
  }
};

const JavaScriptVulnerabilities: React.FC<JavaScriptVulnerabilitiesProps> = ({ vulnerabilities }) => {
  return (
    <div className="bg-surface rounded-lg p-4">
      <div className="flex items-center mb-4">
        <Code2 className="h-6 w-6 text-primary mr-3" />
        <h2 className="text-xl font-bold text-text">JavaScript Library Vulnerabilities</h2>
      </div>
      <div className="space-y-3 max-h-60 overflow-y-auto">
        {vulnerabilities.map((vuln) => (
          <div key={vuln.id || vuln.title} className="bg-background p-3 rounded-md border-l-4 border-yellow-500/50">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center space-x-3 mb-2">
                  <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium border ${getSeverityClass(vuln.severity)}`}>
                    {vuln.severity}
                  </span>
                  <span className="text-xs text-textSecondary bg-surface px-2 py-1 rounded">
                    {vuln.cwe}
                  </span>
                </div>
                <h4 className="font-medium text-text mb-1">{vuln.title}</h4>
                <p className="text-sm text-textSecondary">{vuln.description}</p>
                 <p className="text-xs text-textSecondary mt-1 italic">Found in: {vuln.location}</p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default JavaScriptVulnerabilities; 