import { motion } from 'framer-motion';
import { AlertTriangle, ChevronDown, ChevronUp, ExternalLink, Loader2 } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card';
import { Accordion, AccordionItem, AccordionTrigger, AccordionContent } from './ui/Accordion';
import SeverityBadge from './ui/SeverityBadge';
import { cn } from '../lib/utils';
import { useState, useEffect } from 'react';

const CWE_SEVERITY_MAP = {
  'Critical': ['CWE-20', 'CWE-22', 'CWE-78', 'CWE-89', 'CWE-352', 'CWE-434'],
  'High': ['CWE-79', 'CWE-287', 'CWE-502', 'CWE-611', 'CWE-918'],
  'Medium': ['CWE-200', 'CWE-209', 'CWE-601', 'CWE-798'],
  'Low': ['CWE-212', 'CWE-215', 'CWE-310', 'CWE-326'],
  'Info': ['CWE-209', 'CWE-215', 'CWE-310']
};

const CWE_DESCRIPTIONS = {
  'CWE-20': 'Improper Input Validation',
  'CWE-22': 'Path Traversal',
  'CWE-78': 'OS Command Injection',
  'CWE-79': 'Cross-Site Scripting',
  'CWE-89': 'SQL Injection',
  'CWE-200': 'Information Exposure',
  'CWE-209': 'Information Exposure Through an Error Message',
  'CWE-212': 'Improper Removal of Sensitive Information',
  'CWE-215': 'Information Exposure Through Debug Information',
  'CWE-287': 'Improper Authentication',
  'CWE-310': 'Cryptographic Issues',
  'CWE-326': 'Inadequate Encryption Strength',
  'CWE-352': 'Cross-Site Request Forgery',
  'CWE-434': 'Unrestricted Upload of File with Dangerous Type',
  'CWE-502': 'Deserialization of Untrusted Data',
  'CWE-601': 'URL Redirection to Untrusted Site',
  'CWE-611': 'Information Exposure Through XML External Entity Reference',
  'CWE-798': 'Use of Hard-coded Credentials',
  'CWE-918': 'Server-Side Request Forgery (SSRF)'
};

const getCWEInfo = (finding) => {
  const cweId = finding.cwe_id;
  if (!cweId) return null;
  
  const description = CWE_DESCRIPTIONS[cweId] || 'Unknown CWE';
  const severity = Object.entries(CWE_SEVERITY_MAP).find(([_, cwes]) => 
    cwes.includes(cweId)
  )?.[0] || 'Info';

  return {
    id: cweId,
    description,
    severity
  };
};

const ScanReport = ({ findings, isScanning = false, progress = 0 }) => {
  const [expandedGroups, setExpandedGroups] = useState({});

  const groupedFindings = findings.reduce((acc, finding) => {
    const key = `${finding.vulnerability_type}-${finding.severity}`;
    if (!acc[key]) {
      acc[key] = {
        vulnerability_type: finding.vulnerability_type,
        severity: finding.severity,
        findings: [],
        cweInfo: getCWEInfo(finding)
      };
    }
    acc[key].findings.push(finding);
    return acc;
  }, {});

  const severityOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  const sortedGroups = Object.values(groupedFindings).sort(
    (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
  );

  const toggleGroup = (key) => {
    setExpandedGroups(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
  };

  return (
    <div className="space-y-6">
      {isScanning && (
        <Card className="mb-6">
          <CardContent className="p-6">
            <div className="flex items-center gap-4">
              <Loader2 className="h-6 w-6 animate-spin text-primary" />
              <div className="flex-1">
                <div className="flex justify-between mb-2">
                  <span className="text-sm font-medium">Scanning in progress...</span>
                  <span className="text-sm text-muted-foreground">{progress}%</span>
                </div>
                <div className="h-2 bg-muted rounded-full overflow-hidden">
                  <motion.div
                    className="h-full bg-primary"
                    initial={{ width: 0 }}
                    animate={{ width: `${progress}%` }}
                    transition={{ duration: 0.3 }}
                  />
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {sortedGroups.map((group, index) => (
        <motion.div
          key={`${group.vulnerability_type}-${group.severity}-${index}`}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: index * 0.1 }}
        >
          <Card className="overflow-hidden">
            <CardHeader className="bg-muted/50">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <SeverityBadge severity={group.severity} />
                  <CardTitle className="text-lg font-semibold">
                    {group.vulnerability_type}
                    {group.findings.length > 1 && (
                      <span className="ml-2 text-sm text-muted-foreground">
                        ({group.findings.length} instances)
                      </span>
                    )}
                  </CardTitle>
                </div>
                <button
                  onClick={() => toggleGroup(`${group.vulnerability_type}-${group.severity}`)}
                  className="p-2 hover:bg-muted rounded-full transition-colors"
                >
                  {expandedGroups[`${group.vulnerability_type}-${group.severity}`] ? (
                    <ChevronUp className="h-5 w-5" />
                  ) : (
                    <ChevronDown className="h-5 w-5" />
                  )}
                </button>
              </div>
            </CardHeader>
            <CardContent className="p-6">
              <div className="space-y-4">
                {group.cweInfo && (
                  <div className="flex items-start gap-2 text-sm">
                    <AlertTriangle className="h-4 w-4 mt-0.5 text-amber-warning" />
                    <div>
                      <p className="font-medium">
                        CWE-{group.cweInfo.id}: {group.cweInfo.description}
                      </p>
                      <a
                        href={`https://cwe.mitre.org/data/definitions/${group.cweInfo.id}.html`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-primary hover:underline inline-flex items-center gap-1"
                      >
                        View CWE Details
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>
                  </div>
                )}
                
                {expandedGroups[`${group.vulnerability_type}-${group.severity}`] && (
                  <div className="space-y-4">
                    {group.findings.map((finding, idx) => (
                      <div key={finding.id || idx} className="border-l-2 border-muted pl-4">
                        <h4 className="font-medium mb-2">Instance {idx + 1}</h4>
                        <p className="text-sm text-muted-foreground mb-2">{finding.description}</p>
                        {finding.technical_details && (
                          <div className="rounded-lg bg-muted p-4">
                            <pre className="text-xs whitespace-pre-wrap">{finding.technical_details}</pre>
                          </div>
                        )}
                        {finding.remediation && (
                          <div className="mt-4">
                            <h4 className="font-medium mb-2">Remediation</h4>
                            <p className="text-sm">{finding.remediation}</p>
                          </div>
                        )}
                        {finding.affected_url && (
                          <div className="mt-2 text-sm">
                            <span className="font-medium">Affected URL:</span>{" "}
                            <a
                              href={finding.affected_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-primary hover:underline"
                            >
                              {finding.affected_url}
                            </a>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      ))}
    </div>
  );
};

export default ScanReport; 