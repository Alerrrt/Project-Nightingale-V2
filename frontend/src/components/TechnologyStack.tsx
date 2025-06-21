import React from 'react';

interface TechnologyFinding {
  technology?: string;
  cve?: string;
  title: string;
  description: string;
  references?: string[];
  severity?: string;
  category?: string;
}

interface Props {
  vulnerabilities: TechnologyFinding[];
}

const TechnologyStack: React.FC<Props> = ({ vulnerabilities }) => {
  // Filter for findings with a technology field
  const techFindings = vulnerabilities.filter(v => v.technology);
  // Group by technology
  const grouped: Record<string, TechnologyFinding[]> = {};
  techFindings.forEach(finding => {
    if (!finding.technology) return;
    if (!grouped[finding.technology]) grouped[finding.technology] = [];
    grouped[finding.technology].push(finding);
  });

  return (
    <div className="bg-[#181f2a] rounded-2xl p-8 mb-4 shadow-lg">
      <h2 className="text-2xl font-bold text-white mb-4 flex items-center">
        <span className="h-5 w-5 mr-2 bg-cyan-400 rounded-full inline-block" />
        Technology Stack & Vulnerabilities
      </h2>
      {Object.keys(grouped).length === 0 ? (
        <div className="text-gray-400">No technologies detected for this scan.</div>
      ) : (
        <div className="space-y-6">
          {Object.entries(grouped).map(([tech, findings]) => (
            <div key={tech} className="bg-gray-900 rounded-xl p-6 border border-gray-800 shadow-md">
              <div className="flex items-center mb-2">
                <span className="h-3 w-3 bg-cyan-400 rounded-full mr-2" />
                <span className="font-semibold text-lg text-white truncate">{tech}</span>
              </div>
              <ul className="list-disc ml-6">
                {findings.map((finding, idx) => (
                  <li key={idx} className="mb-2">
                    <div className="text-gray-200 font-medium">
                      {finding.cve ? (
                        <>
                          <span className="text-cyan-400">CVE:</span>{' '}
                          <a
                            href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${finding.cve}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-cyan-400 underline"
                          >
                            {finding.cve}
                          </a>
                        </>
                      ) : (
                        <span className="text-gray-400">No known CVEs</span>
                      )}
                    </div>
                    <div className="text-gray-400 text-sm mb-1">{finding.title}</div>
                    <div className="text-gray-400 text-xs mb-1">{finding.description}</div>
                    {finding.references && finding.references.length > 0 && (
                      <div className="text-xs text-gray-400">
                        <span className="font-semibold">References:</span>{' '}
                        {finding.references.map((ref, i) => (
                          <a
                            key={i}
                            href={ref}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-cyan-400 underline mr-2"
                          >
                            [link]
                          </a>
                        ))}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default TechnologyStack; 