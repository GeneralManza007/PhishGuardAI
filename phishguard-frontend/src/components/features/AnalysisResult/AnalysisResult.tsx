// src/components/features/AnalysisResult/AnalysisResult.tsx
'use client';

import { Card, CardContent } from '@/components/ui/Card';
import { HighlightedEmail } from './HighlightedEmail';
import { type AnalysisResponse } from '@/types/analysis.types';
import { IOCList } from './IOCList';

const riskColorMap = {
  Critical: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
  High: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400',
  Medium: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
  Low: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
  Info: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300',
};

export function AnalysisResult({ 
  result, 
  email 
}: { 
  result: AnalysisResponse; 
  email?: string;
}) {
  console.log('🔍 Full result:', result);
  console.log('🔍 Findings array:', result.findings);
  const { riskScore, riskLevel, findings, highlightedSnippets = [] } = result;

  // Filter out "URL Summary" if you want, or keep it
  // If you want to hide Info findings, filter them here
  const displayedFindings = findings; // Show all findings
  const techniques = findings.filter(f => f.type === "technique");
  const evidence = findings.filter(f => f.type !== "technique" || f.type === null);

  function getSeverityColor(severity: string): string {
  if (severity === 'Critical') return 'bg-red-500';
  if (severity === 'High') return 'bg-orange-500';
  if (severity === 'Medium') return 'bg-yellow-500';
  if (severity === 'Low') return 'bg-blue-500';
  return 'bg-gray-400';
}

return (
<div className="space-y-6">
  <Card>
    <CardContent className="space-y-4 pt-6">
      {/* Risk score header */}

      {techniques.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 flex items-center gap-2">
            <span>🎯 Attack Techniques (MITRE)</span>
            <span className="text-xs text-gray-500">(Tactics mapped to MITRE ATT&CK)</span>
          </h4>
          <ul className="space-y-1">
            {techniques.map((finding, idx) => (
              <li key={idx} className="flex items-start gap-2 rounded-md bg-gray-50 px-3 py-2 text-sm dark:bg-gray-800">
                {/* Severity dot */}
                <span className={`mt-0.5 h-2 w-2 rounded-full ${getSeverityColor(finding.severity)}`} />
                <span>
                  <span className="font-medium">{finding.category}:</span>{' '}
                  <span>{finding.description}</span>
                  <span className="ml-2 inline-flex items-center gap-1">
                    <span className="text-xs font-mono bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300 px-1.5 py-0.5 rounded">
                      {finding.mitre_technique}
                    </span>
                    {finding.mitre_tactic && finding.mitre_tactic !== "Unknown" && (
                      <span className="text-xs text-gray-500 dark:text-gray-400">
                        ({finding.mitre_tactic})
                      </span>
                    )}
                    <a href={finding.mitre_url || '#'} target="_blank" rel="noopener noreferrer" className="text-xs text-blue-600 hover:underline dark:text-blue-400" title="View MITRE ATT&CK technique">
                      📖
                    </a>
                  </span>
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {evidence.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 flex items-center gap-2">
            <span>🔍 Supporting Evidence</span>
            <span className="text-xs text-gray-500">(IOCs, authentication issues, domain intelligence)</span>
          </h4>
          <ul className="space-y-1">
            {evidence.map((finding, idx) => (
              <li key={idx} className="flex items-start gap-2 rounded-md bg-gray-50 px-3 py-2 text-sm dark:bg-gray-800">
                <span className={`mt-0.5 h-2 w-2 rounded-full ${getSeverityColor(finding.severity)}`} />
                <span>
                  <span className="font-medium">{finding.category}:</span>{' '}
                  <span>{finding.description}</span>
                  {finding.confidence && (
                    <span className="ml-2 text-xs text-gray-500 dark:text-gray-400">
                      (confidence: {finding.confidence}%)
                    </span>
                  )}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {result.iocs && <IOCList iocs={result.iocs} />}
    </CardContent>
  </Card>
</div>
);
}