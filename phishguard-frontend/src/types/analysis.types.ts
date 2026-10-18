export interface Finding {
  category: string;
  severity: string;
  description: string;
  evidence?: Record<string, any> | null;
  confidence?: number | null;
  mitre_technique?: string | null;
  mitre_tactic?: string | null;
  mitre_url?: string | null;
  module?: string | null;
  type?: "technique" | "evidence" | null;
}

export interface HighlightedSnippet {
  text: string;
  startIndex: number;
  endIndex: number;
  severity: string;
  category: string;
  description: string;
}

export interface AnalysisResponse {
  riskScore: number;
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  findings: Finding[];
  highlightedSnippets: HighlightedSnippet[];
  iocs?: Record<string, string[]>; 
}