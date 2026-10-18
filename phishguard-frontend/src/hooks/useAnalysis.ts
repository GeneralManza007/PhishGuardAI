import { useState } from 'react';
import { analyzeEmail, type AnalysisResponse } from '@/services/api';

export function useAnalysis() {
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const analyze = async (email: string) => {
    setIsLoading(true);
    setError(null);
    
    try {
      const data = await analyzeEmail(email);
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
      setResult(null);
    } finally {
      setIsLoading(false);
    }
  };

  return { analyze, result, isLoading, error };
}