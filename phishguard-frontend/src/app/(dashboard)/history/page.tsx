'use client';

import { useEffect, useState, useMemo } from 'react';
import { Card, CardContent } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input'; // Create this if you don't have it
import { getHistory, type HistoryItem } from '@/services/history';
import { format } from 'date-fns';
import { getAuthHeaders } from '@/services/history';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const riskColorMap = {
  Critical: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
  High: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400',
  Medium: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
  Low: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
};

export default function HistoryPage() {
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState<number | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    getHistory()
      .then(setHistory)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const downloadReport = async (id: number) => {
  setDownloading(id);
  try {
    // --- Get the token from localStorage ---
    const token = localStorage.getItem('token');
    const headers: HeadersInit = {
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    };

    const response = await fetch(`${API_BASE_URL}/report/${id}`, {
      method: 'GET',
      headers: headers,
    });

    // --- Handle 401 Unauthorized ---
    if (response.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/login';
      throw new Error('Session expired. Please log in again.');
    }

    if (!response.ok) throw new Error('Failed to download report');

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard_report_${id}.pdf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  } catch (error) {
    console.error('Download failed:', error);
    alert('Failed to download the report. Please try again.');
  } finally {
    setDownloading(null);
  }
};

  // Filter history based on search term
  const filteredHistory = useMemo(() => {
    if (!searchTerm.trim()) return history;
    const query = searchTerm.toLowerCase().trim();
    return history.filter(item => {
      // Search in email content
      if (item.email_content?.toLowerCase().includes(query)) return true;
      // Search in findings
      if (item.findings.some(f => 
        f.category.toLowerCase().includes(query) || 
        f.description.toLowerCase().includes(query)
      )) return true;
      // Search in risk level
      if (item.riskLevel.toLowerCase().includes(query)) return true;
      return false;
    });
  }, [history, searchTerm]);

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="text-gray-500 dark:text-gray-400">Loading history...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100">Analysis History</h1>
        <div className="w-64">
          <Input
            placeholder="Search emails, findings..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="dark:bg-gray-800 dark:border-gray-700 dark:text-gray-100"
          />
        </div>
      </div>
      
      {filteredHistory.length === 0 ? (
        <div className="flex h-64 items-center justify-center">
          <div className="text-gray-500 dark:text-gray-400">
            {searchTerm ? 'No analyses match your search.' : 'No analyses found. Start analyzing emails!'}
          </div>
        </div>
      ) : (
        <Card>
          <CardContent className="pt-6">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-gray-700 text-left">
                    <th className="pb-3 font-medium text-gray-700 dark:text-gray-300">Date</th>
                    <th className="pb-3 font-medium text-gray-700 dark:text-gray-300">Risk Score</th>
                    <th className="pb-3 font-medium text-gray-700 dark:text-gray-300">Risk Level</th>
                    <th className="pb-3 font-medium text-gray-700 dark:text-gray-300">Findings</th>
                    <th className="pb-3 font-medium text-gray-700 dark:text-gray-300">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredHistory.map((item) => (
                    <tr key={item.id} className="border-b border-gray-100 dark:border-gray-800">
                      <td className="py-3 text-gray-600 dark:text-gray-400">
                        {format(new Date(item.created_at), 'MMM d, yyyy HH:mm')}
                      </td>
                      <td className="py-3 font-bold text-gray-900 dark:text-gray-100">{item.riskScore}%</td>
                      <td className="py-3">
                        <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${riskColorMap[item.riskLevel as keyof typeof riskColorMap]}`}>
                          {item.riskLevel}
                        </span>
                      </td>
                      <td className="py-3">
                        <div className="flex flex-wrap gap-1">
                          {item.findings.slice(0, 3).map((f, idx) => (
                            <span key={idx} className="rounded bg-gray-100 dark:bg-gray-700 px-2 py-0.5 text-xs text-gray-600 dark:text-gray-300">
                              {f.category}
                            </span>
                          ))}
                          {item.findings.length > 3 && (
                            <span className="rounded bg-gray-100 dark:bg-gray-700 px-2 py-0.5 text-xs text-gray-400 dark:text-gray-500">
                              +{item.findings.length - 3} more
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-3">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => downloadReport(item.id)}
                          disabled={downloading === item.id}
                          className="dark:border-gray-600 dark:text-gray-300 dark:hover:bg-gray-700"
                        >
                          {downloading === item.id ? '...' : '📄 PDF'}
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {searchTerm && (
                <div className="mt-4 text-sm text-gray-500 dark:text-gray-400">
                  Showing {filteredHistory.length} of {history.length} analyses
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}