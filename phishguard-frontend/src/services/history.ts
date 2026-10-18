const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export interface HistoryItem {
  email_content: any;
  id: number;
  riskScore: number;
  riskLevel: string;
  findings: Array<{ category: string; severity: string; description: string }>;
  created_at: string;
}

export interface DashboardStats {
  total_analyses: number;
  average_risk_score: number;
  risk_distribution: Record<string, number>;
  top_brands: Array<{ brand: string; count: number }>;
  top_attack_types: Array<{ type: string; count: number }>;
  today_count: number;
  this_week_count: number;
  recent_attacks: Array<{
    id: number;
    risk_score: number;
    risk_level: string;
    created_at: string;
    brand_impersonated: string | null;
    attack_type: string | null;
    findings_count: number;
  }>;
  trend_over_time: Array<{ date: string; count: number; avg_risk: number }>;  // avg_risk added
  mitre_coverage: Array<{ tactic: string; count: number }>;
}

export function getAuthHeaders(): HeadersInit {
  const token = localStorage.getItem('token');
  return {
    'Content-Type': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
  };
}


export async function getHistory(): Promise<HistoryItem[]> {
  const response = await fetch(`${API_BASE_URL}/history`, {
    method: 'GET',
    headers: getAuthHeaders(),
  });
    if (response.status === 401) {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        window.location.href = '/login';
        throw new Error('Session expired. Please log in again.');
    }

  if (!response.ok) throw new Error('Failed to fetch history');
  return response.json();
}

export async function getDashboardStats(): Promise<DashboardStats> {
  const response = await fetch(`${API_BASE_URL}/dashboard/stats`, {
    method: 'GET', 
    headers: getAuthHeaders(),
  });

      if (response.status === 401) {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        window.location.href = '/login';
        throw new Error('Session expired. Please log in again.');
    }

  if (!response.ok) throw new Error('Failed to fetch dashboard stats');
  return response.json();
}