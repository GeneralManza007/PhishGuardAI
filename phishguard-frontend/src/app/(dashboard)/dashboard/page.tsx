'use client';

import { useEffect, useState } from 'react';
import { Card, CardContent } from '@/components/ui/Card';
import { getDashboardStats, type DashboardStats } from '@/services/history';
import { format } from 'date-fns';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
  PieChart,
  Pie,
} from 'recharts';

// ----------------------------------------------------------------------
//  Helpers
// ----------------------------------------------------------------------

// Format attack type labels: "data_harvesting" → "Data Harvesting"
const formatAttackType = (type: string) => {
  const map: Record<string, string> = {
    credential_harvesting: 'Credential Harvesting',
    data_harvesting: 'Data Harvesting',
    financial_scam: 'Financial Scam',
    urgency_manipulation: 'Urgency Manipulation',
  };
  return map[type] || type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
};

// Format brand names: "paypal" → "PayPal"
const formatBrand = (brand: string) => {
  const map: Record<string, string> = {
    paypal: 'PayPal',
    microsoft: 'Microsoft',
    google: 'Google',
    amazon: 'Amazon',
    apple: 'Apple',
    facebook: 'Facebook',
    linkedin: 'LinkedIn',
  };
  return map[brand] || brand.charAt(0).toUpperCase() + brand.slice(1);
};

// Risk level pill colors
const riskLevelPill = (level: string) => {
  const colors = {
    Critical: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
    High: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
    Medium: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
    Low: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
  };
  return colors[level as keyof typeof colors] || 'bg-gray-100 text-gray-800';
};

// Chart colors
const COLORS = {
  Critical: '#EF4444',
  High: '#F97316',
  Medium: '#EAB308',
  Low: '#3B82F6',
};

// ----------------------------------------------------------------------
//  Stat Card Component
// ----------------------------------------------------------------------
const StatCard = ({ title, value, icon }: { title: string; value: number | string; icon: string }) => (
  <Card className="border-0 shadow-sm">
    <CardContent className="pt-6">
      <div className="flex items-center gap-2 text-sm font-medium text-gray-500 dark:text-gray-400">
        <span className="text-lg">{icon}</span>
        {title}
      </div>
      <div className="mt-1 text-3xl font-bold tracking-tight text-gray-900 dark:text-gray-100">
        {value}
      </div>
    </CardContent>
  </Card>
);

// ----------------------------------------------------------------------
//  Main Dashboard Page
// ----------------------------------------------------------------------
export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getDashboardStats()
      .then(setStats)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="text-gray-500 dark:text-gray-400">Loading dashboard…</div>
      </div>
    );
  }

  if (!stats || stats.total_analyses === 0) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="text-gray-500 dark:text-gray-400">
          No analyses yet. Run some emails through the analyzer!
        </div>
      </div>
    );
  }

  // Risk distribution pie chart
  const pieData = Object.entries(stats.risk_distribution)
    .filter(([_, value]) => value > 0)
    .map(([name, value]) => ({ name, value }));

  // Trend chart – average risk per day
  const trendData = (stats.trend_over_time || []).map(d => ({
    date: format(new Date(d.date), 'MMM d'),
    avg_risk: d.avg_risk || 0,
    count: d.count || 0,
  }));

  console.log('📊 trendData:', trendData);

  // Top attack types – format labels
  const attackData = stats.top_attack_types.map(a => ({
    name: formatAttackType(a.type),
    count: a.count,
  }));

  // Top brands – format labels
  const brandData = stats.top_brands.map(b => ({
    name: formatBrand(b.brand),
    count: b.count,
  }));

  // MITRE coverage
  const mitreData = stats.mitre_coverage || [];

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold tracking-tight text-gray-900 dark:text-gray-100">
        Dashboard
      </h1>

      {/* Stat Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <StatCard title="Today's Emails" value={stats.today_count} icon="📬" />
        <StatCard title="This Week" value={stats.this_week_count} icon="📆" />
        <StatCard title="Total Analyzed" value={stats.total_analyses} icon="📊" />
        <StatCard title="Avg Risk Score" value={`${stats.average_risk_score}%`} icon="🎯" />
      </div>

      {/* Charts Row */}
      <div className="grid gap-4 md:grid-cols-2">
        {/* Trend Chart – Average Risk Score */}
        <Card className="border-0 shadow-sm">
          <CardContent className="pt-6">
            <h3 className="mb-4 text-sm font-medium text-gray-700 dark:text-gray-300 flex items-center gap-2">
              <span className="text-lg">📈</span> Risk Trend (30 Days)
            </h3>
                {trendData.length > 0 ? (
                <ResponsiveContainer width="100%" height={220}>
                    <LineChart data={trendData}>
                    <XAxis
                        dataKey="date"
                        stroke="#888"
                        fontSize={11}
                        tickLine={false}
                        axisLine={false}
                    />
                    <YAxis
                        stroke="#888"
                        fontSize={11}
                        tickLine={false}
                        axisLine={false}
                        domain={[0, 100]}
                        tickFormatter={(value) => `${value}%`}
                    />
                    <Tooltip
                        content={({ active, payload, label }) => {
                        if (active && payload && payload.length) {
                            return (
                            <div
                                style={{
                                backgroundColor: 'var(--background)',
                                border: '1px solid var(--border)',
                                borderRadius: '8px',
                                padding: '8px 12px',
                                fontSize: '12px',
                                boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
                                }}
                            >
                                <p style={{ margin: 0, fontWeight: 600 }}>{`Date: ${label}`}</p>
                                <p style={{ margin: 0, color: '#EF4444' }}>
                                {`Avg Risk: ${payload[0]?.value ?? 0}%`}
                                </p>
                            </div>
                            );
                        }
                        return null;
                        }}
                    />
                    <Line
                        type="monotone"
                        dataKey="avg_risk"
                        stroke="#EF4444"
                        strokeWidth={2.5}
                        dot={false}
                        activeDot={{ r: 6 }}
                    />
                    </LineChart>
                </ResponsiveContainer>
                ) : (
                <div className="flex h-[220px] items-center justify-center text-gray-400">
                    No trend data available yet
                </div>
                )}
                        </CardContent>
        </Card>

        {/* Risk Distribution Pie */}
        <Card className="border-0 shadow-sm">
          <CardContent className="pt-6">
            <h3 className="mb-4 text-sm font-medium text-gray-700 dark:text-gray-300">
              Risk Distribution
            </h3>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name} (${((percent || 0) * 100).toFixed(0)}%)`}
                  outerRadius={80}
                  dataKey="value"
                >
                  {pieData.map((entry) => (
                    <Cell
                      key={entry.name}
                      fill={COLORS[entry.name as keyof typeof COLORS] || '#8884d8'}
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'var(--background)',
                    border: '1px solid var(--border)',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Top Attacks & Brands */}
      <div className="grid gap-4 md:grid-cols-2">
        {attackData.length > 0 && (
          <Card className="border-0 shadow-sm">
            <CardContent className="pt-6">
              <h3 className="mb-4 text-sm font-medium text-gray-700 dark:text-gray-300 flex items-center gap-2">
                <span className="text-lg">🎯</span> Top Attack Types
              </h3>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={attackData} layout="vertical" margin={{ left: 10, right: 20 }}>
                    <XAxis type="number" tickLine={false} axisLine={false} />
                    <YAxis
                        type="category"
                        dataKey="name"
                        width={140}
                        fontSize={12}
                        tickLine={false}
                        axisLine={false}
                        tick={{ fill: 'var(--foreground)' }}
                        tickFormatter={(value) => {
                        return value.length > 18 ? value.slice(0, 16) + '…' : value;
                        }}
                    />
                    <Tooltip
                        contentStyle={{
                        backgroundColor: 'var(--background)',
                        border: '1px solid var(--border)',
                        borderRadius: '8px',
                        fontSize: '12px',
                        }}
                    />
                    <Bar dataKey="count" fill="#F97316" radius={[0, 4, 4, 0]} />
                    </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        )}

        {brandData.length > 0 && (
          <Card className="border-0 shadow-sm">
            <CardContent className="pt-6">
              <h3 className="mb-4 text-sm font-medium text-gray-700 dark:text-gray-300 flex items-center gap-2">
                <span className="text-lg">🏢</span> Top Impersonated Brands
              </h3>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={brandData} layout="vertical" margin={{ left: 10, right: 20 }}>
                    <XAxis type="number" tickLine={false} axisLine={false} />
                    <YAxis
                        type="category"
                        dataKey="name"
                        width={140}
                        fontSize={12}
                        tickLine={false}
                        axisLine={false}
                        tick={{ fill: 'var(--foreground)' }}
                        tickFormatter={(value) => {
                        return value.length > 18 ? value.slice(0, 16) + '…' : value;
                        }}
                    />
                    <Tooltip
                        contentStyle={{
                        backgroundColor: 'var(--background)',
                        border: '1px solid var(--border)',
                        borderRadius: '8px',
                        fontSize: '12px',
                        }}
                    />
                    <Bar dataKey="count" fill="#3B82F6" radius={[0, 4, 4, 0]} />
                    </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        )}
      </div>

      {/* MITRE Coverage */}
      {mitreData.length > 0 && (
        <Card className="border-0 shadow-sm">
          <CardContent className="pt-6">
            <h3 className="mb-4 text-sm font-medium text-gray-700 dark:text-gray-300 flex items-center gap-2">
              <span className="text-lg">🛡</span> MITRE ATT&CK Coverage
            </h3>
            <div className="space-y-2">
              {mitreData.map((item) => (
                <div key={item.tactic} className="flex items-center gap-2">
                  <span className="w-48 text-sm text-gray-700 dark:text-gray-300">
                    {item.tactic}
                  </span>
                  <div className="flex-1 h-3 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-blue-500 dark:bg-blue-400 rounded-full transition-all duration-500"
                      style={{
                        width: `${Math.min((item.count / stats.total_analyses) * 100, 100)}%`,
                      }}
                    />
                  </div>
                  <span className="text-sm font-mono text-gray-600 dark:text-gray-400 w-10 text-right">
                    {item.count}
                  </span>
                </div>
              ))}
            </div>
            <div className="mt-2 text-xs text-gray-400">Occurrences across all analyses</div>
          </CardContent>
        </Card>
      )}

      {/* Recent Attacks Table */}
      <Card className="border-0 shadow-sm">
        <CardContent className="pt-6">
          <h3 className="mb-4 text-sm font-medium text-gray-700 dark:text-gray-300">Recent Attacks</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-700 text-left">
                  <th className="pb-2 font-medium text-gray-600 dark:text-gray-400">Time</th>
                  <th className="pb-2 font-medium text-gray-600 dark:text-gray-400">Risk Score</th>
                  <th className="pb-2 font-medium text-gray-600 dark:text-gray-400">Level</th>
                  <th className="pb-2 font-medium text-gray-600 dark:text-gray-400">Brand</th>
                  <th className="pb-2 font-medium text-gray-600 dark:text-gray-400">Attack Type</th>
                </tr>
              </thead>
              <tbody>
                {stats.recent_attacks.map((attack) => (
                  <tr key={attack.id} className="border-b border-gray-100 dark:border-gray-800">
                    <td className="py-2 text-gray-600 dark:text-gray-400">
                      {format(new Date(attack.created_at), 'MMM d, HH:mm')}
                    </td>
                    <td className="py-2 font-bold text-gray-900 dark:text-gray-100">
                      {attack.risk_score}%
                    </td>
                    <td className="py-2">
                      <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${riskLevelPill(attack.risk_level)}`}>
                        {attack.risk_level}
                      </span>
                    </td>
                    <td className="py-2 text-gray-700 dark:text-gray-300">
                      {attack.brand_impersonated ? formatBrand(attack.brand_impersonated) : '—'}
                    </td>
                    <td className="py-2 text-gray-700 dark:text-gray-300">
                      {attack.attack_type ? formatAttackType(attack.attack_type) : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}