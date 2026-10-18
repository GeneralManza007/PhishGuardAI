'use client';

import { Card, CardContent } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';

interface IOCListProps {
  iocs: Record<string, string[]>;
}

const IOC_TYPES: Record<string, { label: string; color: string }> = {
  ips: { label: 'IP Addresses', color: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300' },
  emails: { label: 'Email Addresses', color: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300' },
  phones: { label: 'Phone Numbers', color: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300' },
  bitcoin: { label: 'Bitcoin Addresses', color: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300' },
  hashes: { label: 'File Hashes', color: 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300' },
  domains: { label: 'Domains', color: 'bg-indigo-100 text-indigo-800 dark:bg-indigo-900/30 dark:text-indigo-300' },
  urls: { label: 'URLs', color: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300' },
  attachments: { label: 'Attachments', color: 'bg-pink-100 text-pink-800 dark:bg-pink-900/30 dark:text-pink-300' },
};

export function IOCList({ iocs }: IOCListProps) {
  if (!iocs || Object.keys(iocs).length === 0) {
    return null;
  }

  // Filter out empty arrays
  const hasIocs = Object.values(iocs).some(arr => arr && arr.length > 0);
  if (!hasIocs) return null;

  return (
    <Card>
      <CardContent className="pt-6">
        <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3 flex items-center gap-2">
          <span>🔍 Indicators of Compromise (IOCs)</span>
          <span className="text-xs text-gray-500">(Extracted from email)</span>
        </h4>
        <div className="space-y-3">
          {Object.entries(iocs).map(([type, values]) => {
            if (!values || values.length === 0) return null;
            const info = IOC_TYPES[type];
            if (!info) return null;
            
            const variantMap: Record<string, 'danger' | 'primary' | 'success' | 'warning' | 'info' | 'purple' | 'orange' | 'pink'> = {
            ips: 'danger',
            emails: 'primary',
            phones: 'success',
            bitcoin: 'warning',
            hashes: 'purple',
            domains: 'info',
            urls: 'orange',
            attachments: 'pink',
            };

            return (
              <div key={type}>
                <div className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">
                  {info.label} ({values.length})
                </div>
                <div className="flex flex-wrap gap-1">
                  {values.slice(0, 10).map((value, idx) => (
                    <Badge key={idx} variant={variantMap[type]} className="font-mono">
                    {value}
                    </Badge>
                  ))} 
                  {values.length > 10 && (
                    <span className="text-xs text-gray-500">+{values.length - 10} more</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}