'use client';

import { useState } from 'react';
import { Card, CardContent } from '@/components/ui/Card';

interface HighlightedSnippet {
  text: string;
  startIndex: number;
  endIndex: number;
  severity: string;
  category: string;
  description: string;
}

const severityColors: Record<string, { bg: string; border: string; text: string }> = {
  Critical: { 
    bg: 'bg-red-100 dark:bg-red-900/30', 
    border: 'border-red-500 dark:border-red-400', 
    text: 'text-red-800 dark:text-red-400' 
  },
  High: { 
    bg: 'bg-orange-100 dark:bg-orange-900/30', 
    border: 'border-orange-500 dark:border-orange-400', 
    text: 'text-orange-800 dark:text-orange-400' 
  },
  Medium: { 
    bg: 'bg-yellow-100 dark:bg-yellow-900/30', 
    border: 'border-yellow-500 dark:border-yellow-400', 
    text: 'text-yellow-800 dark:text-yellow-400' 
  },
  Low: { 
    bg: 'bg-blue-100 dark:bg-blue-900/30', 
    border: 'border-blue-500 dark:border-blue-400', 
    text: 'text-blue-800 dark:text-blue-400' 
  },
};

const severityOrder = { Critical: 4, High: 3, Medium: 2, Low: 1 };

export function HighlightedEmail({
  email,
  highlights,
}: {
  email: string;
  highlights: HighlightedSnippet[];
}) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  if (!email || highlights.length === 0) {
    return (
      <div className="rounded-md border border-gray-200 bg-gray-50 p-4 text-gray-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-400">
        No suspicious text to highlight.
      </div>
    );
  }

  const validHighlights = highlights.filter(
    h => h.startIndex >= 0 && h.endIndex <= email.length && h.startIndex < h.endIndex
  );

  if (validHighlights.length === 0) {
    return (
      <div className="rounded-md border border-gray-200 bg-gray-50 p-4 text-gray-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-400">
        No valid highlights found.
      </div>
    );
  }

  const sortedHighlights = [...validHighlights].sort((a, b) => a.startIndex - b.startIndex);
  const mergedHighlights: HighlightedSnippet[] = [];

  for (const current of sortedHighlights) {
    if (mergedHighlights.length === 0) {
      mergedHighlights.push({ ...current });
      continue;
    }

    const last = mergedHighlights[mergedHighlights.length - 1];

    if (current.startIndex <= last.endIndex) {
      const newEnd = Math.max(last.endIndex, current.endIndex);
      const currentSeverity = severityOrder[current.severity as keyof typeof severityOrder] || 0;
      const lastSeverity = severityOrder[last.severity as keyof typeof severityOrder] || 0;
      const highestSeverity = currentSeverity > lastSeverity ? current.severity : last.severity;
      
      mergedHighlights[mergedHighlights.length - 1] = {
        ...last,
        endIndex: newEnd,
        severity: highestSeverity,
        description: `${last.description} | ${current.description}`,
        category: `${last.category} / ${current.category}`,
        text: email.substring(last.startIndex, newEnd),
      };
    } else {
      mergedHighlights.push({ ...current });
    }
  }

  const parts: { text: string; highlight?: HighlightedSnippet; id: number }[] = [];
  let lastEnd = 0;

  for (let i = 0; i < mergedHighlights.length; i++) {
    const highlight = mergedHighlights[i];
    
    if (highlight.startIndex > lastEnd) {
      parts.push({
        text: email.substring(lastEnd, highlight.startIndex),
        id: -1,
      });
    }

    const highlightedText = email.substring(highlight.startIndex, highlight.endIndex);
    if (highlightedText.trim()) {
      parts.push({
        text: highlightedText,
        highlight: highlight,
        id: i,
      });
    }

    lastEnd = highlight.endIndex;
  }

  if (lastEnd < email.length) {
    parts.push({
      text: email.substring(lastEnd),
      id: -1,
    });
  }

  return (
    <Card>
      <CardContent className="pt-6">
        <div className="mb-4 flex flex-wrap gap-2">
          <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Legend:</span>
          {Object.entries(severityColors).map(([severity, colors]) => (
            <span key={severity} className={`rounded px-2 py-0.5 text-xs font-medium ${colors.bg} ${colors.text}`}>
              {severity}
            </span>
          ))}
        </div>
        <div className="rounded-md border border-gray-200 bg-white p-4 font-mono text-sm leading-relaxed text-gray-900 whitespace-pre-wrap dark:border-gray-700 dark:bg-gray-900 dark:text-gray-100">
          {parts.map((part, idx) => {
            if (part.highlight) {
              const isHovered = hoveredIndex === part.id;
              const colors = severityColors[part.highlight.severity] || severityColors.Low;
              return (
                <span
                  key={idx}
                  className={`cursor-pointer border-b-2 px-0.5 transition-all ${colors.bg} ${colors.border} ${colors.text} ${
                    isHovered ? 'ring-2 ring-blue-500 shadow-lg dark:ring-blue-400' : ''
                  }`}
                  onMouseEnter={() => setHoveredIndex(part.id)}
                  onMouseLeave={() => setHoveredIndex(null)}
                  title={`${part.highlight.category}: ${part.highlight.description}`}
                >
                  {part.text}
                </span>
              );
            }
            return <span key={idx}>{part.text}</span>;
          })}
        </div>
      </CardContent>
    </Card>
  );
}