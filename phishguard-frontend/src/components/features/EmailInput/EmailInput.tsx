'use client';

import { useState } from 'react';
import { Textarea } from '@/components/ui/Textarea';

export function EmailInput({
  value,
  onChange,
}: {
  value: string;
  onChange: (v: string) => void;
}) {
  const [isDragging, setIsDragging] = useState(false);

  const handleDrop = async (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    
    const files = e.dataTransfer.files;
    if (files.length === 0) return;
    
    const file = files[0];
    // Check if it's an .eml file (or text-based)
    if (file.name.endsWith('.eml') || file.type === 'message/rfc822') {
      const content = await file.text();
      onChange(content);
    } else {
      alert('Please drop a valid .eml file.');
    }
  };

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
  };

  return (
    <div className="space-y-2">
      <label htmlFor="email-input" className="text-sm font-medium text-gray-700 dark:text-gray-300">
        Email Content
      </label>
      
      {/* Drag-and-drop zone */}
      <div
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        className={`relative rounded-lg border-2 border-dashed p-2 transition-colors ${
          isDragging
            ? 'border-blue-500 bg-blue-50 dark:border-blue-400 dark:bg-blue-900/20'
            : 'border-gray-300 dark:border-gray-600'
        }`}
      >
        <Textarea
          id="email-input"
          rows={12}
          placeholder="Paste the full email header and body here, or drag-and-drop an .eml file..."
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="min-h-[200px] font-mono text-sm text-gray-900 dark:text-gray-100 dark:bg-gray-800"
        />
        <div className="absolute bottom-2 right-2 text-xs text-gray-400 dark:text-gray-500">
          Drop .eml or paste
        </div>
      </div>
    </div>
  );
}