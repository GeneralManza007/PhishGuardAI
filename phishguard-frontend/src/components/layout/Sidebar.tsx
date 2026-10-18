'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

const navItems = [
  { name: 'Analyzer', href: '/' },
  { name: 'Dashboard', href: '/dashboard' },
  { name: 'History', href: '/history' },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="hidden w-64 flex-col border-r border-gray-200 bg-white dark:border-gray-700 dark:bg-gray-900 md:flex">
      <div className="flex h-16 items-center border-b border-gray-200 px-6 dark:border-gray-700">
        <span className="text-xl font-bold text-blue-600 dark:text-blue-500">PhishGuard</span>
      </div>
      <nav className="flex-1 space-y-1 px-4 py-6">
        {navItems.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            className={`flex items-center rounded-md px-4 py-2 text-sm font-medium transition-colors ${
              pathname === item.href
                ? 'bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400'
                : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900 dark:text-gray-400 dark:hover:bg-gray-800 dark:hover:text-gray-100'
            }`}
          >
            {item.name}
          </Link>
        ))}
      </nav>
    </aside>
  );
}