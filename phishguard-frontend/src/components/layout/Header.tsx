'use client';

import { useAuth } from '@/context/AuthContext';
import { ThemeToggle } from '../ui/ThemeToggle';
import { Button } from '../ui/Button';
import { Shield, LogOut, User } from 'lucide-react';

export function Header() {
  const { user, logout } = useAuth();

  // Get user initials for avatar
  const initials = user ? user.charAt(0).toUpperCase() : '?';

  return (
    <header className="sticky top-0 z-50 flex h-16 items-center border-b border-gray-200/70 bg-white/80 backdrop-blur-sm px-6 dark:border-gray-700/50 dark:bg-gray-900/80">
      <div className="flex flex-1 items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600 text-white shadow-sm">
            <Shield className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-gray-900 dark:text-white">
              PhishGuard
            </h1>
            <p className="hidden text-xs text-gray-500 dark:text-gray-400 sm:block">
              AI-powered email security
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 rounded-full bg-gray-100 px-3 py-1.5 dark:bg-gray-800">
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
              {user}
            </span>
            <div className="flex h-6 w-6 items-center justify-center rounded-full bg-blue-100 text-xs font-bold text-blue-700 dark:bg-blue-900/40 dark:text-blue-300">
              {initials}
            </div>
          </div>

          <Button
            variant="ghost"
            size="sm"
            onClick={logout}
            className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
          >
            <LogOut className="mr-1.5 h-4 w-4" />
            Logout
          </Button>

          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}