'use client';

import { useState } from 'react';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { EmailInput } from '@/components/features/EmailInput/EmailInput';
import { AnalysisResult } from '@/components/features/AnalysisResult/AnalysisResult';
import { useAnalysis } from '@/hooks/useAnalysis';
import { Shield, Zap, Mail, Loader2 } from 'lucide-react';

// Sample phishing email for quick demo
const SAMPLE_EMAIL = `From: security@paypal-secure-verify.xyz
Reply-To: scammer@phishing-site.xyz
To: victim@gmail.com
Subject: URGENT: Your PayPal Account Has Been Limited

Dear valued customer,

We noticed unusual activity on your PayPal account.
To prevent suspension, please confirm your identity within 24 hours.

Click here to verify: http://paypal-secure-verify.xyz/confirm

If you don't confirm within 24 hours, your account will be permanently suspended.

- PayPal Security Team
+1-800-555-0199
support@paypal-security.xyz`;

export default function HomePage() {
  const [emailContent, setEmailContent] = useState('');
  const { analyze, result, isLoading } = useAnalysis();

  const handleAnalyze = () => {
    if (emailContent.trim()) {
      analyze(emailContent);
    }
  };

  const loadSample = () => {
    setEmailContent(SAMPLE_EMAIL);
  };

  return (
    <div className="mx-auto max-w-5xl space-y-8">
      {/* Hero Section */}
      <div className="space-y-3">
        <div className="flex items-center gap-3">
          <div className="rounded-xl bg-gradient-to-br from-blue-600 to-blue-400 p-2.5 text-white shadow-lg">
            <Shield className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-gray-900 dark:text-white">
              PhishGuard
            </h1>
            <p className="text-gray-500 dark:text-gray-400">
              Paste an email to analyse for phishing indicators.
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3 rounded-lg bg-blue-50/50 px-4 py-2 text-sm text-blue-800 dark:bg-blue-900/20 dark:text-blue-200">
          <Zap className="h-4 w-4" />
          <span>AI-powered detection • </span>
          <span className="font-medium">100% client-side privacy</span>
          <span className="hidden sm:inline">• No email stored</span>
        </div>
      </div>

      {/* Input Card */}
      <Card className="overflow-hidden border-0 shadow-lg dark:border dark:border-gray-800">
        <div className="border-l-4 border-blue-600 px-6 pt-6">
          <h2 className="text-sm font-medium text-gray-700 dark:text-gray-300">
            <Mail className="mr-2 inline h-4 w-4" />
            Email Content
          </h2>
        </div>
        <div className="p-6 pt-2">
          <EmailInput value={emailContent} onChange={setEmailContent} />

          <div className="mt-6 flex flex-wrap items-center justify-between gap-3">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={loadSample}
              className="text-gray-600 dark:text-gray-300"
            >
              📄 Load Sample Phish
            </Button>

            <Button
              onClick={handleAnalyze}
              disabled={isLoading || !emailContent.trim()}
              className="min-w-[160px] bg-gradient-to-r from-blue-600 to-blue-500 text-white shadow-md transition-all hover:from-blue-700 hover:to-blue-600 disabled:opacity-50"
            >
              {isLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Analysing…
                </>
              ) : (
                <>
                  <Zap className="mr-2 h-4 w-4" />
                  Analyse Email
                </>
              )}
            </Button>
          </div>
        </div>
      </Card>

      {/* Results */}
      {result && <AnalysisResult result={result} email={emailContent} />}
    </div>
  );
}