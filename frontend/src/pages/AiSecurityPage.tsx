import React from 'react';
import { Brain, Sparkles, TrendingUp, AlertCircle } from 'lucide-react';

const AiSecurityPage: React.FC = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
            <Brain className="h-8 w-8 text-primary" />
            AI/ML Security Operations
          </h1>
          <p className="text-slate-600 dark:text-slate-400 mt-2">
            ML-based alert prioritization, anomaly detection, and intelligent security automation
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {/* Alert Prioritization */}
        <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-6">
          <div className="flex items-center gap-3 mb-4">
            <TrendingUp className="h-6 w-6 text-blue-500" />
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
              Alert Prioritization
            </h3>
          </div>
          <p className="text-sm text-slate-600 dark:text-slate-400">
            ML models analyze alert patterns to automatically prioritize critical threats
          </p>
        </div>

        {/* Anomaly Detection */}
        <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-6">
          <div className="flex items-center gap-3 mb-4">
            <AlertCircle className="h-6 w-6 text-orange-500" />
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
              Anomaly Detection
            </h3>
          </div>
          <p className="text-sm text-slate-600 dark:text-slate-400">
            Train custom models to detect unusual patterns in your security data
          </p>
        </div>

        {/* LLM Security */}
        <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-6">
          <div className="flex items-center gap-3 mb-4">
            <Sparkles className="h-6 w-6 text-purple-500" />
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
              LLM Security Testing
            </h3>
          </div>
          <p className="text-sm text-slate-600 dark:text-slate-400">
            Test AI applications for prompt injection, jailbreaks, and data leakage
          </p>
        </div>
      </div>

      <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-6">
        <div className="flex items-start gap-3">
          <Brain className="h-5 w-5 text-blue-600 dark:text-blue-400 mt-0.5" />
          <div>
            <h4 className="font-semibold text-blue-900 dark:text-blue-100 mb-2">
              Sprint 15 - AI/ML Security Features
            </h4>
            <p className="text-sm text-blue-800 dark:text-blue-200">
              ML-based alert prioritization, anomaly detection model training, false positive prediction,
              attack pattern recognition, natural language security queries, and automated AI-powered report generation.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AiSecurityPage;
