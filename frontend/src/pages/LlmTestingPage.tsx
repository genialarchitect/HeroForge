import React from 'react';
import { Sparkles, ShieldAlert, Lock, Unlock, Code, AlertTriangle } from 'lucide-react';

const LlmTestingPage: React.FC = () => {
  const testCategories = [
    {
      name: 'Prompt Injection',
      icon: <Code className="h-5 w-5" />,
      color: 'text-red-500',
      description: 'Test for malicious prompt injection attacks',
      testCount: 25,
    },
    {
      name: 'Jailbreak Attempts',
      icon: <Unlock className="h-5 w-5" />,
      color: 'text-orange-500',
      description: 'Bypass safety guardrails and content filters',
      testCount: 18,
    },
    {
      name: 'Data Extraction',
      icon: <AlertTriangle className="h-5 w-5" />,
      color: 'text-yellow-500',
      description: 'Attempt to extract training data or sensitive information',
      testCount: 12,
    },
    {
      name: 'Context Manipulation',
      icon: <ShieldAlert className="h-5 w-5" />,
      color: 'text-purple-500',
      description: 'Manipulate conversation context for unintended behavior',
      testCount: 9,
    },
    {
      name: 'Encoding Attacks',
      icon: <Lock className="h-5 w-5" />,
      color: 'text-blue-500',
      description: 'Use encoding techniques to bypass filters',
      testCount: 7,
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
            <Sparkles className="h-8 w-8 text-primary" />
            LLM Security Testing
          </h1>
          <p className="text-slate-600 dark:text-slate-400 mt-2">
            Test AI and LLM applications for security vulnerabilities
          </p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-gradient-to-br from-purple-500 to-purple-600 rounded-lg p-6 text-white">
          <div className="text-3xl font-bold mb-2">69</div>
          <div className="text-purple-100">Built-in Test Cases</div>
        </div>
        <div className="bg-gradient-to-br from-blue-500 to-blue-600 rounded-lg p-6 text-white">
          <div className="text-3xl font-bold mb-2">5</div>
          <div className="text-blue-100">Attack Categories</div>
        </div>
        <div className="bg-gradient-to-br from-green-500 to-green-600 rounded-lg p-6 text-white">
          <div className="text-3xl font-bold mb-2">0</div>
          <div className="text-green-100">Tests Run</div>
        </div>
      </div>

      {/* Test Categories */}
      <div>
        <h2 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">
          Test Categories
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {testCategories.map((category) => (
            <div
              key={category.name}
              className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-5 hover:shadow-lg transition-shadow"
            >
              <div className="flex items-start justify-between mb-3">
                <div className={`${category.color}`}>
                  {category.icon}
                </div>
                <span className="text-xs font-medium px-2 py-1 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 rounded">
                  {category.testCount} tests
                </span>
              </div>
              <h3 className="font-semibold text-slate-900 dark:text-white mb-2">
                {category.name}
              </h3>
              <p className="text-sm text-slate-600 dark:text-slate-400">
                {category.description}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Info Box */}
      <div className="bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded-lg p-6">
        <div className="flex items-start gap-3">
          <Sparkles className="h-5 w-5 text-purple-600 dark:text-purple-400 mt-0.5" />
          <div>
            <h4 className="font-semibold text-purple-900 dark:text-purple-100 mb-2">
              Comprehensive LLM Security Testing
            </h4>
            <p className="text-sm text-purple-800 dark:text-purple-200">
              Test your AI applications against 69 built-in test cases covering prompt injection,
              jailbreak attempts, data extraction, context manipulation, and encoding attacks.
              Identify vulnerabilities before attackers do.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LlmTestingPage;
