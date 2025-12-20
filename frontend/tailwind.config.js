/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Dark theme colors
        dark: {
          bg: '#0f172a',      // slate-900
          surface: '#1e293b', // slate-800
          border: '#334155',  // slate-700
          hover: '#475569',   // slate-600
        },
        // Light theme colors
        light: {
          bg: '#f8fafc',      // slate-50
          surface: '#ffffff', // white
          border: '#e2e8f0',  // slate-200
          hover: '#f1f5f9',   // slate-100
        },
        // Primary blue
        primary: {
          DEFAULT: '#3b82f6', // blue-500
          dark: '#2563eb',    // blue-600
          light: '#60a5fa',   // blue-400
        },
        // Status colors
        status: {
          pending: '#64748b',   // slate-500
          running: '#3b82f6',   // blue-500
          completed: '#22c55e', // green-500
          failed: '#ef4444',    // red-500
        },
        // Severity colors
        severity: {
          critical: '#ef4444',  // red-500
          high: '#f97316',      // orange-500
          medium: '#eab308',    // yellow-500
          low: '#3b82f6',       // blue-500
        },
        // Port state colors
        port: {
          open: '#22c55e',      // green-500
          closed: '#6b7280',    // gray-500
          filtered: '#f97316',  // orange-500
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Courier New', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'spin-slow': 'spin 2s linear infinite',
        'fade-in': 'fadeIn 150ms ease-out',
        'scale-in': 'scaleIn 200ms ease-out',
        'slide-up': 'slideUp 200ms ease-out',
        'slide-down': 'slideDown 200ms ease-out',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        scaleIn: {
          '0%': { opacity: '0', transform: 'scale(0.95)' },
          '100%': { opacity: '1', transform: 'scale(1)' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateX(-50%) translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateX(-50%) translateY(0)' },
        },
        slideDown: {
          '0%': { opacity: '0', transform: 'translateY(-10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
}
