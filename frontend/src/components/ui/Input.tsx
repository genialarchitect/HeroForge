import React, { useId } from 'react';
import { HelpCircle } from 'lucide-react';
import Tooltip from './Tooltip';

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  icon?: React.ReactNode;
  helpText?: string;
  hint?: string;
}

const Input: React.FC<InputProps> = ({
  label,
  error,
  icon,
  helpText,
  hint,
  className = '',
  id: propId,
  ...props
}) => {
  const generatedId = useId();
  const inputId = propId || generatedId;
  const errorId = `${inputId}-error`;
  const hintId = `${inputId}-hint`;

  const describedBy = [
    error ? errorId : null,
    hint ? hintId : null,
  ].filter(Boolean).join(' ') || undefined;

  return (
    <div className="w-full">
      {label && (
        <div className="flex items-center gap-1.5 mb-1">
          <label
            htmlFor={inputId}
            className="block text-sm font-medium text-slate-700 dark:text-slate-300"
          >
            {label}
            {props.required && (
              <span className="text-red-500 dark:text-red-400 ml-0.5" aria-hidden="true">*</span>
            )}
          </label>
          {helpText && (
            <Tooltip content={helpText} position="top">
              <button
                type="button"
                className="text-slate-400 dark:text-slate-500 hover:text-slate-600 dark:hover:text-slate-300 transition-colors"
                aria-label={`Help for ${label}`}
              >
                <HelpCircle className="h-3.5 w-3.5" />
              </button>
            </Tooltip>
          )}
        </div>
      )}
      {hint && (
        <p id={hintId} className="text-xs text-slate-500 mb-1.5">
          {hint}
        </p>
      )}
      <div className="relative">
        {icon && (
          <div
            className="absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-500 dark:text-slate-400 pointer-events-none"
            aria-hidden="true"
          >
            {icon}
          </div>
        )}
        <input
          id={inputId}
          className={`
            w-full px-3 py-2 rounded-lg transition-colors focus-ring
            bg-light-surface dark:bg-dark-surface
            text-slate-900 dark:text-slate-100
            placeholder-slate-400 dark:placeholder-slate-500
            ${icon ? 'pl-10' : ''}
            ${error
              ? 'border border-red-500'
              : 'border border-light-border dark:border-dark-border hover:border-slate-400 dark:hover:border-dark-hover focus:border-primary'
            }
            ${className}
          `}
          aria-invalid={error ? 'true' : undefined}
          aria-describedby={describedBy}
          {...props}
        />
      </div>
      {error && (
        <p id={errorId} className="mt-1 text-sm text-red-500" role="alert">
          {error}
        </p>
      )}
    </div>
  );
};

export { Input };
export default Input;
