import React from 'react';
import { Loader2 } from 'lucide-react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost' | 'outline';
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
  loadingText?: string;
  children: React.ReactNode;
}

const Button: React.FC<ButtonProps> = ({
  variant = 'primary',
  size = 'md',
  loading = false,
  loadingText,
  disabled,
  className = '',
  children,
  'aria-label': ariaLabel,
  ...props
}) => {
  const baseStyles = 'inline-flex items-center justify-center font-medium rounded-lg transition-colors focus-ring disabled:opacity-50 disabled:cursor-not-allowed';

  const variantStyles = {
    primary: 'bg-primary text-white hover:bg-primary-dark active:bg-blue-700',
    secondary: 'bg-light-surface dark:bg-dark-surface text-slate-700 dark:text-slate-100 hover:bg-light-hover dark:hover:bg-dark-hover border border-light-border dark:border-dark-border',
    danger: 'bg-red-600 text-white hover:bg-red-700 active:bg-red-800',
    ghost: 'text-slate-600 dark:text-slate-300 hover:bg-light-hover dark:hover:bg-dark-surface hover:text-slate-900 dark:hover:text-slate-100',
    outline: 'bg-transparent text-slate-600 dark:text-slate-300 border border-light-border dark:border-dark-border hover:bg-light-hover dark:hover:bg-dark-surface hover:text-slate-900 dark:hover:text-slate-100',
  };

  const sizeStyles = {
    sm: 'px-3 py-1.5 text-sm',
    md: 'px-4 py-2 text-base',
    lg: 'px-6 py-3 text-lg',
  };

  return (
    <button
      className={`${baseStyles} ${variantStyles[variant]} ${sizeStyles[size]} ${className}`}
      disabled={disabled || loading}
      aria-busy={loading}
      aria-disabled={disabled || loading}
      aria-label={loading && loadingText ? loadingText : ariaLabel}
      {...props}
    >
      {loading && (
        <Loader2
          className="mr-2 h-4 w-4 animate-spin"
          aria-hidden="true"
        />
      )}
      <span aria-live={loading ? 'polite' : undefined}>
        {loading && loadingText ? loadingText : children}
      </span>
    </button>
  );
};

export { Button };
export default Button;
