import React from 'react';
import { Check } from 'lucide-react';

interface CheckboxProps {
  id?: string;
  label?: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  className?: string;
  disabled?: boolean;
}

const Checkbox: React.FC<CheckboxProps> = ({
  id,
  label,
  checked,
  onChange,
  className = '',
  disabled = false,
}) => {
  return (
    <label className={`inline-flex items-center ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'} ${className}`}>
      <div className="relative">
        <input
          id={id}
          type="checkbox"
          checked={checked}
          onChange={(e) => onChange(e.target.checked)}
          disabled={disabled}
          className="sr-only"
        />
        <div
          className={`
            w-5 h-5 border-2 rounded transition-all
            ${checked
              ? 'bg-primary border-primary'
              : 'bg-light-surface dark:bg-dark-surface border-light-border dark:border-dark-border hover:border-primary'
            }
          `}
        >
          {checked && (
            <Check className="h-full w-full text-white p-0.5" />
          )}
        </div>
      </div>
      {label && (
        <span className="ml-2 text-sm text-slate-700 dark:text-slate-300">{label}</span>
      )}
    </label>
  );
};

export default Checkbox;
