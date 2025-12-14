import React from 'react';
import { Check } from 'lucide-react';

interface CheckboxProps {
  label?: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  className?: string;
}

const Checkbox: React.FC<CheckboxProps> = ({
  label,
  checked,
  onChange,
  className = '',
}) => {
  return (
    <label className={`inline-flex items-center cursor-pointer ${className}`}>
      <div className="relative">
        <input
          type="checkbox"
          checked={checked}
          onChange={(e) => onChange(e.target.checked)}
          className="sr-only"
        />
        <div
          className={`
            w-5 h-5 border-2 rounded transition-all
            ${checked
              ? 'bg-primary border-primary'
              : 'bg-dark-surface border-dark-border hover:border-primary'
            }
          `}
        >
          {checked && (
            <Check className="h-full w-full text-white p-0.5" />
          )}
        </div>
      </div>
      {label && (
        <span className="ml-2 text-sm text-slate-300">{label}</span>
      )}
    </label>
  );
};

export default Checkbox;
