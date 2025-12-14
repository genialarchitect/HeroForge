import React from 'react';

interface CardProps {
  children: React.ReactNode;
  variant?: 'default' | 'interactive';
  className?: string;
  onClick?: () => void;
}

const Card: React.FC<CardProps> = ({
  children,
  variant = 'default',
  className = '',
  onClick,
}) => {
  const baseStyles = 'bg-dark-surface border border-dark-border rounded-lg p-4 shadow-lg';

  const variantStyles = {
    default: '',
    interactive: 'cursor-pointer hover:border-primary hover:shadow-xl transition-all duration-200',
  };

  return (
    <div
      className={`${baseStyles} ${variantStyles[variant]} ${className}`}
      onClick={onClick}
    >
      {children}
    </div>
  );
};

export default Card;
