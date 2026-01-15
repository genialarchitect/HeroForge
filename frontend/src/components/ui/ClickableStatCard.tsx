import React from 'react';
import { Link } from 'react-router-dom';
import Card from './Card';
import { ChevronRight } from 'lucide-react';

interface ClickableStatCardProps {
  title: string;
  value: number | string;
  icon: React.ReactNode;
  color: string;
  subtitle?: string;
  to?: string; // Navigation target
  onClick?: () => void; // Alternative click handler
}

const ClickableStatCard: React.FC<ClickableStatCardProps> = ({
  title,
  value,
  icon,
  color,
  subtitle,
  to,
  onClick,
}) => {
  const isClickable = to || onClick;

  const content = (
    <Card
      variant={isClickable ? 'interactive' : 'default'}
      className="p-6 group"
      onClick={onClick}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-slate-400 text-sm font-medium mb-1">{title}</p>
          <p className={`text-3xl font-bold ${color} mb-1`}>{value}</p>
          {subtitle && <p className="text-slate-500 text-xs">{subtitle}</p>}
        </div>
        <div className="flex items-center gap-2">
          <div className={`${color.replace('text-', 'bg-')}/20 p-3 rounded-lg`}>
            {icon}
          </div>
          {isClickable && (
            <ChevronRight className="h-5 w-5 text-slate-500 group-hover:text-primary transition-colors" />
          )}
        </div>
      </div>
    </Card>
  );

  if (to) {
    return (
      <Link to={to} className="block">
        {content}
      </Link>
    );
  }

  return content;
};

export default ClickableStatCard;
