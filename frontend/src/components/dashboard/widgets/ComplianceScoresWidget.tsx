import React, { useEffect, useState } from 'react';
import { Award, Loader } from 'lucide-react';
import WidgetContainer from './WidgetContainer';

interface ComplianceScore {
  framework: string;
  score: number;
  total: number;
}

interface ComplianceScoresWidgetProps {
  onRemove?: () => void;
}

const ComplianceScoresWidget: React.FC<ComplianceScoresWidgetProps> = ({ onRemove }) => {
  const [scores, setScores] = useState<ComplianceScore[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const response = await fetch('/api/dashboard/data/compliance_scores', {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('token')}`,
        },
      });
      const data = await response.json();
      setScores(data.scores || []);
    } catch (error) {
      console.error('Failed to fetch compliance scores:', error);
    } finally {
      setLoading(false);
    }
  };

  const getScoreColor = (percentage: number) => {
    if (percentage >= 90) return 'text-green-500';
    if (percentage >= 70) return 'text-yellow-500';
    return 'text-red-500';
  };

  const getProgressColor = (percentage: number) => {
    if (percentage >= 90) return 'bg-green-500';
    if (percentage >= 70) return 'bg-yellow-500';
    return 'bg-red-500';
  };

  return (
    <WidgetContainer
      title="Compliance Scores"
      icon={<Award className="h-5 w-5" />}
      onRemove={onRemove}
    >
      {loading ? (
        <div className="flex items-center justify-center h-32">
          <Loader className="h-6 w-6 text-primary animate-spin" />
        </div>
      ) : scores.length === 0 ? (
        <div className="text-center text-slate-400 py-8">
          No compliance data
        </div>
      ) : (
        <div className="space-y-4">
          {scores.map((score) => {
            const percentage = (score.score / score.total) * 100;
            return (
              <div key={score.framework} className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-white">{score.framework}</span>
                  <span className={`text-sm font-bold ${getScoreColor(percentage)}`}>
                    {score.score}/{score.total} ({percentage.toFixed(0)}%)
                  </span>
                </div>
                <div className="w-full bg-dark-bg rounded-full h-2">
                  <div
                    className={`${getProgressColor(percentage)} h-2 rounded-full transition-all duration-300`}
                    style={{ width: `${percentage}%` }}
                  ></div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </WidgetContainer>
  );
};

export default ComplianceScoresWidget;
