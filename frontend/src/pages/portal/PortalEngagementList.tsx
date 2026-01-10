import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { PortalLayout } from '../../components/portal/PortalLayout';
import { portalEngagementsAPI } from '../../services/portalApi';
import type { PortalEngagement } from '../../types';

const statusColors: Record<string, string> = {
  planning: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300',
  in_progress: 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300',
  completed: 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300',
  on_hold: 'bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-300',
  cancelled: 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300',
};

const typeLabels: Record<string, string> = {
  pentest: 'Penetration Test',
  vuln_assessment: 'Vulnerability Assessment',
  red_team: 'Red Team',
  compliance_audit: 'Compliance Audit',
  consulting: 'Consulting',
};

export default function PortalEngagementList() {
  const [engagements, setEngagements] = useState<PortalEngagement[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  useEffect(() => {
    loadEngagements();
  }, []);

  const loadEngagements = async () => {
    try {
      const response = await portalEngagementsAPI.getAll();
      setEngagements(response.data);
    } catch (err) {
      setError('Failed to load engagements');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const filteredEngagements = statusFilter === 'all'
    ? engagements
    : engagements.filter(e => e.status === statusFilter);

  if (loading) {
    return (
      <PortalLayout>
        <div className="flex items-center justify-center h-64">
          <div className="w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      </PortalLayout>
    );
  }

  return (
    <PortalLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Engagements</h1>
          <div className="flex gap-2">
            {['all', 'planning', 'in_progress', 'completed'].map(status => (
              <button
                key={status}
                onClick={() => setStatusFilter(status)}
                className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                  statusFilter === status
                    ? 'bg-primary text-white'
                    : 'bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border text-slate-600 dark:text-slate-400 hover:bg-light-hover dark:hover:bg-dark-hover'
                }`}
              >
                {status === 'all' ? 'All' : status.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}
              </button>
            ))}
          </div>
        </div>

        {error && (
          <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 p-4 rounded-lg">{error}</div>
        )}

        {filteredEngagements.length === 0 ? (
          <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-8 text-center">
            <p className="text-slate-500 dark:text-slate-400">No engagements found</p>
          </div>
        ) : (
          <div className="grid gap-4">
            {filteredEngagements.map(engagement => (
              <Link
                key={engagement.id}
                to={`/portal/engagements/${engagement.id}`}
                className="bg-light-surface dark:bg-dark-surface rounded-lg p-6 hover:border-primary/50 transition-colors border border-light-border dark:border-dark-border"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white">{engagement.name}</h3>
                    <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                      {typeLabels[engagement.engagement_type] || engagement.engagement_type}
                    </p>
                  </div>
                  <span className={`px-3 py-1 rounded-full text-xs font-medium ${statusColors[engagement.status] || 'bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-300'}`}>
                    {engagement.status.replace('_', ' ')}
                  </span>
                </div>
                {engagement.scope && (
                  <p className="mt-3 text-sm text-slate-500 dark:text-slate-400 line-clamp-2">{engagement.scope}</p>
                )}
                <div className="mt-4 flex items-center gap-4 text-xs text-slate-500 dark:text-slate-400">
                  {engagement.start_date && (
                    <span>Started: {new Date(engagement.start_date).toLocaleDateString()}</span>
                  )}
                  {engagement.end_date && (
                    <span>Ends: {new Date(engagement.end_date).toLocaleDateString()}</span>
                  )}
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </PortalLayout>
  );
}
