import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { PortalLayout } from '../../components/portal/PortalLayout';
import { portalEngagementsAPI } from '../../services/portalApi';
import type { PortalEngagement } from '../../types';

const statusColors: Record<string, string> = {
  planning: 'bg-yellow-900/50 text-yellow-200',
  in_progress: 'bg-blue-900/50 text-blue-200',
  completed: 'bg-green-900/50 text-green-200',
  on_hold: 'bg-gray-700 text-gray-300',
  cancelled: 'bg-red-900/50 text-red-200',
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
          <div className="w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full animate-spin" />
        </div>
      </PortalLayout>
    );
  }

  return (
    <PortalLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-white">Engagements</h1>
          <div className="flex gap-2">
            {['all', 'planning', 'in_progress', 'completed'].map(status => (
              <button
                key={status}
                onClick={() => setStatusFilter(status)}
                className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                  statusFilter === status
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                }`}
              >
                {status === 'all' ? 'All' : status.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}
              </button>
            ))}
          </div>
        </div>

        {error && (
          <div className="bg-red-900/50 text-red-200 p-4 rounded-lg">{error}</div>
        )}

        {filteredEngagements.length === 0 ? (
          <div className="bg-gray-800 rounded-lg p-8 text-center">
            <p className="text-gray-400">No engagements found</p>
          </div>
        ) : (
          <div className="grid gap-4">
            {filteredEngagements.map(engagement => (
              <Link
                key={engagement.id}
                to={`/portal/engagements/${engagement.id}`}
                className="bg-gray-800 rounded-lg p-6 hover:bg-gray-750 transition-colors border border-gray-700 hover:border-gray-600"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-lg font-semibold text-white">{engagement.name}</h3>
                    <p className="text-sm text-gray-400 mt-1">
                      {typeLabels[engagement.engagement_type] || engagement.engagement_type}
                    </p>
                  </div>
                  <span className={`px-3 py-1 rounded-full text-xs font-medium ${statusColors[engagement.status] || 'bg-gray-700 text-gray-300'}`}>
                    {engagement.status.replace('_', ' ')}
                  </span>
                </div>
                {engagement.scope && (
                  <p className="mt-3 text-sm text-gray-400 line-clamp-2">{engagement.scope}</p>
                )}
                <div className="mt-4 flex items-center gap-4 text-xs text-gray-500">
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
