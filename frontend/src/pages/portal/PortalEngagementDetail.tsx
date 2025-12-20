import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { PortalLayout } from '../../components/portal/PortalLayout';
import { portalEngagementsAPI } from '../../services/portalApi';
import type { PortalEngagementDetail, PortalMilestone } from '../../types';

const statusColors: Record<string, string> = {
  pending: 'bg-yellow-900/50 text-yellow-200',
  in_progress: 'bg-blue-900/50 text-blue-200',
  completed: 'bg-green-900/50 text-green-200',
};

export default function PortalEngagementDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [engagement, setEngagement] = useState<PortalEngagementDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [updatingMilestone, setUpdatingMilestone] = useState<string | null>(null);

  useEffect(() => {
    if (id) loadEngagement();
  }, [id]);

  const loadEngagement = async () => {
    if (!id) return;
    try {
      const response = await portalEngagementsAPI.getById(id);
      setEngagement(response.data);
    } catch (err) {
      setError('Failed to load engagement');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleMilestoneStatusChange = async (milestone: PortalMilestone, newStatus: string) => {
    if (!id) return;
    setUpdatingMilestone(milestone.id);
    try {
      await portalEngagementsAPI.updateMilestone(id, milestone.id, { status: newStatus });
      loadEngagement();
    } catch (err) {
      console.error('Failed to update milestone:', err);
    } finally {
      setUpdatingMilestone(null);
    }
  };

  if (loading) {
    return (
      <PortalLayout>
        <div className="flex items-center justify-center h-64">
          <div className="w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full animate-spin" />
        </div>
      </PortalLayout>
    );
  }

  if (error || !engagement) {
    return (
      <PortalLayout>
        <div className="bg-red-900/50 text-red-200 p-4 rounded-lg">
          {error || 'Engagement not found'}
        </div>
      </PortalLayout>
    );
  }

  return (
    <PortalLayout>
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <Link to="/portal/engagements" className="text-gray-400 hover:text-white">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </Link>
          <h1 className="text-2xl font-bold text-white">{engagement.engagement.name}</h1>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-gray-800 rounded-lg p-4">
            <p className="text-sm text-gray-400">Status</p>
            <p className="text-lg font-semibold text-white capitalize">{engagement.engagement.status.replace('_', ' ')}</p>
          </div>
          <div className="bg-gray-800 rounded-lg p-4">
            <p className="text-sm text-gray-400">Scans</p>
            <p className="text-lg font-semibold text-white">{engagement.scan_count}</p>
          </div>
          <div className="bg-gray-800 rounded-lg p-4">
            <p className="text-sm text-gray-400">Vulnerabilities</p>
            <Link to={`/portal/vulnerabilities?engagement_id=${id}`} className="text-lg font-semibold text-blue-400 hover:text-blue-300">
              {engagement.vulnerability_count}
            </Link>
          </div>
        </div>

        {engagement.engagement.scope && (
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-2">Scope</h2>
            <p className="text-gray-300 whitespace-pre-wrap">{engagement.engagement.scope}</p>
          </div>
        )}

        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Milestones</h2>
          {engagement.milestones.length === 0 ? (
            <p className="text-gray-400">No milestones defined</p>
          ) : (
            <div className="space-y-4">
              {engagement.milestones.map(milestone => (
                <div key={milestone.id} className="border border-gray-700 rounded-lg p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <h3 className="font-medium text-white">{milestone.name}</h3>
                      {milestone.description && (
                        <p className="text-sm text-gray-400 mt-1">{milestone.description}</p>
                      )}
                      {milestone.due_date && (
                        <p className="text-xs text-gray-500 mt-2">
                          Due: {new Date(milestone.due_date).toLocaleDateString()}
                        </p>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${statusColors[milestone.status] || 'bg-gray-700 text-gray-300'}`}>
                        {milestone.status}
                      </span>
                      {milestone.status !== 'completed' && (
                        <button
                          onClick={() => handleMilestoneStatusChange(milestone, 'completed')}
                          disabled={updatingMilestone === milestone.id}
                          className="px-3 py-1 bg-green-600 hover:bg-green-500 text-white text-xs rounded disabled:opacity-50"
                        >
                          {updatingMilestone === milestone.id ? '...' : 'Complete'}
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </PortalLayout>
  );
}
