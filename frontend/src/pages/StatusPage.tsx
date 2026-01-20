import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';

interface ServiceStatus {
  name: string;
  status: 'operational' | 'degraded' | 'partial_outage' | 'major_outage' | 'maintenance';
  latency?: number;
  uptime: number;
  description: string;
}

interface Incident {
  id: string;
  title: string;
  status: 'investigating' | 'identified' | 'monitoring' | 'resolved';
  severity: 'minor' | 'major' | 'critical';
  createdAt: string;
  updatedAt: string;
  resolvedAt?: string;
  updates: {
    timestamp: string;
    status: string;
    message: string;
  }[];
  affectedServices: string[];
}

interface UptimeDay {
  date: string;
  status: 'operational' | 'degraded' | 'partial_outage' | 'major_outage' | 'maintenance' | 'no_data';
}

const StatusPage: React.FC = () => {
  const [services, setServices] = useState<ServiceStatus[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [uptimeHistory, setUptimeHistory] = useState<Record<string, UptimeDay[]>>({});
  const [loading, setLoading] = useState(true);
  const [subscribeEmail, setSubscribeEmail] = useState('');
  const [subscribed, setSubscribed] = useState(false);

  useEffect(() => {
    // Simulate fetching status data
    const fetchStatus = async () => {
      await new Promise(resolve => setTimeout(resolve, 500));

      const mockServices: ServiceStatus[] = [
        { name: 'Web Application', status: 'operational', latency: 45, uptime: 99.98, description: 'Main web dashboard and user interface' },
        { name: 'API', status: 'operational', latency: 23, uptime: 99.99, description: 'REST API endpoints for all operations' },
        { name: 'Scanning Engine', status: 'operational', latency: 156, uptime: 99.95, description: 'Network and vulnerability scanning services' },
        { name: 'Database', status: 'operational', latency: 12, uptime: 99.99, description: 'Primary data storage and retrieval' },
        { name: 'Authentication', status: 'operational', latency: 34, uptime: 99.99, description: 'User authentication and authorization' },
        { name: 'Report Generation', status: 'operational', latency: 89, uptime: 99.92, description: 'PDF, HTML, and other report formats' },
        { name: 'WebSocket', status: 'operational', latency: 18, uptime: 99.97, description: 'Real-time scan progress updates' },
        { name: 'Email Service', status: 'operational', latency: 245, uptime: 99.85, description: 'Notifications and alerts delivery' },
      ];

      const mockIncidents: Incident[] = [
        {
          id: '1',
          title: 'Scheduled Maintenance - Database Optimization',
          status: 'resolved',
          severity: 'minor',
          createdAt: '2026-01-15T02:00:00Z',
          updatedAt: '2026-01-15T04:30:00Z',
          resolvedAt: '2026-01-15T04:30:00Z',
          updates: [
            { timestamp: '2026-01-15T02:00:00Z', status: 'maintenance', message: 'Starting scheduled database optimization. Expected duration: 2-3 hours.' },
            { timestamp: '2026-01-15T04:30:00Z', status: 'resolved', message: 'Database optimization completed successfully. All systems operational.' },
          ],
          affectedServices: ['Database', 'API'],
        },
        {
          id: '2',
          title: 'Elevated API Latency',
          status: 'resolved',
          severity: 'minor',
          createdAt: '2026-01-10T14:23:00Z',
          updatedAt: '2026-01-10T15:45:00Z',
          resolvedAt: '2026-01-10T15:45:00Z',
          updates: [
            { timestamp: '2026-01-10T14:23:00Z', status: 'investigating', message: 'We are investigating reports of elevated API response times.' },
            { timestamp: '2026-01-10T14:45:00Z', status: 'identified', message: 'Root cause identified: Increased traffic from a large scan operation. Scaling resources.' },
            { timestamp: '2026-01-10T15:45:00Z', status: 'resolved', message: 'Additional capacity deployed. API latency returned to normal levels.' },
          ],
          affectedServices: ['API'],
        },
      ];

      // Generate 90 days of uptime history
      const generateUptimeHistory = (serviceName: string): UptimeDay[] => {
        const days: UptimeDay[] = [];
        const today = new Date();
        for (let i = 89; i >= 0; i--) {
          const date = new Date(today);
          date.setDate(date.getDate() - i);
          const rand = Math.random();
          let status: UptimeDay['status'] = 'operational';
          if (rand > 0.98) status = 'degraded';
          if (rand > 0.995) status = 'partial_outage';
          if (serviceName === 'Database' && i === 5) status = 'maintenance';
          days.push({
            date: date.toISOString().split('T')[0],
            status,
          });
        }
        return days;
      };

      const history: Record<string, UptimeDay[]> = {};
      mockServices.forEach(service => {
        history[service.name] = generateUptimeHistory(service.name);
      });

      setServices(mockServices);
      setIncidents(mockIncidents);
      setUptimeHistory(history);
      setLoading(false);
    };

    fetchStatus();
  }, []);

  const getStatusColor = (status: ServiceStatus['status']) => {
    switch (status) {
      case 'operational': return 'bg-green-500';
      case 'degraded': return 'bg-yellow-500';
      case 'partial_outage': return 'bg-orange-500';
      case 'major_outage': return 'bg-red-500';
      case 'maintenance': return 'bg-blue-500';
      default: return 'bg-gray-500';
    }
  };

  const getStatusText = (status: ServiceStatus['status']) => {
    switch (status) {
      case 'operational': return 'Operational';
      case 'degraded': return 'Degraded Performance';
      case 'partial_outage': return 'Partial Outage';
      case 'major_outage': return 'Major Outage';
      case 'maintenance': return 'Under Maintenance';
      default: return 'Unknown';
    }
  };

  const getIncidentStatusColor = (status: Incident['status']) => {
    switch (status) {
      case 'investigating': return 'text-yellow-400';
      case 'identified': return 'text-orange-400';
      case 'monitoring': return 'text-blue-400';
      case 'resolved': return 'text-green-400';
      default: return 'text-gray-400';
    }
  };

  const getSeverityBadge = (severity: Incident['severity']) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/50';
      case 'major': return 'bg-orange-500/20 text-orange-400 border-orange-500/50';
      case 'minor': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/50';
    }
  };

  const getOverallStatus = () => {
    if (services.some(s => s.status === 'major_outage')) return { status: 'major_outage', text: 'Major System Outage', color: 'bg-red-500' };
    if (services.some(s => s.status === 'partial_outage')) return { status: 'partial_outage', text: 'Partial System Outage', color: 'bg-orange-500' };
    if (services.some(s => s.status === 'degraded')) return { status: 'degraded', text: 'Degraded Performance', color: 'bg-yellow-500' };
    if (services.some(s => s.status === 'maintenance')) return { status: 'maintenance', text: 'Scheduled Maintenance', color: 'bg-blue-500' };
    return { status: 'operational', text: 'All Systems Operational', color: 'bg-green-500' };
  };

  const handleSubscribe = (e: React.FormEvent) => {
    e.preventDefault();
    if (subscribeEmail) {
      setSubscribed(true);
      setSubscribeEmail('');
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const overallStatus = getOverallStatus();

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-gray-400">Loading status...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-4xl mx-auto px-4 py-4 flex items-center justify-between">
          <Link to="/" className="flex items-center space-x-2">
            <span className="text-2xl font-bold text-cyan-400">HeroForge</span>
            <span className="text-gray-400">Status</span>
          </Link>
          <nav className="hidden md:flex items-center space-x-6">
            <Link to="/features" className="text-gray-300 hover:text-white">Features</Link>
            <Link to="/pricing" className="text-gray-300 hover:text-white">Pricing</Link>
            <Link to="/docs" className="text-gray-300 hover:text-white">Docs</Link>
            <Link to="/login" className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg">Sign In</Link>
          </nav>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-4 py-12">
        {/* Overall Status Banner */}
        <div className={`${overallStatus.color} rounded-xl p-6 mb-8`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-4 h-4 bg-white rounded-full animate-pulse" />
              <h1 className="text-2xl font-bold text-white">{overallStatus.text}</h1>
            </div>
            <p className="text-white/80 text-sm">
              Last updated: {new Date().toLocaleTimeString()}
            </p>
          </div>
        </div>

        {/* Subscribe to Updates */}
        <div className="bg-gray-800 rounded-xl border border-gray-700 p-6 mb-8">
          <h2 className="text-lg font-semibold text-white mb-2">Subscribe to Updates</h2>
          <p className="text-gray-400 text-sm mb-4">
            Get notified when we have scheduled maintenance or experience service disruptions.
          </p>
          {subscribed ? (
            <div className="flex items-center gap-2 text-green-400">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              <span>You're subscribed to status updates!</span>
            </div>
          ) : (
            <form onSubmit={handleSubscribe} className="flex gap-2">
              <input
                type="email"
                value={subscribeEmail}
                onChange={(e) => setSubscribeEmail(e.target.value)}
                placeholder="your@email.com"
                className="flex-1 bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                required
              />
              <button
                type="submit"
                className="px-6 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-medium transition-colors"
              >
                Subscribe
              </button>
            </form>
          )}
        </div>

        {/* Services Status */}
        <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden mb-8">
          <div className="p-4 border-b border-gray-700">
            <h2 className="text-lg font-semibold text-white">System Status</h2>
          </div>
          <div className="divide-y divide-gray-700">
            {services.map((service) => (
              <div key={service.name} className="p-4">
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <h3 className="text-white font-medium">{service.name}</h3>
                    <p className="text-gray-500 text-sm">{service.description}</p>
                  </div>
                  <div className="flex items-center gap-3">
                    {service.latency && (
                      <span className="text-gray-400 text-sm">{service.latency}ms</span>
                    )}
                    <div className="flex items-center gap-2">
                      <div className={`w-3 h-3 rounded-full ${getStatusColor(service.status)}`} />
                      <span className={`text-sm ${service.status === 'operational' ? 'text-green-400' : 'text-yellow-400'}`}>
                        {getStatusText(service.status)}
                      </span>
                    </div>
                  </div>
                </div>
                {/* Uptime Bar */}
                <div className="flex items-center gap-1 mt-3">
                  <span className="text-gray-500 text-xs w-20">{service.uptime}% uptime</span>
                  <div className="flex-1 flex gap-px">
                    {uptimeHistory[service.name]?.slice(-90).map((day, i) => (
                      <div
                        key={i}
                        className={`h-6 flex-1 rounded-sm ${getStatusColor(day.status as ServiceStatus['status'])} opacity-80 hover:opacity-100 transition-opacity`}
                        title={`${day.date}: ${getStatusText(day.status as ServiceStatus['status'])}`}
                      />
                    ))}
                  </div>
                  <span className="text-gray-500 text-xs w-16 text-right">90 days</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Uptime Summary */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          {[
            { label: 'Current Month', value: '99.98%', trend: '+0.02%' },
            { label: 'Last 30 Days', value: '99.97%', trend: '+0.01%' },
            { label: 'Last 90 Days', value: '99.95%', trend: '+0.03%' },
            { label: 'All Time', value: '99.94%', trend: '' },
          ].map((stat) => (
            <div key={stat.label} className="bg-gray-800 rounded-xl border border-gray-700 p-4">
              <p className="text-gray-400 text-sm mb-1">{stat.label}</p>
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold text-white">{stat.value}</span>
                {stat.trend && (
                  <span className="text-green-400 text-sm">{stat.trend}</span>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Incidents */}
        <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden mb-8">
          <div className="p-4 border-b border-gray-700">
            <h2 className="text-lg font-semibold text-white">Recent Incidents</h2>
          </div>
          {incidents.length === 0 ? (
            <div className="p-8 text-center">
              <div className="w-16 h-16 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
                <svg className="w-8 h-8 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <p className="text-gray-400">No incidents reported in the last 90 days</p>
            </div>
          ) : (
            <div className="divide-y divide-gray-700">
              {incidents.map((incident) => (
                <div key={incident.id} className="p-4">
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`text-xs px-2 py-0.5 rounded border ${getSeverityBadge(incident.severity)}`}>
                          {incident.severity.toUpperCase()}
                        </span>
                        <span className={`text-sm font-medium ${getIncidentStatusColor(incident.status)}`}>
                          {incident.status.charAt(0).toUpperCase() + incident.status.slice(1)}
                        </span>
                      </div>
                      <h3 className="text-white font-medium">{incident.title}</h3>
                    </div>
                    <span className="text-gray-500 text-sm">{formatDate(incident.createdAt)}</span>
                  </div>
                  <div className="flex flex-wrap gap-2 mb-3">
                    {incident.affectedServices.map((service) => (
                      <span key={service} className="text-xs bg-gray-700 text-gray-300 px-2 py-1 rounded">
                        {service}
                      </span>
                    ))}
                  </div>
                  <div className="space-y-3 pl-4 border-l-2 border-gray-700">
                    {incident.updates.map((update, i) => (
                      <div key={i} className="relative">
                        <div className="absolute -left-[21px] w-3 h-3 bg-gray-700 rounded-full border-2 border-gray-600" />
                        <p className="text-gray-500 text-xs mb-1">{formatDate(update.timestamp)}</p>
                        <p className="text-gray-300 text-sm">{update.message}</p>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Scheduled Maintenance */}
        <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
          <div className="p-4 border-b border-gray-700">
            <h2 className="text-lg font-semibold text-white">Scheduled Maintenance</h2>
          </div>
          <div className="p-8 text-center">
            <div className="w-16 h-16 bg-blue-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
              <svg className="w-8 h-8 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
              </svg>
            </div>
            <p className="text-gray-400 mb-2">No scheduled maintenance</p>
            <p className="text-gray-500 text-sm">We'll notify subscribers 48 hours before any planned maintenance.</p>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="bg-gray-800 border-t border-gray-700 mt-16">
        <div className="max-w-4xl mx-auto px-4 py-8">
          <div className="flex flex-col md:flex-row justify-between items-center gap-4">
            <p className="text-gray-500 text-sm">
              &copy; {new Date().getFullYear()} HeroForge Security. All rights reserved.
            </p>
            <div className="flex items-center gap-6">
              <Link to="/legal/terms" className="text-gray-400 hover:text-white text-sm">Terms</Link>
              <Link to="/legal/privacy" className="text-gray-400 hover:text-white text-sm">Privacy</Link>
              <a href="mailto:support@heroforge.io" className="text-gray-400 hover:text-white text-sm">Contact Support</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default StatusPage;
