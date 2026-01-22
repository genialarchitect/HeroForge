import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { toast } from 'react-toastify';

interface ServiceStatus {
  id: string;
  name: string;
  description: string;
  status: 'operational' | 'degraded' | 'partial_outage' | 'major_outage' | 'maintenance';
  latency_ms?: number;
  uptime_percent: number;
  last_check_at?: string;
}

interface IncidentUpdate {
  id: string;
  incident_id: string;
  status: string;
  message: string;
  created_at: string;
}

interface Incident {
  id: string;
  title: string;
  status: 'investigating' | 'identified' | 'monitoring' | 'resolved';
  severity: 'minor' | 'major' | 'critical' | 'maintenance';
  affected_services: string;
  created_at: string;
  updated_at: string;
  resolved_at?: string;
  updates: IncidentUpdate[];
}

interface UptimeRecord {
  service_id: string;
  date: string;
  status: string;
  uptime_percent: number;
  avg_latency_ms?: number;
  check_count: number;
}

interface UptimeSummary {
  current_month: number;
  last_30_days: number;
  last_90_days: number;
  all_time: number;
}

interface UptimeDay {
  date: string;
  status: 'operational' | 'degraded' | 'partial_outage' | 'major_outage' | 'maintenance' | 'no_data';
}

const StatusPage: React.FC = () => {
  const [services, setServices] = useState<ServiceStatus[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [uptimeHistory, setUptimeHistory] = useState<Record<string, UptimeDay[]>>({});
  const [uptimeSummary, setUptimeSummary] = useState<UptimeSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [subscribeEmail, setSubscribeEmail] = useState('');
  const [subscribed, setSubscribed] = useState(false);
  const [subscribing, setSubscribing] = useState(false);

  useEffect(() => {
    fetchStatusData();
    // Refresh every 60 seconds
    const interval = setInterval(fetchStatusData, 60000);
    return () => clearInterval(interval);
  }, []);

  const fetchStatusData = async () => {
    try {
      const [servicesRes, incidentsRes, uptimeRes, summaryRes] = await Promise.all([
        fetch('/api/status/services'),
        fetch('/api/status/incidents'),
        fetch('/api/status/uptime'),
        fetch('/api/status/uptime/summary'),
      ]);

      if (servicesRes.ok) {
        const data = await servicesRes.json();
        if (data.success) {
          setServices(data.data);
        }
      }

      if (incidentsRes.ok) {
        const data = await incidentsRes.json();
        if (data.success) {
          setIncidents(data.data);
        }
      }

      if (uptimeRes.ok) {
        const data = await uptimeRes.json();
        if (data.success && Array.isArray(data.data)) {
          // Group uptime by service
          const history: Record<string, UptimeDay[]> = {};
          data.data.forEach((record: UptimeRecord) => {
            if (!history[record.service_id]) {
              history[record.service_id] = [];
            }
            history[record.service_id].push({
              date: record.date,
              status: record.status as UptimeDay['status'],
            });
          });
          setUptimeHistory(history);
        }
      }

      if (summaryRes.ok) {
        const data = await summaryRes.json();
        if (data.success) {
          setUptimeSummary(data.data);
        }
      }
    } catch (error) {
      console.error('Failed to fetch status data:', error);
    } finally {
      setLoading(false);
    }
  };

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
      case 'maintenance': return 'bg-blue-500/20 text-blue-400 border-blue-500/50';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/50';
    }
  };

  const getOverallStatus = () => {
    if (services.some(s => s.status === 'major_outage'))
      return { status: 'major_outage', text: 'Major System Outage', color: 'bg-red-500' };
    if (services.some(s => s.status === 'partial_outage'))
      return { status: 'partial_outage', text: 'Partial System Outage', color: 'bg-orange-500' };
    if (services.some(s => s.status === 'degraded'))
      return { status: 'degraded', text: 'Degraded Performance', color: 'bg-yellow-500' };
    if (services.some(s => s.status === 'maintenance'))
      return { status: 'maintenance', text: 'Scheduled Maintenance', color: 'bg-blue-500' };
    return { status: 'operational', text: 'All Systems Operational', color: 'bg-green-500' };
  };

  const handleSubscribe = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!subscribeEmail.trim()) return;

    setSubscribing(true);
    try {
      const response = await fetch('/api/status/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: subscribeEmail }),
      });

      const data = await response.json();

      if (data.success) {
        setSubscribed(true);
        setSubscribeEmail('');
        toast.success('Please check your email to verify your subscription.');
      } else {
        toast.error(data.error || 'Failed to subscribe');
      }
    } catch (error) {
      console.error('Failed to subscribe:', error);
      toast.error('Failed to subscribe');
    } finally {
      setSubscribing(false);
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

  const parseAffectedServices = (services: string): string[] => {
    try {
      return JSON.parse(services);
    } catch {
      return [];
    }
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
            <Link to="/roadmap" className="text-gray-300 hover:text-white">Roadmap</Link>
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

        {/* Uptime Summary */}
        {uptimeSummary && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-4 text-center">
              <p className="text-2xl font-bold text-green-400">{uptimeSummary.current_month.toFixed(2)}%</p>
              <p className="text-gray-400 text-sm">This Month</p>
            </div>
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-4 text-center">
              <p className="text-2xl font-bold text-green-400">{uptimeSummary.last_30_days.toFixed(2)}%</p>
              <p className="text-gray-400 text-sm">Last 30 Days</p>
            </div>
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-4 text-center">
              <p className="text-2xl font-bold text-green-400">{uptimeSummary.last_90_days.toFixed(2)}%</p>
              <p className="text-gray-400 text-sm">Last 90 Days</p>
            </div>
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-4 text-center">
              <p className="text-2xl font-bold text-green-400">{uptimeSummary.all_time.toFixed(2)}%</p>
              <p className="text-gray-400 text-sm">All Time</p>
            </div>
          </div>
        )}

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
              <span>Please check your email to verify your subscription.</span>
            </div>
          ) : (
            <form onSubmit={handleSubscribe} className="flex gap-2">
              <input
                type="email"
                value={subscribeEmail}
                onChange={(e) => setSubscribeEmail(e.target.value)}
                placeholder="your@email.com"
                className="flex-1 bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                required
              />
              <button
                type="submit"
                disabled={subscribing}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-medium transition-colors disabled:opacity-50"
              >
                {subscribing ? 'Subscribing...' : 'Subscribe'}
              </button>
            </form>
          )}
        </div>

        {/* Services List */}
        <div className="mb-12">
          <h2 className="text-xl font-semibold text-white mb-4">System Status</h2>
          <div className="bg-gray-800 rounded-xl border border-gray-700 divide-y divide-gray-700">
            {services.map((service) => (
              <div key={service.id} className="p-4">
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <h3 className="text-white font-medium">{service.name}</h3>
                    <p className="text-gray-500 text-sm">{service.description}</p>
                  </div>
                  <div className="flex items-center gap-3">
                    {service.latency_ms && (
                      <span className="text-gray-400 text-sm">{service.latency_ms}ms</span>
                    )}
                    <div className="flex items-center gap-2">
                      <span className={`w-3 h-3 rounded-full ${getStatusColor(service.status)}`} />
                      <span className="text-gray-300 text-sm">{getStatusText(service.status)}</span>
                    </div>
                  </div>
                </div>
                {/* Uptime History Bar */}
                <div className="flex gap-px">
                  {(uptimeHistory[service.id] || []).slice(-90).map((day, i) => (
                    <div
                      key={i}
                      className={`flex-1 h-6 rounded-sm ${getStatusColor(day.status as ServiceStatus['status'])} opacity-80 hover:opacity-100 transition-opacity`}
                      title={`${day.date}: ${getStatusText(day.status as ServiceStatus['status'])}`}
                    />
                  ))}
                  {(!uptimeHistory[service.id] || uptimeHistory[service.id].length === 0) && (
                    // Show placeholder bars if no history
                    Array.from({ length: 90 }).map((_, i) => (
                      <div key={i} className="flex-1 h-6 rounded-sm bg-green-500 opacity-50" />
                    ))
                  )}
                </div>
                <div className="flex justify-between mt-1">
                  <span className="text-gray-500 text-xs">90 days ago</span>
                  <span className="text-gray-400 text-xs font-medium">{service.uptime_percent.toFixed(2)}% uptime</span>
                  <span className="text-gray-500 text-xs">Today</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Incidents */}
        <div>
          <h2 className="text-xl font-semibold text-white mb-4">Recent Incidents</h2>
          {incidents.length === 0 ? (
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-8 text-center">
              <div className="w-16 h-16 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
                <svg className="w-8 h-8 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <p className="text-gray-400">No incidents reported in the last 90 days.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {incidents.map((incident) => (
                <div key={incident.id} className="bg-gray-800 rounded-xl border border-gray-700 p-6">
                  <div className="flex items-start justify-between mb-4">
                    <div>
                      <div className="flex items-center gap-3 mb-1">
                        <h3 className="text-white font-medium">{incident.title}</h3>
                        <span className={`text-xs px-2 py-0.5 rounded border ${getSeverityBadge(incident.severity)}`}>
                          {incident.severity}
                        </span>
                      </div>
                      <p className="text-gray-500 text-sm">
                        {formatDate(incident.created_at)}
                        {incident.resolved_at && ` — Resolved ${formatDate(incident.resolved_at)}`}
                      </p>
                    </div>
                    <span className={`text-sm font-medium ${getIncidentStatusColor(incident.status)}`}>
                      {incident.status.charAt(0).toUpperCase() + incident.status.slice(1)}
                    </span>
                  </div>

                  {/* Affected Services */}
                  <div className="flex flex-wrap gap-2 mb-4">
                    {parseAffectedServices(incident.affected_services).map((service) => (
                      <span key={service} className="text-xs bg-gray-700 text-gray-300 px-2 py-1 rounded">
                        {service}
                      </span>
                    ))}
                  </div>

                  {/* Timeline */}
                  <div className="border-l-2 border-gray-700 pl-4 space-y-4">
                    {incident.updates.map((update, i) => (
                      <div key={i}>
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`text-sm font-medium ${getIncidentStatusColor(update.status as Incident['status'])}`}>
                            {update.status.charAt(0).toUpperCase() + update.status.slice(1)}
                          </span>
                          <span className="text-gray-500 text-xs">{formatDate(update.created_at)}</span>
                        </div>
                        <p className="text-gray-400 text-sm">{update.message}</p>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
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
              <Link to="/roadmap" className="text-gray-400 hover:text-white text-sm">Roadmap</Link>
              <Link to="/legal/terms" className="text-gray-400 hover:text-white text-sm">Terms</Link>
              <Link to="/legal/privacy" className="text-gray-400 hover:text-white text-sm">Privacy</Link>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default StatusPage;
