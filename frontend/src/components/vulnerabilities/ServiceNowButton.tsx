import React, { useState, useEffect, useRef } from 'react';
import { toast } from 'react-toastify';
import { serviceNowAPI, ServiceNowTicket } from '../../services/api';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';
import { Building2, ChevronDown, ExternalLink, AlertCircle, FileText, Wrench } from 'lucide-react';

interface ServiceNowButtonProps {
  vulnerabilityId: string;
  onTicketCreated?: () => void;
}

const ServiceNowButton: React.FC<ServiceNowButtonProps> = ({ vulnerabilityId, onTicketCreated }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [tickets, setTickets] = useState<ServiceNowTicket[]>([]);
  const [loadingTickets, setLoadingTickets] = useState(false);
  const [configured, setConfigured] = useState<boolean | null>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    checkConfiguration();
    loadTickets();
  }, [vulnerabilityId]);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const checkConfiguration = async () => {
    try {
      await serviceNowAPI.getSettings();
      setConfigured(true);
    } catch (error: unknown) {
      const axiosError = error as { response?: { status?: number } };
      if (axiosError.response?.status === 404) {
        setConfigured(false);
      }
    }
  };

  const loadTickets = async () => {
    setLoadingTickets(true);
    try {
      const response = await serviceNowAPI.getTicketsForVulnerability(vulnerabilityId);
      setTickets(response.data);
    } catch (error) {
      console.error('Failed to load ServiceNow tickets:', error);
    } finally {
      setLoadingTickets(false);
    }
  };

  const handleCreateIncident = async () => {
    if (!configured) {
      toast.error('ServiceNow is not configured. Please configure it in Settings.');
      setIsOpen(false);
      return;
    }

    setLoading(true);
    try {
      const response = await serviceNowAPI.createIncident(vulnerabilityId);
      toast.success(`Incident ${response.data.ticket_number} created successfully`);
      setIsOpen(false);
      await loadTickets();
      onTicketCreated?.();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      console.error('Failed to create ServiceNow incident:', error);
      toast.error(axiosError.response?.data?.error || 'Failed to create incident');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateChange = async () => {
    if (!configured) {
      toast.error('ServiceNow is not configured. Please configure it in Settings.');
      setIsOpen(false);
      return;
    }

    setLoading(true);
    try {
      const response = await serviceNowAPI.createChange(vulnerabilityId);
      toast.success(`Change Request ${response.data.ticket_number} created successfully`);
      setIsOpen(false);
      await loadTickets();
      onTicketCreated?.();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      console.error('Failed to create ServiceNow change request:', error);
      toast.error(axiosError.response?.data?.error || 'Failed to create change request');
    } finally {
      setLoading(false);
    }
  };

  const getTicketTypeIcon = (type: string) => {
    return type === 'incident' ? (
      <AlertCircle className="h-4 w-4 text-red-400" />
    ) : (
      <Wrench className="h-4 w-4 text-blue-400" />
    );
  };

  if (configured === null) {
    return null; // Still checking configuration
  }

  return (
    <div className="relative" ref={dropdownRef}>
      <Button
        variant="secondary"
        onClick={() => setIsOpen(!isOpen)}
        disabled={loading}
        className="flex items-center gap-2"
      >
        {loading ? (
          <LoadingSpinner className="h-4 w-4" />
        ) : (
          <Building2 className="h-4 w-4 text-green-400" />
        )}
        <span>ServiceNow</span>
        <ChevronDown className={`h-4 w-4 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </Button>

      {isOpen && (
        <div className="absolute right-0 mt-2 w-72 bg-gray-800 border border-gray-700 rounded-lg shadow-xl z-50">
          {!configured ? (
            <div className="p-4 text-center">
              <AlertCircle className="h-8 w-8 text-yellow-400 mx-auto mb-2" />
              <p className="text-sm text-gray-300 mb-2">ServiceNow not configured</p>
              <p className="text-xs text-gray-500">
                Go to Settings &gt; ServiceNow to configure the integration.
              </p>
            </div>
          ) : (
            <>
              {/* Create Ticket Section */}
              <div className="p-2 border-b border-gray-700">
                <p className="text-xs text-gray-500 px-2 py-1">Create Ticket</p>
                <button
                  onClick={handleCreateIncident}
                  disabled={loading}
                  className="w-full flex items-center gap-3 px-3 py-2 text-left text-gray-300 hover:bg-gray-700 rounded-md transition-colors"
                >
                  <AlertCircle className="h-5 w-5 text-red-400" />
                  <div>
                    <div className="font-medium">Create Incident</div>
                    <div className="text-xs text-gray-500">Report an issue for investigation</div>
                  </div>
                </button>
                <button
                  onClick={handleCreateChange}
                  disabled={loading}
                  className="w-full flex items-center gap-3 px-3 py-2 text-left text-gray-300 hover:bg-gray-700 rounded-md transition-colors"
                >
                  <Wrench className="h-5 w-5 text-blue-400" />
                  <div>
                    <div className="font-medium">Create Change Request</div>
                    <div className="text-xs text-gray-500">Request remediation changes</div>
                  </div>
                </button>
              </div>

              {/* Existing Tickets Section */}
              <div className="p-2">
                <p className="text-xs text-gray-500 px-2 py-1">
                  Linked Tickets {loadingTickets && <LoadingSpinner className="h-3 w-3 inline ml-1" />}
                </p>
                {tickets.length === 0 ? (
                  <p className="px-3 py-2 text-sm text-gray-500">No tickets linked yet</p>
                ) : (
                  <div className="max-h-48 overflow-y-auto">
                    {tickets.map((ticket) => (
                      <a
                        key={ticket.id}
                        href={ticket.ticket_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-3 px-3 py-2 text-gray-300 hover:bg-gray-700 rounded-md transition-colors"
                      >
                        {getTicketTypeIcon(ticket.ticket_type)}
                        <div className="flex-1 min-w-0">
                          <div className="font-medium text-cyan-400 truncate">
                            {ticket.ticket_number}
                          </div>
                          <div className="text-xs text-gray-500 capitalize">
                            {ticket.ticket_type} {ticket.status && `- ${ticket.status}`}
                          </div>
                        </div>
                        <ExternalLink className="h-4 w-4 text-gray-500 flex-shrink-0" />
                      </a>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
};

export default ServiceNowButton;
