import { useEffect, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import Layout from '../../components/layout/Layout';
import { crmAPI } from '../../services/api';
import type {
  Customer,
  Contact,
  Engagement,
  Contract,
  Communication,
  SlaDefinition,
  CrmPortalUser,
  CreateContactRequest,
  CreateEngagementRequest,
  CreateCommunicationRequest,
  CreatePortalUserRequest,
  ResetPortalUserPasswordRequest,
} from '../../types';

type TabType = 'overview' | 'contacts' | 'engagements' | 'contracts' | 'communications' | 'sla' | 'portal-users';

export default function CustomerDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [customer, setCustomer] = useState<Customer | null>(null);
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [contracts, setContracts] = useState<Contract[]>([]);
  const [communications, setCommunications] = useState<Communication[]>([]);
  const [sla, setSla] = useState<SlaDefinition | null>(null);
  const [portalUsers, setPortalUsers] = useState<CrmPortalUser[]>([]);
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (id) {
      loadCustomer();
    }
  }, [id]);

  const loadCustomer = async () => {
    if (!id) return;
    try {
      setLoading(true);
      const [customerRes, contactsRes, engagementsRes, contractsRes, commsRes, slaRes, portalUsersRes] = await Promise.all([
        crmAPI.customers.getById(id),
        crmAPI.contacts.getByCustomer(id),
        crmAPI.engagements.getByCustomer(id),
        crmAPI.contracts.getByCustomer(id),
        crmAPI.communications.getByCustomer(id),
        crmAPI.sla.getByCustomer(id),
        crmAPI.portalUsers.getByCustomer(id),
      ]);
      setCustomer(customerRes.data);
      setContacts(contactsRes.data);
      setEngagements(engagementsRes.data);
      setContracts(contractsRes.data);
      setCommunications(commsRes.data);
      setSla(slaRes.data);
      setPortalUsers(portalUsersRes.data);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to load customer';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteCustomer = async () => {
    if (!id || !customer) return;
    if (!confirm(`Are you sure you want to delete ${customer.name}? This will also delete all related data.`)) {
      return;
    }
    try {
      await crmAPI.customers.delete(id);
      navigate('/crm/customers');
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to delete customer';
      setError(message);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
      case 'completed':
        return 'bg-green-100 text-green-800';
      case 'inactive':
      case 'cancelled':
        return 'bg-gray-100 text-gray-800';
      case 'prospect':
      case 'planning':
        return 'bg-yellow-100 text-yellow-800';
      case 'in_progress':
        return 'bg-blue-100 text-blue-800';
      case 'on_hold':
        return 'bg-orange-100 text-orange-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const formatCurrency = (value: number | null) => {
    if (value === null) return '-';
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 0,
    }).format(value);
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return '-';
    return new Date(dateString).toLocaleDateString();
  };

  if (loading) {
    return (
      <Layout>
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
        </div>
      </Layout>
    );
  }

  if (error || !customer) {
    return (
      <Layout>
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <p className="text-red-800">{error || 'Customer not found'}</p>
          <Link to="/crm/customers" className="mt-2 text-red-600 hover:text-red-800">
            Back to Customers
          </Link>
        </div>
      </Layout>
    );
  }

  const tabs = [
    { id: 'overview' as TabType, label: 'Overview' },
    { id: 'contacts' as TabType, label: `Contacts (${contacts.length})` },
    { id: 'engagements' as TabType, label: `Engagements (${engagements.length})` },
    { id: 'contracts' as TabType, label: `Contracts (${contracts.length})` },
    { id: 'communications' as TabType, label: `Activity (${communications.length})` },
    { id: 'sla' as TabType, label: 'SLA' },
    { id: 'portal-users' as TabType, label: `Portal Users (${portalUsers.length})` },
  ];

  return (
    <Layout>
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white shadow rounded-lg p-6">
        <div className="flex justify-between items-start">
          <div className="flex items-center space-x-4">
            <div className="h-16 w-16 rounded-full bg-indigo-100 flex items-center justify-center">
              <span className="text-2xl text-indigo-600 font-bold">
                {customer.name.charAt(0).toUpperCase()}
              </span>
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-900">{customer.name}</h1>
              <div className="flex items-center space-x-4 mt-1">
                <span className={`px-2 py-1 text-xs rounded-full ${getStatusColor(customer.status)}`}>
                  {customer.status}
                </span>
                {customer.industry && (
                  <span className="text-sm text-gray-500">{customer.industry}</span>
                )}
                {customer.company_size && (
                  <span className="text-sm text-gray-500">
                    {customer.company_size.charAt(0).toUpperCase() + customer.company_size.slice(1)}
                  </span>
                )}
              </div>
            </div>
          </div>
          <div className="flex space-x-3">
            <Link
              to={`/dashboard?customer=${customer.id}`}
              className="px-4 py-2 text-sm font-medium text-indigo-600 border border-indigo-600 rounded-md hover:bg-indigo-50"
            >
              New Scan
            </Link>
            <button
              onClick={handleDeleteCustomer}
              className="px-4 py-2 text-sm font-medium text-red-600 border border-red-300 rounded-md hover:bg-red-50"
            >
              Delete
            </button>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-indigo-500 text-indigo-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="bg-white shadow rounded-lg p-6">
        {activeTab === 'overview' && (
          <OverviewTab customer={customer} engagements={engagements} contracts={contracts} />
        )}
        {activeTab === 'contacts' && (
          <ContactsTab
            customerId={customer.id}
            contacts={contacts}
            onUpdate={loadCustomer}
          />
        )}
        {activeTab === 'engagements' && (
          <EngagementsTab
            customerId={customer.id}
            engagements={engagements}
            onUpdate={loadCustomer}
          />
        )}
        {activeTab === 'contracts' && (
          <ContractsTab contracts={contracts} />
        )}
        {activeTab === 'communications' && (
          <CommunicationsTab
            customerId={customer.id}
            communications={communications}
            contacts={contacts}
            onUpdate={loadCustomer}
          />
        )}
        {activeTab === 'sla' && (
          <SlaTab sla={sla} />
        )}
        {activeTab === 'portal-users' && (
          <PortalUsersTab
            customerId={customer.id}
            portalUsers={portalUsers}
            contacts={contacts}
            onUpdate={loadCustomer}
          />
        )}
      </div>
    </div>
    </Layout>
  );
}

// Overview Tab Component
function OverviewTab({
  customer,
  engagements,
  contracts,
}: {
  customer: Customer;
  engagements: Engagement[];
  contracts: Contract[];
}) {
  const activeEngagements = engagements.filter((e) => e.status === 'in_progress');
  const totalContractValue = contracts.reduce((sum, c) => sum + (c.value || 0), 0);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <div className="space-y-4">
        <h3 className="text-lg font-medium text-gray-900">Customer Details</h3>
        <dl className="space-y-3">
          {customer.website && (
            <div>
              <dt className="text-sm font-medium text-gray-500">Website</dt>
              <dd className="mt-1">
                <a
                  href={customer.website}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-indigo-600 hover:text-indigo-800"
                >
                  {customer.website}
                </a>
              </dd>
            </div>
          )}
          {customer.address && (
            <div>
              <dt className="text-sm font-medium text-gray-500">Address</dt>
              <dd className="mt-1 text-gray-900">{customer.address}</dd>
            </div>
          )}
          {customer.notes && (
            <div>
              <dt className="text-sm font-medium text-gray-500">Notes</dt>
              <dd className="mt-1 text-gray-900 whitespace-pre-wrap">{customer.notes}</dd>
            </div>
          )}
          <div>
            <dt className="text-sm font-medium text-gray-500">Created</dt>
            <dd className="mt-1 text-gray-900">{new Date(customer.created_at).toLocaleDateString()}</dd>
          </div>
        </dl>
      </div>

      <div className="space-y-4">
        <h3 className="text-lg font-medium text-gray-900">Summary</h3>
        <div className="grid grid-cols-2 gap-4">
          <div className="bg-gray-50 rounded-lg p-4">
            <p className="text-sm text-gray-500">Active Engagements</p>
            <p className="text-2xl font-semibold text-gray-900">{activeEngagements.length}</p>
          </div>
          <div className="bg-gray-50 rounded-lg p-4">
            <p className="text-sm text-gray-500">Total Engagements</p>
            <p className="text-2xl font-semibold text-gray-900">{engagements.length}</p>
          </div>
          <div className="bg-gray-50 rounded-lg p-4">
            <p className="text-sm text-gray-500">Contracts</p>
            <p className="text-2xl font-semibold text-gray-900">{contracts.length}</p>
          </div>
          <div className="bg-gray-50 rounded-lg p-4">
            <p className="text-sm text-gray-500">Contract Value</p>
            <p className="text-2xl font-semibold text-gray-900">
              ${totalContractValue.toLocaleString()}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

// Contacts Tab Component
function ContactsTab({
  customerId,
  contacts,
  onUpdate,
}: {
  customerId: string;
  contacts: Contact[];
  onUpdate: () => void;
}) {
  const [showAdd, setShowAdd] = useState(false);
  const [newContact, setNewContact] = useState<CreateContactRequest>({
    first_name: '',
    last_name: '',
    email: '',
    phone: '',
    title: '',
    is_primary: false,
  });
  const [submitting, setSubmitting] = useState(false);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSubmitting(true);
      await crmAPI.contacts.create(customerId, newContact);
      setShowAdd(false);
      setNewContact({ first_name: '', last_name: '', email: '', phone: '', title: '', is_primary: false });
      onUpdate();
    } catch (error) {
      console.error('Failed to add contact:', error);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-medium text-gray-900">Contacts</h3>
        <button
          onClick={() => setShowAdd(true)}
          className="text-sm text-indigo-600 hover:text-indigo-800"
        >
          + Add Contact
        </button>
      </div>

      {showAdd && (
        <form onSubmit={handleAdd} className="bg-gray-50 rounded-lg p-4 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <input
              type="text"
              placeholder="First Name *"
              value={newContact.first_name}
              onChange={(e) => setNewContact({ ...newContact, first_name: e.target.value })}
              className="rounded-md border-gray-300 text-sm text-gray-900 bg-white"
              required
            />
            <input
              type="text"
              placeholder="Last Name *"
              value={newContact.last_name}
              onChange={(e) => setNewContact({ ...newContact, last_name: e.target.value })}
              className="rounded-md border-gray-300 text-sm text-gray-900 bg-white"
              required
            />
            <input
              type="email"
              placeholder="Email"
              value={newContact.email || ''}
              onChange={(e) => setNewContact({ ...newContact, email: e.target.value })}
              className="rounded-md border-gray-300 text-sm text-gray-900 bg-white"
            />
            <input
              type="tel"
              placeholder="Phone"
              value={newContact.phone || ''}
              onChange={(e) => setNewContact({ ...newContact, phone: e.target.value })}
              className="rounded-md border-gray-300 text-sm text-gray-900 bg-white"
            />
            <input
              type="text"
              placeholder="Title"
              value={newContact.title || ''}
              onChange={(e) => setNewContact({ ...newContact, title: e.target.value })}
              className="rounded-md border-gray-300 text-sm text-gray-900 bg-white"
            />
            <label className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={newContact.is_primary || false}
                onChange={(e) => setNewContact({ ...newContact, is_primary: e.target.checked })}
                className="rounded border-gray-300"
              />
              <span className="text-sm text-gray-700">Primary Contact</span>
            </label>
          </div>
          <div className="flex space-x-2">
            <button
              type="submit"
              disabled={submitting}
              className="px-3 py-1 bg-indigo-600 text-white rounded text-sm hover:bg-indigo-700 disabled:opacity-50"
            >
              {submitting ? 'Adding...' : 'Add'}
            </button>
            <button
              type="button"
              onClick={() => setShowAdd(false)}
              className="px-3 py-1 text-gray-600 hover:text-gray-800 text-sm"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      <div className="divide-y divide-gray-200">
        {contacts.length === 0 ? (
          <p className="text-gray-500 py-4">No contacts yet.</p>
        ) : (
          contacts.map((contact) => (
            <div key={contact.id} className="py-4 flex items-center justify-between">
              <div>
                <p className="font-medium text-gray-900">
                  {contact.first_name} {contact.last_name}
                  {contact.is_primary && (
                    <span className="ml-2 px-2 py-0.5 text-xs bg-indigo-100 text-indigo-800 rounded">Primary</span>
                  )}
                </p>
                <p className="text-sm text-gray-500">{contact.title}</p>
                <div className="flex space-x-4 mt-1 text-sm text-gray-500">
                  {contact.email && <span>{contact.email}</span>}
                  {contact.phone && <span>{contact.phone}</span>}
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// Engagements Tab Component
function EngagementsTab({
  customerId,
  engagements,
  onUpdate,
}: {
  customerId: string;
  engagements: Engagement[];
  onUpdate: () => void;
}) {
  const [showAdd, setShowAdd] = useState(false);
  const [newEngagement, setNewEngagement] = useState<CreateEngagementRequest>({
    name: '',
    engagement_type: 'pentest',
    status: 'planning',
  });
  const [submitting, setSubmitting] = useState(false);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSubmitting(true);
      await crmAPI.engagements.create(customerId, newEngagement);
      setShowAdd(false);
      setNewEngagement({ name: '', engagement_type: 'pentest', status: 'planning' });
      onUpdate();
    } catch (error) {
      console.error('Failed to add engagement:', error);
    } finally {
      setSubmitting(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'bg-green-100 text-green-800';
      case 'in_progress':
        return 'bg-blue-100 text-blue-800';
      case 'planning':
        return 'bg-yellow-100 text-yellow-800';
      case 'on_hold':
        return 'bg-orange-100 text-orange-800';
      case 'cancelled':
        return 'bg-gray-100 text-gray-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-medium text-gray-900">Engagements</h3>
        <button
          onClick={() => setShowAdd(true)}
          className="text-sm text-indigo-600 hover:text-indigo-800"
        >
          + New Engagement
        </button>
      </div>

      {showAdd && (
        <form onSubmit={handleAdd} className="bg-gray-50 rounded-lg p-4 space-y-3">
          <input
            type="text"
            placeholder="Engagement Name *"
            value={newEngagement.name}
            onChange={(e) => setNewEngagement({ ...newEngagement, name: e.target.value })}
            className="w-full rounded-md border-gray-300 text-sm text-gray-900 bg-white"
            required
          />
          <div className="grid grid-cols-2 gap-3">
            <select
              value={newEngagement.engagement_type}
              onChange={(e) => setNewEngagement({ ...newEngagement, engagement_type: e.target.value as CreateEngagementRequest['engagement_type'] })}
              className="rounded-md border-gray-300 text-sm text-gray-900 bg-white"
            >
              <option value="pentest">Penetration Test</option>
              <option value="vuln_assessment">Vulnerability Assessment</option>
              <option value="red_team">Red Team</option>
              <option value="compliance_audit">Compliance Audit</option>
              <option value="consulting">Consulting</option>
            </select>
            <select
              value={newEngagement.status}
              onChange={(e) => setNewEngagement({ ...newEngagement, status: e.target.value as CreateEngagementRequest['status'] })}
              className="rounded-md border-gray-300 text-sm text-gray-900 bg-white"
            >
              <option value="planning">Planning</option>
              <option value="in_progress">In Progress</option>
              <option value="on_hold">On Hold</option>
              <option value="completed">Completed</option>
            </select>
          </div>
          <div className="flex space-x-2">
            <button
              type="submit"
              disabled={submitting}
              className="px-3 py-1 bg-indigo-600 text-white rounded text-sm hover:bg-indigo-700 disabled:opacity-50"
            >
              {submitting ? 'Creating...' : 'Create'}
            </button>
            <button
              type="button"
              onClick={() => setShowAdd(false)}
              className="px-3 py-1 text-gray-600 hover:text-gray-800 text-sm"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      <div className="divide-y divide-gray-200">
        {engagements.length === 0 ? (
          <p className="text-gray-500 py-4">No engagements yet.</p>
        ) : (
          engagements.map((engagement) => (
            <div
              key={engagement.id}
              className="py-4 flex items-center justify-between -mx-2 px-2 rounded"
            >
              <div>
                <p className="font-medium text-gray-900">{engagement.name}</p>
                <p className="text-sm text-gray-500 capitalize">
                  {engagement.engagement_type.replace('_', ' ')}
                </p>
                {engagement.start_date && (
                  <p className="text-xs text-gray-400 mt-1">
                    Started: {new Date(engagement.start_date).toLocaleDateString()}
                  </p>
                )}
              </div>
              <div className="flex items-center space-x-4">
                <span className={`px-2 py-1 text-xs rounded-full ${getStatusColor(engagement.status)}`}>
                  {engagement.status.replace('_', ' ')}
                </span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// Contracts Tab Component
function ContractsTab({ contracts }: { contracts: Contract[] }) {
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'bg-green-100 text-green-800';
      case 'expired':
      case 'terminated':
        return 'bg-red-100 text-red-800';
      case 'pending_signature':
        return 'bg-yellow-100 text-yellow-800';
      case 'draft':
        return 'bg-gray-100 text-gray-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-medium text-gray-900">Contracts</h3>
      <div className="divide-y divide-gray-200">
        {contracts.length === 0 ? (
          <p className="text-gray-500 py-4">No contracts yet.</p>
        ) : (
          contracts.map((contract) => (
            <div key={contract.id} className="py-4 flex items-center justify-between">
              <div>
                <p className="font-medium text-gray-900">{contract.name}</p>
                <p className="text-sm text-gray-500 uppercase">{contract.contract_type}</p>
              </div>
              <div className="flex items-center space-x-4">
                {contract.value && (
                  <span className="text-sm font-medium text-gray-900">
                    ${contract.value.toLocaleString()}
                  </span>
                )}
                <span className={`px-2 py-1 text-xs rounded-full ${getStatusColor(contract.status)}`}>
                  {contract.status.replace('_', ' ')}
                </span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// Communications Tab Component
function CommunicationsTab({
  customerId,
  communications,
  contacts,
  onUpdate,
}: {
  customerId: string;
  communications: Communication[];
  contacts: Contact[];
  onUpdate: () => void;
}) {
  const [showAdd, setShowAdd] = useState(false);
  const [newComm, setNewComm] = useState<CreateCommunicationRequest>({
    comm_type: 'note',
    subject: '',
    content: '',
    comm_date: new Date().toISOString().split('T')[0],
  });
  const [submitting, setSubmitting] = useState(false);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSubmitting(true);
      await crmAPI.communications.create(customerId, newComm);
      setShowAdd(false);
      setNewComm({
        comm_type: 'note',
        subject: '',
        content: '',
        comm_date: new Date().toISOString().split('T')[0],
      });
      onUpdate();
    } catch (error) {
      console.error('Failed to add communication:', error);
    } finally {
      setSubmitting(false);
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'email':
        return '📧';
      case 'call':
        return '📞';
      case 'meeting':
        return '🤝';
      case 'note':
        return '📝';
      default:
        return '💬';
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-medium text-gray-900">Activity Log</h3>
        <button
          onClick={() => setShowAdd(true)}
          className="text-sm text-indigo-600 hover:text-indigo-800"
        >
          + Log Activity
        </button>
      </div>

      {showAdd && (
        <form onSubmit={handleAdd} className="bg-gray-50 rounded-lg p-4 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <select
              value={newComm.comm_type}
              onChange={(e) => setNewComm({ ...newComm, comm_type: e.target.value as CreateCommunicationRequest['comm_type'] })}
              className="rounded-md border-gray-300 text-sm text-gray-900 bg-white"
            >
              <option value="note">Note</option>
              <option value="email">Email</option>
              <option value="call">Call</option>
              <option value="meeting">Meeting</option>
            </select>
            <input
              type="date"
              value={newComm.comm_date}
              onChange={(e) => setNewComm({ ...newComm, comm_date: e.target.value })}
              className="rounded-md border-gray-300 text-sm text-gray-900 bg-white"
            />
          </div>
          <input
            type="text"
            placeholder="Subject"
            value={newComm.subject || ''}
            onChange={(e) => setNewComm({ ...newComm, subject: e.target.value })}
            className="w-full rounded-md border-gray-300 text-sm text-gray-900 bg-white"
          />
          <textarea
            placeholder="Content"
            value={newComm.content || ''}
            onChange={(e) => setNewComm({ ...newComm, content: e.target.value })}
            rows={3}
            className="w-full rounded-md border-gray-300 text-sm text-gray-900 bg-white"
          />
          <div className="flex space-x-2">
            <button
              type="submit"
              disabled={submitting}
              className="px-3 py-1 bg-indigo-600 text-white rounded text-sm hover:bg-indigo-700 disabled:opacity-50"
            >
              {submitting ? 'Adding...' : 'Add'}
            </button>
            <button
              type="button"
              onClick={() => setShowAdd(false)}
              className="px-3 py-1 text-gray-600 hover:text-gray-800 text-sm"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      <div className="divide-y divide-gray-200">
        {communications.length === 0 ? (
          <p className="text-gray-500 py-4">No activity logged yet.</p>
        ) : (
          communications.map((comm) => (
            <div key={comm.id} className="py-4">
              <div className="flex items-start space-x-3">
                <span className="text-xl">{getTypeIcon(comm.comm_type)}</span>
                <div className="flex-1">
                  <p className="font-medium text-gray-900">
                    {comm.subject || `${comm.comm_type.charAt(0).toUpperCase() + comm.comm_type.slice(1)} logged`}
                  </p>
                  {comm.content && (
                    <p className="text-sm text-gray-600 mt-1 whitespace-pre-wrap">{comm.content}</p>
                  )}
                  <p className="text-xs text-gray-500 mt-1">
                    {new Date(comm.comm_date).toLocaleDateString()}
                  </p>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// SLA Tab Component
function SlaTab({ sla }: { sla: SlaDefinition | null }) {
  if (!sla) {
    return (
      <div className="text-center py-8">
        <p className="text-gray-500">No SLA defined for this customer.</p>
        <button className="mt-4 text-sm text-indigo-600 hover:text-indigo-800">
          + Set SLA
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-medium text-gray-900">{sla.name}</h3>
      {sla.description && <p className="text-gray-600">{sla.description}</p>}

      <div className="grid grid-cols-2 gap-6">
        <div>
          <h4 className="font-medium text-gray-900 mb-3">Response Times</h4>
          <dl className="space-y-2">
            <div className="flex justify-between">
              <dt className="text-sm text-gray-500">Critical</dt>
              <dd className="text-sm font-medium">{sla.response_time_critical ? `${sla.response_time_critical} min` : '-'}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-sm text-gray-500">High</dt>
              <dd className="text-sm font-medium">{sla.response_time_high ? `${sla.response_time_high} min` : '-'}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-sm text-gray-500">Medium</dt>
              <dd className="text-sm font-medium">{sla.response_time_medium ? `${sla.response_time_medium} min` : '-'}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-sm text-gray-500">Low</dt>
              <dd className="text-sm font-medium">{sla.response_time_low ? `${sla.response_time_low} min` : '-'}</dd>
            </div>
          </dl>
        </div>
        <div>
          <h4 className="font-medium text-gray-900 mb-3">Resolution Times</h4>
          <dl className="space-y-2">
            <div className="flex justify-between">
              <dt className="text-sm text-gray-500">Critical</dt>
              <dd className="text-sm font-medium">{sla.resolution_time_critical ? `${sla.resolution_time_critical} min` : '-'}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-sm text-gray-500">High</dt>
              <dd className="text-sm font-medium">{sla.resolution_time_high ? `${sla.resolution_time_high} min` : '-'}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-sm text-gray-500">Medium</dt>
              <dd className="text-sm font-medium">{sla.resolution_time_medium ? `${sla.resolution_time_medium} min` : '-'}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-sm text-gray-500">Low</dt>
              <dd className="text-sm font-medium">{sla.resolution_time_low ? `${sla.resolution_time_low} min` : '-'}</dd>
            </div>
          </dl>
        </div>
      </div>
    </div>
  );
}

// Portal Users Tab Component
function PortalUsersTab({
  customerId,
  portalUsers,
  contacts,
  onUpdate,
}: {
  customerId: string;
  portalUsers: CrmPortalUser[];
  contacts: Contact[];
  onUpdate: () => void;
}) {
  const [showAdd, setShowAdd] = useState(false);
  const [newUser, setNewUser] = useState<CreatePortalUserRequest>({
    email: '',
    password: '',
    contact_id: undefined,
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resetPasswordUserId, setResetPasswordUserId] = useState<string | null>(null);
  const [newPassword, setNewPassword] = useState('');

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      setSubmitting(true);
      await crmAPI.portalUsers.create(customerId, newUser);
      setShowAdd(false);
      setNewUser({ email: '', password: '', contact_id: undefined });
      onUpdate();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to create portal user';
      setError(message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleToggleActive = async (user: CrmPortalUser) => {
    try {
      if (user.is_active) {
        await crmAPI.portalUsers.deactivate(customerId, user.id);
      } else {
        await crmAPI.portalUsers.activate(customerId, user.id);
      }
      onUpdate();
    } catch (err) {
      console.error('Failed to toggle user status:', err);
    }
  };

  const handleDelete = async (user: CrmPortalUser) => {
    if (!confirm(`Are you sure you want to delete portal user ${user.email}?`)) {
      return;
    }
    try {
      await crmAPI.portalUsers.delete(customerId, user.id);
      onUpdate();
    } catch (err) {
      console.error('Failed to delete portal user:', err);
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resetPasswordUserId) return;
    try {
      setSubmitting(true);
      await crmAPI.portalUsers.resetPassword(customerId, resetPasswordUserId, { new_password: newPassword });
      setResetPasswordUserId(null);
      setNewPassword('');
      alert('Password reset successfully');
    } catch (err) {
      console.error('Failed to reset password:', err);
      alert('Failed to reset password');
    } finally {
      setSubmitting(false);
    }
  };

  const getContactName = (contactId: string | undefined) => {
    if (!contactId) return null;
    const contact = contacts.find(c => c.id === contactId);
    return contact ? `${contact.first_name} ${contact.last_name}` : null;
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-medium text-gray-900">Portal Users</h3>
        <button
          onClick={() => setShowAdd(true)}
          className="text-sm text-indigo-600 hover:text-indigo-800"
        >
          + Add Portal User
        </button>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-3">
          <p className="text-sm text-red-800">{error}</p>
        </div>
      )}

      {showAdd && (
        <form onSubmit={handleAdd} className="bg-gray-50 rounded-lg p-4 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <input
              type="email"
              placeholder="Email *"
              value={newUser.email}
              onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
              className="rounded-md border-gray-300 text-sm text-gray-900 bg-white"
              required
            />
            <input
              type="password"
              placeholder="Password * (min 8 chars)"
              value={newUser.password}
              onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
              className="rounded-md border-gray-300 text-sm text-gray-900 bg-white"
              required
              minLength={8}
            />
          </div>
          <select
            value={newUser.contact_id || ''}
            onChange={(e) => setNewUser({ ...newUser, contact_id: e.target.value || undefined })}
            className="w-full rounded-md border-gray-300 text-sm text-gray-900 bg-white"
          >
            <option value="">Link to contact (optional)</option>
            {contacts.map((contact) => (
              <option key={contact.id} value={contact.id}>
                {contact.first_name} {contact.last_name} {contact.email ? `(${contact.email})` : ''}
              </option>
            ))}
          </select>
          <div className="flex space-x-2">
            <button
              type="submit"
              disabled={submitting}
              className="px-3 py-1 bg-indigo-600 text-white rounded text-sm hover:bg-indigo-700 disabled:opacity-50"
            >
              {submitting ? 'Creating...' : 'Create User'}
            </button>
            <button
              type="button"
              onClick={() => {
                setShowAdd(false);
                setError(null);
              }}
              className="px-3 py-1 text-gray-600 hover:text-gray-800 text-sm"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {/* Reset Password Modal */}
      {resetPasswordUserId && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Reset Password</h3>
            <form onSubmit={handleResetPassword} className="space-y-4">
              <input
                type="password"
                placeholder="New Password (min 8 chars)"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full rounded-md border-gray-300 text-sm text-gray-900 bg-white"
                required
                minLength={8}
              />
              <div className="flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => {
                    setResetPasswordUserId(null);
                    setNewPassword('');
                  }}
                  className="px-4 py-2 text-gray-600 hover:text-gray-800 text-sm"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-2 bg-indigo-600 text-white rounded text-sm hover:bg-indigo-700 disabled:opacity-50"
                >
                  {submitting ? 'Resetting...' : 'Reset Password'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <div className="divide-y divide-gray-200">
        {portalUsers.length === 0 ? (
          <p className="text-gray-500 py-4">No portal users yet. Create one to allow customer access to the portal.</p>
        ) : (
          portalUsers.map((user) => (
            <div key={user.id} className="py-4 flex items-center justify-between">
              <div>
                <div className="flex items-center space-x-2">
                  <p className="font-medium text-gray-900">{user.email}</p>
                  <span className={`px-2 py-0.5 text-xs rounded-full ${
                    user.is_active ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                  }`}>
                    {user.is_active ? 'Active' : 'Inactive'}
                  </span>
                </div>
                {user.contact_id && (
                  <p className="text-sm text-gray-500">
                    Linked to: {getContactName(user.contact_id) || user.contact_id}
                  </p>
                )}
                {user.first_name && (
                  <p className="text-sm text-gray-500">
                    {user.first_name} {user.last_name} {user.title ? `- ${user.title}` : ''}
                  </p>
                )}
                <p className="text-xs text-gray-400 mt-1">
                  Created: {new Date(user.created_at).toLocaleDateString()}
                  {user.last_login && ` | Last login: ${new Date(user.last_login).toLocaleDateString()}`}
                </p>
              </div>
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => handleToggleActive(user)}
                  className={`px-2 py-1 text-xs rounded ${
                    user.is_active
                      ? 'text-orange-600 border border-orange-300 hover:bg-orange-50'
                      : 'text-green-600 border border-green-300 hover:bg-green-50'
                  }`}
                >
                  {user.is_active ? 'Deactivate' : 'Activate'}
                </button>
                <button
                  onClick={() => setResetPasswordUserId(user.id)}
                  className="px-2 py-1 text-xs text-indigo-600 border border-indigo-300 rounded hover:bg-indigo-50"
                >
                  Reset Password
                </button>
                <button
                  onClick={() => handleDelete(user)}
                  className="px-2 py-1 text-xs text-red-600 border border-red-300 rounded hover:bg-red-50"
                >
                  Delete
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
