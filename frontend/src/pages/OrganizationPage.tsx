import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import Layout from '../components/layout/Layout';
import { organizationAPI, rolesAPI, permissionsAPI } from '../services/api';
import { useOrgStore } from '../store/orgStore';
import {
  Building2,
  Users,
  Layers,
  UsersRound,
  Shield,
  Settings,
  ArrowLeft,
  Loader2,
  Crown,
  UserCog,
  User,
  Gauge,
} from 'lucide-react';
import Button from '../components/ui/Button';
import { QuotaUsageCard, QuotaManagement } from '../components/organization';
import type {
  Organization,
  OrgMember,
  Department,
  Team,
  CustomRole,
  RoleTemplate,
} from '../types';

// Tab Components (inline for now, can be extracted later)
const OverviewTab: React.FC<{ organization: Organization; memberCount: number; teamCount: number }> = ({
  organization,
  memberCount,
  teamCount,
}) => {
  return (
    <div className="space-y-6">
      {/* Organization Info Card */}
      <div className="bg-dark-surface rounded-lg border border-dark-border p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Organization Details</h3>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-sm text-slate-400">Name</label>
            <p className="text-white font-medium">{organization.name}</p>
          </div>
          <div>
            <label className="text-sm text-slate-400">Slug</label>
            <p className="text-white font-mono">{organization.slug}</p>
          </div>
          <div className="col-span-2">
            <label className="text-sm text-slate-400">Description</label>
            <p className="text-white">{organization.description || 'No description'}</p>
          </div>
          <div>
            <label className="text-sm text-slate-400">Status</label>
            <span className={`inline-flex items-center px-2 py-1 text-xs font-medium rounded ${
              organization.is_active
                ? 'bg-green-500/20 text-green-400 border border-green-500/30'
                : 'bg-red-500/20 text-red-400 border border-red-500/30'
            }`}>
              {organization.is_active ? 'Active' : 'Inactive'}
            </span>
          </div>
          <div>
            <label className="text-sm text-slate-400">Created</label>
            <p className="text-white">{new Date(organization.created_at).toLocaleDateString()}</p>
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-dark-surface rounded-lg border border-dark-border p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/20">
              <Users className="h-5 w-5 text-cyan-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{memberCount}</p>
              <p className="text-sm text-slate-400">Members</p>
            </div>
          </div>
        </div>
        <div className="bg-dark-surface rounded-lg border border-dark-border p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-purple-500/20">
              <UsersRound className="h-5 w-5 text-purple-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{teamCount}</p>
              <p className="text-sm text-slate-400">Teams</p>
            </div>
          </div>
        </div>
        <div className="bg-dark-surface rounded-lg border border-dark-border p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-amber-500/20">
              <Layers className="h-5 w-5 text-amber-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">0</p>
              <p className="text-sm text-slate-400">Departments</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

const MembersTab: React.FC<{ orgId: string; isAdmin: boolean }> = ({ orgId, isAdmin }) => {
  const { data: members, isLoading } = useQuery({
    queryKey: ['org-members', orgId],
    queryFn: async () => {
      const response = await organizationAPI.listMembers(orgId);
      return response.data;
    },
  });

  const getRoleIcon = (role: string) => {
    switch (role) {
      case 'owner':
        return <Crown className="h-4 w-4 text-amber-400" />;
      case 'admin':
        return <UserCog className="h-4 w-4 text-cyan-400" />;
      default:
        return <User className="h-4 w-4 text-slate-400" />;
    }
  };

  const getRoleBadgeColor = (role: string) => {
    switch (role) {
      case 'owner':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
      case 'admin':
        return 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header with Add Button */}
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Members ({members?.length || 0})</h3>
        {isAdmin && (
          <Button size="sm">
            <Users className="h-4 w-4 mr-2" />
            Add Member
          </Button>
        )}
      </div>

      {/* Members List */}
      <div className="bg-dark-surface rounded-lg border border-dark-border overflow-hidden">
        <table className="w-full">
          <thead className="bg-dark-hover">
            <tr>
              <th className="text-left px-4 py-3 text-sm font-medium text-slate-400">User</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-slate-400">Email</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-slate-400">Role</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-slate-400">Joined</th>
              {isAdmin && (
                <th className="text-right px-4 py-3 text-sm font-medium text-slate-400">Actions</th>
              )}
            </tr>
          </thead>
          <tbody className="divide-y divide-dark-border">
            {members?.map((member: OrgMember) => (
              <tr key={member.user_id} className="hover:bg-dark-hover">
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    {getRoleIcon(member.role)}
                    <span className="text-white font-medium">{member.username}</span>
                  </div>
                </td>
                <td className="px-4 py-3 text-slate-400">{member.email}</td>
                <td className="px-4 py-3">
                  <span className={`inline-flex items-center px-2 py-1 text-xs font-medium rounded border ${getRoleBadgeColor(member.role)}`}>
                    {member.role}
                  </span>
                </td>
                <td className="px-4 py-3 text-slate-400">
                  {new Date(member.joined_at).toLocaleDateString()}
                </td>
                {isAdmin && (
                  <td className="px-4 py-3 text-right">
                    <Button variant="ghost" size="sm">
                      Edit
                    </Button>
                  </td>
                )}
              </tr>
            ))}
            {(!members || members.length === 0) && (
              <tr>
                <td colSpan={isAdmin ? 5 : 4} className="px-4 py-8 text-center text-slate-400">
                  No members found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const DepartmentsTab: React.FC<{ orgId: string; isAdmin: boolean }> = ({ orgId, isAdmin }) => {
  const { data: departments, isLoading } = useQuery({
    queryKey: ['org-departments', orgId],
    queryFn: async () => {
      const response = await organizationAPI.listDepartments(orgId);
      return response.data;
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Departments ({departments?.length || 0})</h3>
        {isAdmin && (
          <Button size="sm">
            <Layers className="h-4 w-4 mr-2" />
            Add Department
          </Button>
        )}
      </div>

      <div className="grid gap-4">
        {departments?.map((dept: Department) => (
          <div key={dept.id} className="bg-dark-surface rounded-lg border border-dark-border p-4">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="text-white font-medium">{dept.name}</h4>
                <p className="text-sm text-slate-400">{dept.description || 'No description'}</p>
              </div>
              {isAdmin && (
                <Button variant="ghost" size="sm">
                  Edit
                </Button>
              )}
            </div>
          </div>
        ))}
        {(!departments || departments.length === 0) && (
          <div className="bg-dark-surface rounded-lg border border-dark-border p-8 text-center text-slate-400">
            No departments created yet. Departments help organize your teams.
          </div>
        )}
      </div>
    </div>
  );
};

const TeamsTab: React.FC<{ orgId: string; isAdmin: boolean }> = ({ orgId, isAdmin }) => {
  const { data: teams, isLoading } = useQuery({
    queryKey: ['org-teams', orgId],
    queryFn: async () => {
      const response = await organizationAPI.listTeams(orgId);
      return response.data;
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Teams ({teams?.length || 0})</h3>
        {isAdmin && (
          <Button size="sm">
            <UsersRound className="h-4 w-4 mr-2" />
            Add Team
          </Button>
        )}
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {teams?.map((team: Team) => (
          <div key={team.id} className="bg-dark-surface rounded-lg border border-dark-border p-4">
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-white font-medium">{team.name}</h4>
              {isAdmin && (
                <Button variant="ghost" size="sm">
                  Edit
                </Button>
              )}
            </div>
            <p className="text-sm text-slate-400 mb-3">{team.description || 'No description'}</p>
            <div className="flex items-center gap-2 text-xs text-slate-500">
              <span className="font-mono bg-dark-hover px-2 py-1 rounded">{team.slug}</span>
            </div>
          </div>
        ))}
        {(!teams || teams.length === 0) && (
          <div className="col-span-2 bg-dark-surface rounded-lg border border-dark-border p-8 text-center text-slate-400">
            No teams created yet. Create a department first, then add teams to it.
          </div>
        )}
      </div>
    </div>
  );
};

const RolesTab: React.FC<{ orgId: string; isAdmin: boolean }> = ({ orgId, isAdmin }) => {
  const { data: roleTemplates } = useQuery({
    queryKey: ['role-templates'],
    queryFn: async () => {
      const response = await rolesAPI.listRoleTemplates();
      return response.data;
    },
  });

  const { data: customRoles, isLoading } = useQuery({
    queryKey: ['org-custom-roles', orgId],
    queryFn: async () => {
      const response = await rolesAPI.listCustomRoles(orgId);
      return response.data;
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* System Role Templates */}
      <div>
        <h3 className="text-lg font-semibold text-white mb-4">Role Templates (System)</h3>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {roleTemplates?.map((role: RoleTemplate) => (
            <div key={role.id} className="bg-dark-surface rounded-lg border border-dark-border p-4">
              <div className="flex items-center gap-2 mb-2">
                <Shield className="h-5 w-5 text-primary" />
                <h4 className="text-white font-medium">{role.display_name}</h4>
              </div>
              <p className="text-sm text-slate-400 mb-3">{role.description || 'No description'}</p>
              <div className="text-xs text-slate-500">
                {role.permissions?.length || 0} permissions
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Custom Roles */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white">Custom Roles</h3>
          {isAdmin && (
            <Button size="sm">
              <Shield className="h-4 w-4 mr-2" />
              Create Custom Role
            </Button>
          )}
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {customRoles?.map((role: CustomRole) => (
            <div key={role.id} className="bg-dark-surface rounded-lg border border-dark-border p-4">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <Shield className="h-5 w-5 text-purple-400" />
                  <h4 className="text-white font-medium">{role.display_name}</h4>
                </div>
                {isAdmin && (
                  <Button variant="ghost" size="sm">
                    Edit
                  </Button>
                )}
              </div>
              <p className="text-sm text-slate-400 mb-3">{role.description || 'No description'}</p>
              <div className="text-xs text-slate-500">
                {role.permissions?.length || 0} permissions
              </div>
            </div>
          ))}
          {(!customRoles || customRoles.length === 0) && (
            <div className="col-span-full bg-dark-surface rounded-lg border border-dark-border p-8 text-center text-slate-400">
              No custom roles created yet. Create custom roles to define specific permission sets for your organization.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const SettingsTab: React.FC<{ organization: Organization; isOwner: boolean }> = ({
  organization,
  isOwner,
}) => {
  return (
    <div className="space-y-6">
      {/* General Settings */}
      <div className="bg-dark-surface rounded-lg border border-dark-border p-6">
        <h3 className="text-lg font-semibold text-white mb-4">General Settings</h3>
        <form className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-400 mb-1">Organization Name</label>
            <input
              type="text"
              defaultValue={organization.name}
              disabled={!isOwner}
              className="w-full px-3 py-2 bg-dark-hover border border-dark-border rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-primary disabled:opacity-50"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-400 mb-1">Description</label>
            <textarea
              defaultValue={organization.description || ''}
              disabled={!isOwner}
              rows={3}
              className="w-full px-3 py-2 bg-dark-hover border border-dark-border rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-primary disabled:opacity-50"
            />
          </div>
          {isOwner && (
            <Button type="submit">Save Changes</Button>
          )}
        </form>
      </div>

      {/* Danger Zone */}
      {isOwner && (
        <div className="bg-dark-surface rounded-lg border border-red-500/30 p-6">
          <h3 className="text-lg font-semibold text-red-400 mb-4">Danger Zone</h3>
          <p className="text-sm text-slate-400 mb-4">
            Deleting an organization is permanent and cannot be undone. All members, teams, and associated data will be removed.
          </p>
          <Button variant="danger">
            Delete Organization
          </Button>
        </div>
      )}
    </div>
  );
};

// Main Page Component
type TabId = 'overview' | 'members' | 'departments' | 'teams' | 'roles' | 'quotas' | 'settings';

interface Tab {
  id: TabId;
  label: string;
  icon: React.ReactNode;
}

const OrganizationPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const { isOrgOwner, isOrgAdmin } = useOrgStore();

  // Fetch organization details
  const { data: organization, isLoading, error } = useQuery({
    queryKey: ['organization', id],
    queryFn: async () => {
      const response = await organizationAPI.get(id!);
      return response.data;
    },
    enabled: !!id,
  });

  // Fetch member count for overview
  const { data: members } = useQuery({
    queryKey: ['org-members', id],
    queryFn: async () => {
      const response = await organizationAPI.listMembers(id!);
      return response.data;
    },
    enabled: !!id,
  });

  // Fetch team count for overview
  const { data: teams } = useQuery({
    queryKey: ['org-teams', id],
    queryFn: async () => {
      const response = await organizationAPI.listTeams(id!);
      return response.data;
    },
    enabled: !!id,
  });

  const tabs: Tab[] = [
    { id: 'overview', label: 'Overview', icon: <Building2 className="h-4 w-4" /> },
    { id: 'members', label: 'Members', icon: <Users className="h-4 w-4" /> },
    { id: 'departments', label: 'Departments', icon: <Layers className="h-4 w-4" /> },
    { id: 'teams', label: 'Teams', icon: <UsersRound className="h-4 w-4" /> },
    { id: 'roles', label: 'Roles', icon: <Shield className="h-4 w-4" /> },
    { id: 'quotas', label: 'Quotas', icon: <Gauge className="h-4 w-4" /> },
    { id: 'settings', label: 'Settings', icon: <Settings className="h-4 w-4" /> },
  ];

  if (isLoading) {
    return (
      <Layout>
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
        </div>
      </Layout>
    );
  }

  if (error || !organization) {
    return (
      <Layout>
        <div className="text-center py-12">
          <p className="text-red-400 mb-4">Failed to load organization</p>
          <Button onClick={() => navigate(-1)}>
            <ArrowLeft className="h-4 w-4 mr-2" />
            Go Back
          </Button>
        </div>
      </Layout>
    );
  }

  const renderTabContent = () => {
    switch (activeTab) {
      case 'overview':
        return (
          <OverviewTab
            organization={organization}
            memberCount={members?.length || 0}
            teamCount={teams?.length || 0}
          />
        );
      case 'members':
        return <MembersTab orgId={id!} isAdmin={isOrgAdmin()} />;
      case 'departments':
        return <DepartmentsTab orgId={id!} isAdmin={isOrgAdmin()} />;
      case 'teams':
        return <TeamsTab orgId={id!} isAdmin={isOrgAdmin()} />;
      case 'roles':
        return <RolesTab orgId={id!} isAdmin={isOrgAdmin()} />;
      case 'quotas':
        return (
          <div className="space-y-6">
            <QuotaUsageCard orgId={id!} />
            <QuotaManagement orgId={id!} isOwner={isOrgOwner()} />
          </div>
        );
      case 'settings':
        return <SettingsTab organization={organization} isOwner={isOrgOwner()} />;
      default:
        return null;
    }
  };

  return (
    <Layout>
      <div className="space-y-6">
        {/* Page Header */}
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <button
                onClick={() => navigate(-1)}
                className="p-1 rounded hover:bg-dark-hover transition-colors"
              >
                <ArrowLeft className="h-5 w-5 text-slate-400" />
              </button>
              <Building2 className="h-6 w-6 text-primary" />
              <h1 className="text-2xl font-bold text-white">{organization.name}</h1>
            </div>
            <p className="text-slate-400 ml-9">{organization.description || 'Organization management'}</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="bg-dark-surface rounded-lg border border-dark-border p-4">
          <div className="flex gap-1">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                  activeTab === tab.id
                    ? 'bg-primary text-white'
                    : 'text-slate-400 hover:text-white hover:bg-dark-hover'
                }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Tab Content */}
        <div>{renderTabContent()}</div>
      </div>
    </Layout>
  );
};

export default OrganizationPage;
