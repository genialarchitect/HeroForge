import React, { useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import { adminAPI, rolesAPI } from '../../services/api';
import { AdminUser, RoleAssignmentInfo, RoleTemplate } from '../../types';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import LoadingSpinner from '../ui/LoadingSpinner';
import {
  Search,
  Edit2,
  Trash2,
  Shield,
  ChevronDown,
  ChevronRight,
  Building2,
  Users,
  Clock,
  Unlock,
  Lock,
  ShieldCheck,
  ShieldOff,
  Key
} from 'lucide-react';

interface ExpandedUser {
  [userId: string]: boolean;
}

const UserManagement: React.FC = () => {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedUsers, setExpandedUsers] = useState<ExpandedUser>({});
  const [selectedUser, setSelectedUser] = useState<AdminUser | null>(null);
  const [showRoleModal, setShowRoleModal] = useState(false);
  const [roleTemplates, setRoleTemplates] = useState<RoleTemplate[]>([]);

  useEffect(() => {
    loadUsers();
    loadRoleTemplates();
  }, []);

  const loadUsers = async () => {
    setLoading(true);
    try {
      const response = await adminAPI.getUsers();
      setUsers(response.data);
    } catch (error) {
      toast.error('Failed to load users');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const loadRoleTemplates = async () => {
    try {
      const response = await rolesAPI.listRoleTemplates();
      setRoleTemplates(response.data);
    } catch (error) {
      console.error('Failed to load role templates:', error);
    }
  };

  const handleDeleteUser = async (userId: string, username: string) => {
    if (!confirm(`Are you sure you want to delete user "${username}"? This action cannot be undone.`)) {
      return;
    }

    try {
      await adminAPI.deleteUser(userId);
      toast.success('User deleted successfully');
      loadUsers();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to delete user');
    }
  };

  const handleToggleActive = async (user: AdminUser) => {
    try {
      await adminAPI.updateUser(user.id, { is_active: !user.is_active });
      toast.success(`User ${user.is_active ? 'deactivated' : 'activated'} successfully`);
      loadUsers();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to update user');
    }
  };

  const handleUnlockUser = async (userId: string) => {
    try {
      await adminAPI.unlockUser(userId);
      toast.success('Account unlocked successfully');
      loadUsers();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to unlock account');
    }
  };

  const handleRemoveRoleAssignment = async (userId: string, assignmentId: string) => {
    if (!confirm('Are you sure you want to remove this role assignment?')) {
      return;
    }

    try {
      await adminAPI.removeRoleAssignment(userId, assignmentId);
      toast.success('Role assignment removed');
      loadUsers();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to remove role');
    }
  };

  const toggleUserExpanded = (userId: string) => {
    setExpandedUsers(prev => ({
      ...prev,
      [userId]: !prev[userId]
    }));
  };

  const filteredUsers = users.filter(
    (user) =>
      user.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
      user.email.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const getRoleIcon = (roleName: string) => {
    switch (roleName.toLowerCase()) {
      case 'admin':
        return <ShieldCheck className="h-4 w-4" />;
      case 'analyst':
        return <Search className="h-4 w-4" />;
      case 'engineer':
        return <Key className="h-4 w-4" />;
      case 'viewer':
        return <Shield className="h-4 w-4" />;
      case 'auditor':
        return <ShieldOff className="h-4 w-4" />;
      default:
        return <Shield className="h-4 w-4" />;
    }
  };

  const getRoleColor = (roleName: string) => {
    switch (roleName.toLowerCase()) {
      case 'admin':
        return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'analyst':
        return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
      case 'engineer':
        return 'text-purple-400 bg-purple-500/10 border-purple-500/30';
      case 'manager':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'auditor':
        return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30';
      case 'viewer':
        return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
      default:
        return 'text-green-400 bg-green-500/10 border-green-500/30';
    }
  };

  const getScopeLabel = (assignment: RoleAssignmentInfo) => {
    if (!assignment.scope_type || assignment.scope_type === 'Organization') {
      return assignment.organization_name || 'System-wide';
    }
    return `${assignment.scope_name || assignment.scope_id} (${assignment.scope_type})`;
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  if (loading) {
    return (
      <Card>
        <div className="flex items-center justify-center py-12">
          <LoadingSpinner />
        </div>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {/* Search */}
      <Card>
        <div className="flex items-center gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
            <input
              type="text"
              placeholder="Search users by username or email..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-dark-bg border border-dark-border rounded-lg pl-10 pr-4 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
            />
          </div>
        </div>
      </Card>

      {/* Users Table */}
      <Card>
        <h3 className="text-xl font-semibold text-white mb-4">
          Users ({filteredUsers.length})
        </h3>

        <div className="space-y-2">
          {filteredUsers.map((user) => (
            <div key={user.id} className="border border-dark-border rounded-lg overflow-hidden">
              {/* Main Row */}
              <div
                className="flex items-center gap-4 p-4 bg-dark-surface hover:bg-dark-hover cursor-pointer"
                onClick={() => toggleUserExpanded(user.id)}
              >
                {/* Expand/Collapse Icon */}
                <div className="text-slate-400">
                  {expandedUsers[user.id] ? (
                    <ChevronDown className="h-5 w-5" />
                  ) : (
                    <ChevronRight className="h-5 w-5" />
                  )}
                </div>

                {/* User Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3">
                    <span className="font-medium text-white">{user.username}</span>
                    {user.mfa_enabled && (
                      <span className="text-xs text-green-400 flex items-center gap-1">
                        <ShieldCheck className="h-3 w-3" />
                        MFA
                      </span>
                    )}
                    {user.is_locked && (
                      <span className="text-xs text-red-400 flex items-center gap-1">
                        <Lock className="h-3 w-3" />
                        Locked
                      </span>
                    )}
                  </div>
                  <div className="text-sm text-slate-400">{user.email}</div>
                </div>

                {/* Role Summary */}
                <div className="flex items-center gap-2">
                  {user.permissions_summary.has_admin_role && (
                    <span className="px-2 py-1 text-xs rounded border text-red-400 bg-red-500/10 border-red-500/30 flex items-center gap-1">
                      <ShieldCheck className="h-3 w-3" />
                      Admin
                    </span>
                  )}
                  <span className="text-sm text-slate-400">
                    {user.permissions_summary.role_count} role{user.permissions_summary.role_count !== 1 ? 's' : ''}
                    {user.permissions_summary.organization_count > 0 && (
                      <> in {user.permissions_summary.organization_count} org{user.permissions_summary.organization_count !== 1 ? 's' : ''}</>
                    )}
                  </span>
                </div>

                {/* Status */}
                <div className="w-20">
                  <Badge
                    variant="status"
                    type={user.is_active ? 'completed' : 'failed'}
                  >
                    {user.is_active ? 'Active' : 'Inactive'}
                  </Badge>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                  {user.is_locked && (
                    <button
                      onClick={() => handleUnlockUser(user.id)}
                      className="p-2 text-amber-400 hover:text-amber-300 transition-colors"
                      title="Unlock account"
                    >
                      <Unlock className="h-4 w-4" />
                    </button>
                  )}
                  <button
                    onClick={() => handleToggleActive(user)}
                    className="p-2 text-slate-400 hover:text-primary transition-colors"
                    title={user.is_active ? 'Deactivate user' : 'Activate user'}
                  >
                    <Edit2 className="h-4 w-4" />
                  </button>
                  <button
                    onClick={() => handleDeleteUser(user.id, user.username)}
                    className="p-2 text-slate-400 hover:text-red-400 transition-colors"
                    title="Delete user"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>

              {/* Expanded Role Assignments */}
              {expandedUsers[user.id] && (
                <div className="border-t border-dark-border bg-dark-bg p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h4 className="text-sm font-medium text-slate-300 flex items-center gap-2">
                      <Shield className="h-4 w-4 text-primary" />
                      Role Assignments
                    </h4>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        setSelectedUser(user);
                        setShowRoleModal(true);
                      }}
                    >
                      + Assign Role
                    </Button>
                  </div>

                  {user.role_assignments.length === 0 ? (
                    <div className="text-center py-4 text-slate-500">
                      No role assignments. User has no permissions.
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {user.role_assignments.map((assignment) => (
                        <div
                          key={assignment.id}
                          className="flex items-center gap-4 p-3 bg-dark-surface rounded-lg border border-dark-border"
                        >
                          {/* Role Badge */}
                          <div className={`flex items-center gap-2 px-3 py-1.5 rounded border ${getRoleColor(assignment.role_name)}`}>
                            {getRoleIcon(assignment.role_name)}
                            <span className="font-medium">{assignment.role_display_name}</span>
                          </div>

                          {/* Scope */}
                          <div className="flex-1 flex items-center gap-2 text-sm text-slate-400">
                            {assignment.organization_name ? (
                              <>
                                <Building2 className="h-4 w-4" />
                                <span>{getScopeLabel(assignment)}</span>
                              </>
                            ) : (
                              <>
                                <Users className="h-4 w-4" />
                                <span>System-wide</span>
                              </>
                            )}
                          </div>

                          {/* Expiration */}
                          {assignment.expires_at && (
                            <div className="flex items-center gap-1 text-xs text-amber-400">
                              <Clock className="h-3 w-3" />
                              Expires {formatDate(assignment.expires_at)}
                            </div>
                          )}

                          {/* Assignment info */}
                          <div className="text-xs text-slate-500">
                            Assigned {formatDate(assignment.assigned_at)}
                            {assignment.assigned_by && ` by ${assignment.assigned_by}`}
                          </div>

                          {/* Remove button */}
                          <button
                            onClick={() => handleRemoveRoleAssignment(user.id, assignment.id)}
                            className="p-1.5 text-slate-500 hover:text-red-400 transition-colors"
                            title="Remove role assignment"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Additional user info */}
                  <div className="mt-4 pt-4 border-t border-dark-border">
                    <div className="grid grid-cols-3 gap-4 text-sm">
                      <div>
                        <span className="text-slate-500">Created:</span>
                        <span className="ml-2 text-slate-300">{formatDate(user.created_at)}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">MFA:</span>
                        <span className={`ml-2 ${user.mfa_enabled ? 'text-green-400' : 'text-slate-400'}`}>
                          {user.mfa_enabled ? 'Enabled' : 'Disabled'}
                        </span>
                      </div>
                      {user.is_locked && (
                        <div>
                          <span className="text-slate-500">Locked until:</span>
                          <span className="ml-2 text-red-400">
                            {user.locked_until ? formatDate(user.locked_until) : 'Unknown'}
                          </span>
                          <span className="ml-2 text-slate-500">
                            ({user.failed_attempts} failed attempts)
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}

          {filteredUsers.length === 0 && (
            <div className="text-center py-8 text-slate-400">
              No users found matching your search
            </div>
          )}
        </div>
      </Card>

      {/* Role Assignment Modal */}
      {showRoleModal && selectedUser && (
        <RoleAssignmentModal
          user={selectedUser}
          roleTemplates={roleTemplates}
          onClose={() => {
            setShowRoleModal(false);
            setSelectedUser(null);
          }}
          onAssign={loadUsers}
        />
      )}
    </div>
  );
};

// Role Assignment Modal Component
interface RoleAssignmentModalProps {
  user: AdminUser;
  roleTemplates: RoleTemplate[];
  onClose: () => void;
  onAssign: () => void;
}

const RoleAssignmentModal: React.FC<RoleAssignmentModalProps> = ({
  user,
  roleTemplates,
  onClose,
  onAssign
}) => {
  const [selectedTemplate, setSelectedTemplate] = useState<string>('');
  const [organizationId, setOrganizationId] = useState<string>('system');
  const [expiresAt, setExpiresAt] = useState<string>('');
  const [submitting, setSubmitting] = useState(false);

  const handleAssign = async () => {
    if (!selectedTemplate) {
      toast.error('Please select a role template');
      return;
    }

    setSubmitting(true);
    try {
      await adminAPI.assignRoleWithScope(user.id, {
        role_type: 'template',
        role_id: selectedTemplate,
        organization_id: organizationId === 'system' ? '' : organizationId,
        expires_at: expiresAt || undefined
      });
      toast.success('Role assigned successfully');
      onAssign();
      onClose();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to assign role');
    } finally {
      setSubmitting(false);
    }
  };

  const selectedTemplateInfo = roleTemplates.find(t => t.id === selectedTemplate);

  return (
    <>
      <div className="fixed inset-0 bg-black/50 z-40" onClick={onClose} />
      <div className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 bg-dark-surface border border-dark-border rounded-lg shadow-2xl p-6 w-full max-w-lg">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-semibold text-white flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary" />
            Assign Role to {user.username}
          </h3>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white transition-colors text-2xl"
          >
            &times;
          </button>
        </div>

        <div className="space-y-4">
          {/* Role Template Selector */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Role Template
            </label>
            <select
              value={selectedTemplate}
              onChange={(e) => setSelectedTemplate(e.target.value)}
              className="w-full bg-dark-bg border border-dark-border rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
            >
              <option value="">Select a role...</option>
              {roleTemplates.map((template) => (
                <option key={template.id} value={template.id}>
                  {template.display_name}
                </option>
              ))}
            </select>
          </div>

          {/* Role Description */}
          {selectedTemplateInfo && (
            <div className="p-3 bg-dark-bg rounded-lg border border-dark-border">
              <div className="text-sm text-slate-300 mb-2">
                {selectedTemplateInfo.description || 'No description available'}
              </div>
              <div className="text-xs text-slate-500">
                {selectedTemplateInfo.permissions.length} permissions
              </div>
            </div>
          )}

          {/* Scope (simplified for now) */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Scope
            </label>
            <select
              value={organizationId}
              onChange={(e) => setOrganizationId(e.target.value)}
              className="w-full bg-dark-bg border border-dark-border rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
            >
              <option value="system">System-wide (all organizations)</option>
            </select>
            <p className="mt-1 text-xs text-slate-500">
              Organization-scoped assignments require selecting an organization first
            </p>
          </div>

          {/* Expiration */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Expires (optional)
            </label>
            <input
              type="date"
              value={expiresAt}
              onChange={(e) => setExpiresAt(e.target.value)}
              className="w-full bg-dark-bg border border-dark-border rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
            />
            <p className="mt-1 text-xs text-slate-500">
              Leave empty for permanent assignment
            </p>
          </div>
        </div>

        <div className="flex justify-end gap-3 mt-6">
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            onClick={handleAssign}
            disabled={!selectedTemplate || submitting}
          >
            {submitting ? 'Assigning...' : 'Assign Role'}
          </Button>
        </div>
      </div>
    </>
  );
};

export default UserManagement;
