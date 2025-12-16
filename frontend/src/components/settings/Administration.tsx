import React, { useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import { adminAPI } from '../../services/api';
import { User, AuditLog, UserRole } from '../../types';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import LoadingSpinner from '../ui/LoadingSpinner';
import ConfirmationDialog from '../ui/ConfirmationDialog';
import {
  Users,
  Shield,
  Trash2,
  UserCheck,
  UserX,
  History,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  Clock,
  Unlock,
  Lock,
} from 'lucide-react';

const AVAILABLE_ROLES: { id: string; name: string; description: string }[] = [
  { id: 'admin', name: 'Admin', description: 'Full system access' },
  { id: 'user', name: 'User', description: 'Standard user access' },
  { id: 'auditor', name: 'Auditor', description: 'Read-only access to all scans' },
  { id: 'viewer', name: 'Viewer', description: 'Limited view access' },
];

const Administration: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingLogs, setLoadingLogs] = useState(false);
  const [expandedUsers, setExpandedUsers] = useState<Set<string>>(new Set());
  const [showAuditLogs, setShowAuditLogs] = useState(false);
  const [hasAdminAccess, setHasAdminAccess] = useState(true);
  const [deleteConfirm, setDeleteConfirm] = useState<User | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  useEffect(() => {
    loadUsers();
  }, []);

  const loadUsers = async () => {
    setLoading(true);
    try {
      const response = await adminAPI.getUsers();
      setUsers(response.data);
      setHasAdminAccess(true);
    } catch (error: any) {
      if (error.response?.status === 403) {
        setHasAdminAccess(false);
      } else {
        toast.error('Failed to load users');
      }
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const loadAuditLogs = async () => {
    setLoadingLogs(true);
    try {
      const response = await adminAPI.getAuditLogs(50);
      setAuditLogs(response.data);
    } catch (error: any) {
      toast.error('Failed to load audit logs');
      console.error(error);
    } finally {
      setLoadingLogs(false);
    }
  };

  const toggleUser = (userId: string) => {
    const newExpanded = new Set(expandedUsers);
    if (newExpanded.has(userId)) {
      newExpanded.delete(userId);
    } else {
      newExpanded.add(userId);
    }
    setExpandedUsers(newExpanded);
  };

  const handleToggleActive = async (user: User) => {
    try {
      await adminAPI.updateUser(user.id, { is_active: !user.is_active });
      toast.success(`User ${user.is_active ? 'deactivated' : 'activated'}`);
      loadUsers();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to update user');
    }
  };

  const handleDeleteUser = async () => {
    if (!deleteConfirm) return;

    setIsDeleting(true);
    try {
      await adminAPI.deleteUser(deleteConfirm.id);
      toast.success(`User "${deleteConfirm.username}" deleted successfully`);
      loadUsers();
      setDeleteConfirm(null);
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to delete user');
    } finally {
      setIsDeleting(false);
    }
  };

  const handleAssignRole = async (userId: string, roleId: string) => {
    try {
      await adminAPI.assignRole(userId, roleId);
      toast.success('Role assigned');
      loadUsers();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to assign role');
    }
  };

  const handleRemoveRole = async (userId: string, roleId: string) => {
    try {
      await adminAPI.removeRole(userId, roleId);
      toast.success('Role removed');
      loadUsers();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to remove role');
    }
  };

  const handleUnlockUser = async (user: User) => {
    try {
      await adminAPI.unlockUser(user.id);
      toast.success(`Account "${user.username}" unlocked`);
      loadUsers();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to unlock account');
    }
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const getRoleBadgeColor = (role: UserRole): string => {
    switch (role) {
      case 'admin':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'user':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'auditor':
        return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
      case 'viewer':
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
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

  if (!hasAdminAccess) {
    return (
      <Card>
        <div className="text-center py-12">
          <AlertTriangle className="h-12 w-12 text-yellow-400 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-white mb-2">Access Denied</h3>
          <p className="text-slate-400">
            You don't have permission to access the administration panel.
          </p>
          <p className="text-sm text-slate-500 mt-2">
            Contact an administrator if you need elevated access.
          </p>
        </div>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Users Management */}
      <Card>
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Users className="h-6 w-6 text-primary" />
            <h3 className="text-xl font-semibold text-white">User Management</h3>
          </div>
          <Badge variant="status" type="completed">
            {users.length} users
          </Badge>
        </div>

        <div className="space-y-3">
          {users.map((user) => {
            const isExpanded = expandedUsers.has(user.id);
            const userRoles = user.roles || [];

            return (
              <div
                key={user.id}
                className="bg-dark-bg rounded-lg border border-dark-border overflow-hidden"
              >
                {/* User Row */}
                <div
                  className="flex items-center justify-between p-4 cursor-pointer hover:bg-dark-hover transition-colors"
                  onClick={() => toggleUser(user.id)}
                >
                  <div className="flex items-center gap-4">
                    <button className="text-slate-400">
                      {isExpanded ? (
                        <ChevronDown className="h-4 w-4" />
                      ) : (
                        <ChevronRight className="h-4 w-4" />
                      )}
                    </button>
                    <div className="flex items-center gap-3">
                      <div
                        className={`w-2 h-2 rounded-full ${
                          user.is_active !== false ? 'bg-green-400' : 'bg-red-400'
                        }`}
                      />
                      <div>
                        <p className="font-medium text-white">{user.username}</p>
                        <p className="text-sm text-slate-400">{user.email}</p>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <div className="flex gap-1">
                      {userRoles.map((role) => (
                        <span
                          key={role}
                          className={`px-2 py-0.5 text-xs rounded border capitalize ${getRoleBadgeColor(role)}`}
                        >
                          {role}
                        </span>
                      ))}
                    </div>
                    {user.is_locked && (
                      <span className="px-2 py-0.5 text-xs rounded border bg-red-500/20 text-red-400 border-red-500/30 flex items-center gap-1">
                        <Lock className="h-3 w-3" />
                        Locked
                      </span>
                    )}
                    <span className="text-xs text-slate-500">
                      {user.created_at ? formatDate(user.created_at) : 'N/A'}
                    </span>
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="border-t border-dark-border p-4 space-y-4">
                    {/* Roles Management */}
                    <div>
                      <h4 className="text-sm font-medium text-slate-300 mb-3 flex items-center gap-2">
                        <Shield className="h-4 w-4" />
                        Manage Roles
                      </h4>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                        {AVAILABLE_ROLES.map((role) => {
                          const hasRole = userRoles.includes(role.id as UserRole);
                          return (
                            <button
                              key={role.id}
                              onClick={(e) => {
                                e.stopPropagation();
                                if (hasRole) {
                                  handleRemoveRole(user.id, role.id);
                                } else {
                                  handleAssignRole(user.id, role.id);
                                }
                              }}
                              className={`p-3 rounded-lg border text-left transition-colors ${
                                hasRole
                                  ? 'bg-primary/20 border-primary/50 text-primary'
                                  : 'bg-dark-surface border-dark-border text-slate-400 hover:border-primary/30'
                              }`}
                            >
                              <p className="font-medium text-sm capitalize">{role.name}</p>
                              <p className="text-xs opacity-75">{role.description}</p>
                            </button>
                          );
                        })}
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center justify-between pt-4 border-t border-dark-border">
                      <div className="flex gap-2">
                        <Button
                          variant={user.is_active !== false ? 'secondary' : 'primary'}
                          size="sm"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleToggleActive(user);
                          }}
                        >
                          {user.is_active !== false ? (
                            <>
                              <UserX className="h-4 w-4 mr-1" />
                              Deactivate
                            </>
                          ) : (
                            <>
                              <UserCheck className="h-4 w-4 mr-1" />
                              Activate
                            </>
                          )}
                        </Button>
                        {user.is_locked && (
                          <Button
                            variant="primary"
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleUnlockUser(user);
                            }}
                          >
                            <Unlock className="h-4 w-4 mr-1" />
                            Unlock Account
                          </Button>
                        )}
                      </div>
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          setDeleteConfirm(user);
                        }}
                        className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
                        aria-label={`Delete user ${user.username}`}
                      >
                        <Trash2 className="h-4 w-4 mr-1" />
                        Delete
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </Card>

      {/* Audit Logs */}
      <Card>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <History className="h-6 w-6 text-purple-400" />
            <h3 className="text-xl font-semibold text-white">Audit Logs</h3>
          </div>
          <Button
            variant="secondary"
            onClick={() => {
              setShowAuditLogs(!showAuditLogs);
              if (!showAuditLogs && auditLogs.length === 0) {
                loadAuditLogs();
              }
            }}
          >
            {showAuditLogs ? 'Hide Logs' : 'Show Logs'}
          </Button>
        </div>

        {showAuditLogs && (
          <>
            {loadingLogs ? (
              <div className="flex items-center justify-center py-8">
                <LoadingSpinner />
              </div>
            ) : auditLogs.length === 0 ? (
              <p className="text-slate-400 text-center py-8">No audit logs found</p>
            ) : (
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {auditLogs.map((log) => (
                  <div
                    key={log.id}
                    className="flex items-start gap-3 p-3 bg-dark-bg rounded-lg text-sm"
                  >
                    <Clock className="h-4 w-4 text-slate-500 mt-0.5 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-medium text-white">{log.action}</span>
                        {log.target_type && (
                          <span className="text-slate-400">
                            on {log.target_type}
                          </span>
                        )}
                        {log.target_id && (
                          <span className="text-xs text-slate-500 font-mono truncate max-w-32">
                            {log.target_id}
                          </span>
                        )}
                      </div>
                      {log.details && (
                        <p className="text-xs text-slate-500 mt-1 truncate">
                          {log.details}
                        </p>
                      )}
                    </div>
                    <span className="text-xs text-slate-500 whitespace-nowrap">
                      {formatDate(log.created_at)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </>
        )}

        {!showAuditLogs && (
          <p className="text-slate-400">
            View a log of administrative actions performed in the system.
          </p>
        )}
      </Card>

      {/* Delete User Confirmation Dialog */}
      <ConfirmationDialog
        isOpen={!!deleteConfirm}
        onClose={() => setDeleteConfirm(null)}
        onConfirm={handleDeleteUser}
        title="Delete User"
        message={`Are you sure you want to delete user "${deleteConfirm?.username}"? All their data, including scans and settings, will be permanently removed.`}
        confirmLabel="Delete User"
        variant="danger"
        loading={isDeleting}
      />
    </div>
  );
};

export default Administration;
