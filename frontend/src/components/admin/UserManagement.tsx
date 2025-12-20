import React, { useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import { adminAPI } from '../../services/api';
import { User, UserRole } from '../../types';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import LoadingSpinner from '../ui/LoadingSpinner';
import { Search, UserPlus, Edit2, Trash2, Shield } from 'lucide-react';

const UserManagement: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [showRoleModal, setShowRoleModal] = useState(false);

  useEffect(() => {
    loadUsers();
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

  const handleToggleActive = async (user: User) => {
    try {
      await adminAPI.updateUser(user.id, { is_active: !user.is_active });
      toast.success(`User ${user.is_active ? 'deactivated' : 'activated'} successfully`);
      loadUsers();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to update user');
    }
  };

  const handleAssignRole = async (userId: string, roleId: string) => {
    try {
      await adminAPI.assignRole(userId, roleId);
      toast.success('Role assigned successfully');
      loadUsers();
      setShowRoleModal(false);
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to assign role');
    }
  };

  const handleRemoveRole = async (userId: string, roleId: string) => {
    try {
      await adminAPI.removeRole(userId, roleId);
      toast.success('Role removed successfully');
      loadUsers();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to remove role');
    }
  };

  const filteredUsers = users.filter(
    (user) =>
      user.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
      user.email.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const getRoleBadgeColor = (role: UserRole) => {
    switch (role) {
      case 'admin':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'auditor':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'user':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
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

  return (
    <div className="space-y-4">
      {/* Search and Actions */}
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
          <Button variant="primary" disabled>
            <UserPlus className="h-4 w-4 mr-2" />
            Add User (Coming Soon)
          </Button>
        </div>
      </Card>

      {/* Users Table */}
      <Card>
        <h3 className="text-xl font-semibold text-white mb-4">
          Users ({filteredUsers.length})
        </h3>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-dark-border">
                <th className="text-left py-3 px-4 text-sm font-medium text-slate-400">Username</th>
                <th className="text-left py-3 px-4 text-sm font-medium text-slate-400">Email</th>
                <th className="text-left py-3 px-4 text-sm font-medium text-slate-400">Roles</th>
                <th className="text-left py-3 px-4 text-sm font-medium text-slate-400">Status</th>
                <th className="text-left py-3 px-4 text-sm font-medium text-slate-400">Created</th>
                <th className="text-right py-3 px-4 text-sm font-medium text-slate-400">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredUsers.map((user) => (
                <tr key={user.id} className="border-b border-dark-border hover:bg-dark-hover">
                  <td className="py-3 px-4 text-white font-medium">{user.username}</td>
                  <td className="py-3 px-4 text-slate-300">{user.email}</td>
                  <td className="py-3 px-4">
                    <div className="flex flex-wrap gap-1">
                      {user.roles?.map((role) => (
                        <div key={role} className="group relative">
                          <span
                            className={`inline-flex items-center gap-1 px-2 py-1 text-xs font-medium rounded border ${getRoleBadgeColor(
                              role
                            )}`}
                          >
                            {role}
                            {user.roles && user.roles.length > 1 && (
                              <button
                                onClick={() => handleRemoveRole(user.id, role)}
                                className="hover:text-red-400 ml-1"
                              >
                                ×
                              </button>
                            )}
                          </span>
                        </div>
                      ))}
                      <button
                        onClick={() => {
                          setSelectedUser(user);
                          setShowRoleModal(true);
                        }}
                        className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium rounded border border-dashed border-slate-600 text-slate-400 hover:text-white hover:border-primary"
                      >
                        + Add Role
                      </button>
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <Badge
                      variant="status"
                      type={user.is_active ? 'completed' : 'failed'}
                    >
                      {user.is_active ? 'Active' : 'Inactive'}
                    </Badge>
                  </td>
                  <td className="py-3 px-4 text-slate-400 text-sm">
                    {user.created_at ? new Date(user.created_at).toLocaleDateString() : '-'}
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center justify-end gap-2">
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
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {filteredUsers.length === 0 && (
            <div className="text-center py-8 text-slate-400">
              No users found matching your search
            </div>
          )}
        </div>
      </Card>

      {/* Role Assignment Modal */}
      {showRoleModal && selectedUser && (
        <>
          <div
            className="fixed inset-0 bg-black/50 z-40"
            onClick={() => setShowRoleModal(false)}
          />
          <div className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 bg-dark-surface border border-dark-border rounded-lg shadow-2xl p-6 w-full max-w-md">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-semibold text-white flex items-center gap-2">
                <Shield className="h-5 w-5 text-primary" />
                Assign Role to {selectedUser.username}
              </h3>
              <button
                onClick={() => setShowRoleModal(false)}
                className="text-slate-400 hover:text-white transition-colors"
              >
                ×
              </button>
            </div>

            <div className="space-y-2">
              {(['admin', 'user', 'auditor', 'viewer'] as UserRole[]).map((role) => {
                const hasRole = selectedUser.roles?.includes(role);
                return (
                  <button
                    key={role}
                    onClick={() => !hasRole && handleAssignRole(selectedUser.id, role)}
                    disabled={hasRole}
                    className={`w-full text-left px-4 py-3 rounded border transition-colors ${
                      hasRole
                        ? 'bg-dark-bg border-dark-border text-slate-500 cursor-not-allowed'
                        : 'bg-dark-bg border-dark-border text-white hover:border-primary hover:bg-dark-hover'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="font-medium capitalize">{role}</div>
                        <div className="text-xs text-slate-400">
                          {role === 'admin' && 'Full system access'}
                          {role === 'user' && 'Standard user access'}
                          {role === 'auditor' && 'Read-only access to all scans and logs'}
                          {role === 'viewer' && 'View-only access to own scans'}
                        </div>
                      </div>
                      {hasRole && (
                        <span className="text-xs text-green-400">Already assigned</span>
                      )}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default UserManagement;
