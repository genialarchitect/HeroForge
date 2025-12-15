import React, { useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import { authAPI } from '../../services/api';
import { User } from '../../types';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Input from '../ui/Input';
import LoadingSpinner from '../ui/LoadingSpinner';
import { User as UserIcon, Mail, Lock, Shield, Calendar, Save } from 'lucide-react';

const Profile: React.FC = () => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [changingPassword, setChangingPassword] = useState(false);

  // Profile form
  const [email, setEmail] = useState('');

  // Password form
  const [showPasswordForm, setShowPasswordForm] = useState(false);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  useEffect(() => {
    loadProfile();
  }, []);

  const loadProfile = async () => {
    setLoading(true);
    try {
      const response = await authAPI.me();
      setUser(response.data);
      setEmail(response.data.email || '');
    } catch (error) {
      toast.error('Failed to load profile');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim()) {
      toast.error('Email is required');
      return;
    }

    setSaving(true);
    try {
      const response = await authAPI.updateProfile({ email: email.trim() });
      setUser(response.data);
      toast.success('Profile updated successfully');
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to update profile');
    } finally {
      setSaving(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!currentPassword || !newPassword) {
      toast.error('All password fields are required');
      return;
    }

    if (newPassword.length < 6) {
      toast.error('New password must be at least 6 characters');
      return;
    }

    if (newPassword !== confirmPassword) {
      toast.error('Passwords do not match');
      return;
    }

    setChangingPassword(true);
    try {
      await authAPI.changePassword({
        current_password: currentPassword,
        new_password: newPassword,
      });
      toast.success('Password changed successfully');
      setShowPasswordForm(false);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to change password');
    } finally {
      setChangingPassword(false);
    }
  };

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return 'N/A';
    return new Date(dateStr).toLocaleDateString('en-US', {
      month: 'long',
      day: 'numeric',
      year: 'numeric',
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
    <div className="space-y-6">
      {/* Profile Info Card */}
      <Card>
        <div className="flex items-center gap-3 mb-6">
          <UserIcon className="h-6 w-6 text-primary" />
          <h3 className="text-xl font-semibold text-white">Profile Information</h3>
        </div>

        {/* User Summary */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6 p-4 bg-dark-bg rounded-lg">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-primary/20 rounded-lg">
              <UserIcon className="h-5 w-5 text-primary" />
            </div>
            <div>
              <p className="text-xs text-slate-500 uppercase tracking-wide">Username</p>
              <p className="text-white font-medium">{user?.username}</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-500/20 rounded-lg">
              <Shield className="h-5 w-5 text-green-400" />
            </div>
            <div>
              <p className="text-xs text-slate-500 uppercase tracking-wide">Roles</p>
              <div className="flex gap-1 flex-wrap">
                {user?.roles?.map((role) => (
                  <span
                    key={role}
                    className="px-2 py-0.5 text-xs bg-primary/20 text-primary rounded capitalize"
                  >
                    {role}
                  </span>
                )) || <span className="text-slate-400">No roles</span>}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-500/20 rounded-lg">
              <Calendar className="h-5 w-5 text-purple-400" />
            </div>
            <div>
              <p className="text-xs text-slate-500 uppercase tracking-wide">Member Since</p>
              <p className="text-white">{formatDate(user?.created_at)}</p>
            </div>
          </div>
        </div>

        {/* Edit Email Form */}
        <form onSubmit={handleSaveProfile} className="space-y-4">
          <div>
            <label className="flex items-center gap-2 text-sm font-medium text-slate-300 mb-2">
              <Mail className="h-4 w-4" />
              Email Address
            </label>
            <div className="flex gap-3">
              <Input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="your@email.com"
                className="flex-1"
              />
              <Button
                type="submit"
                variant="primary"
                loading={saving}
                disabled={saving || email === user?.email}
              >
                <Save className="h-4 w-4 mr-2" />
                Save
              </Button>
            </div>
          </div>
        </form>
      </Card>

      {/* Change Password Card */}
      <Card>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <Lock className="h-6 w-6 text-yellow-400" />
            <h3 className="text-xl font-semibold text-white">Security</h3>
          </div>
          {!showPasswordForm && (
            <Button variant="secondary" onClick={() => setShowPasswordForm(true)}>
              Change Password
            </Button>
          )}
        </div>

        {showPasswordForm ? (
          <form onSubmit={handleChangePassword} className="space-y-4">
            <Input
              label="Current Password"
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              placeholder="Enter current password"
            />
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Input
                label="New Password"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Enter new password"
              />
              <Input
                label="Confirm New Password"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm new password"
              />
            </div>
            {newPassword && confirmPassword && newPassword !== confirmPassword && (
              <p className="text-sm text-red-400">Passwords do not match</p>
            )}
            <div className="flex gap-3 justify-end">
              <Button
                type="button"
                variant="secondary"
                onClick={() => {
                  setShowPasswordForm(false);
                  setCurrentPassword('');
                  setNewPassword('');
                  setConfirmPassword('');
                }}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                variant="primary"
                loading={changingPassword}
                disabled={changingPassword || !currentPassword || !newPassword || newPassword !== confirmPassword}
              >
                Update Password
              </Button>
            </div>
          </form>
        ) : (
          <p className="text-slate-400">
            Keep your account secure by using a strong, unique password.
          </p>
        )}
      </Card>

      {/* Account Status Card */}
      <Card>
        <div className="flex items-center gap-3 mb-4">
          <Shield className="h-6 w-6 text-green-400" />
          <h3 className="text-xl font-semibold text-white">Account Status</h3>
        </div>
        <div className="flex items-center gap-3">
          <div
            className={`w-3 h-3 rounded-full ${
              user?.is_active !== false ? 'bg-green-400' : 'bg-red-400'
            }`}
          />
          <span className="text-white">
            {user?.is_active !== false ? 'Active' : 'Inactive'}
          </span>
        </div>
        <p className="text-sm text-slate-400 mt-2">
          Your account is in good standing.
        </p>
      </Card>
    </div>
  );
};

export default Profile;
