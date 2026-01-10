import { useState, useEffect } from 'react';
import { PortalLayout } from '../../components/portal/PortalLayout';
import { portalProfileAPI, portalAuthAPI } from '../../services/portalApi';
import type { PortalProfile, PortalUpdateProfileRequest, PortalChangePasswordRequest } from '../../types';

export default function PortalProfilePage() {
  const [profile, setProfile] = useState<PortalProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Edit mode state
  const [isEditing, setIsEditing] = useState(false);
  const [editForm, setEditForm] = useState<PortalUpdateProfileRequest>({});
  const [saving, setSaving] = useState(false);

  // Password change state
  const [showPasswordForm, setShowPasswordForm] = useState(false);
  const [passwordForm, setPasswordForm] = useState<PortalChangePasswordRequest>({
    current_password: '',
    new_password: '',
  });
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [changingPassword, setChangingPassword] = useState(false);

  useEffect(() => {
    loadProfile();
  }, []);

  const loadProfile = async () => {
    try {
      const response = await portalProfileAPI.getProfile();
      setProfile(response.data);
      setEditForm({
        first_name: response.data.first_name || '',
        last_name: response.data.last_name || '',
        phone: response.data.phone || '',
        title: response.data.title || '',
      });
    } catch (err) {
      setError('Failed to load profile');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    setError('');
    setSuccess('');
    try {
      const response = await portalProfileAPI.updateProfile(editForm);
      setProfile(response.data);
      setIsEditing(false);
      setSuccess('Profile updated successfully');
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      setError('Failed to update profile');
      console.error(err);
    } finally {
      setSaving(false);
    }
  };

  const handleCancel = () => {
    setIsEditing(false);
    if (profile) {
      setEditForm({
        first_name: profile.first_name || '',
        last_name: profile.last_name || '',
        phone: profile.phone || '',
        title: profile.title || '',
      });
    }
  };

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordError('');

    if (passwordForm.new_password !== confirmPassword) {
      setPasswordError('Passwords do not match');
      return;
    }

    if (passwordForm.new_password.length < 8) {
      setPasswordError('Password must be at least 8 characters');
      return;
    }

    setChangingPassword(true);
    try {
      await portalAuthAPI.changePassword(passwordForm);
      setShowPasswordForm(false);
      setPasswordForm({ current_password: '', new_password: '' });
      setConfirmPassword('');
      setSuccess('Password changed successfully');
      setTimeout(() => setSuccess(''), 3000);
    } catch (err: unknown) {
      const error = err as { response?: { data?: { error?: string } } };
      setPasswordError(error.response?.data?.error || 'Failed to change password');
    } finally {
      setChangingPassword(false);
    }
  };

  if (loading) {
    return (
      <PortalLayout>
        <div className="flex items-center justify-center h-64">
          <div className="w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      </PortalLayout>
    );
  }

  if (!profile) {
    return (
      <PortalLayout>
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 p-4 rounded-lg">
          {error || 'Failed to load profile'}
        </div>
      </PortalLayout>
    );
  }

  return (
    <PortalLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Profile</h1>
          {!isEditing && (
            <button
              onClick={() => setIsEditing(true)}
              className="px-4 py-2 bg-primary hover:bg-primary-dark text-white rounded-lg text-sm transition-colors"
            >
              Edit Profile
            </button>
          )}
        </div>

        {error && (
          <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 p-4 rounded-lg">{error}</div>
        )}

        {success && (
          <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 text-green-700 dark:text-green-300 p-4 rounded-lg">{success}</div>
        )}

        {/* Profile Information */}
        <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-6">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Account Information</h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-sm text-slate-500 dark:text-slate-400 mb-1">Email</label>
              <p className="text-slate-900 dark:text-white bg-light-hover dark:bg-dark-hover px-4 py-2 rounded-lg">{profile.email}</p>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Email cannot be changed</p>
            </div>

            <div>
              <label className="block text-sm text-slate-500 dark:text-slate-400 mb-1">Organization</label>
              <p className="text-slate-900 dark:text-white bg-light-hover dark:bg-dark-hover px-4 py-2 rounded-lg">
                {profile.customer_name || 'Not set'}
              </p>
            </div>

            <div>
              <label className="block text-sm text-slate-500 dark:text-slate-400 mb-1">First Name</label>
              {isEditing ? (
                <input
                  type="text"
                  value={editForm.first_name || ''}
                  onChange={(e) => setEditForm({ ...editForm, first_name: e.target.value })}
                  className="w-full bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white px-4 py-2 rounded-lg border border-light-border dark:border-dark-border focus:ring-2 focus:ring-primary focus:border-primary"
                  placeholder="Enter first name"
                />
              ) : (
                <p className="text-slate-900 dark:text-white bg-light-hover dark:bg-dark-hover px-4 py-2 rounded-lg">
                  {profile.first_name || <span className="text-slate-500 dark:text-slate-400">Not set</span>}
                </p>
              )}
            </div>

            <div>
              <label className="block text-sm text-slate-500 dark:text-slate-400 mb-1">Last Name</label>
              {isEditing ? (
                <input
                  type="text"
                  value={editForm.last_name || ''}
                  onChange={(e) => setEditForm({ ...editForm, last_name: e.target.value })}
                  className="w-full bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white px-4 py-2 rounded-lg border border-light-border dark:border-dark-border focus:ring-2 focus:ring-primary focus:border-primary"
                  placeholder="Enter last name"
                />
              ) : (
                <p className="text-slate-900 dark:text-white bg-light-hover dark:bg-dark-hover px-4 py-2 rounded-lg">
                  {profile.last_name || <span className="text-slate-500 dark:text-slate-400">Not set</span>}
                </p>
              )}
            </div>

            <div>
              <label className="block text-sm text-slate-500 dark:text-slate-400 mb-1">Phone</label>
              {isEditing ? (
                <input
                  type="tel"
                  value={editForm.phone || ''}
                  onChange={(e) => setEditForm({ ...editForm, phone: e.target.value })}
                  className="w-full bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white px-4 py-2 rounded-lg border border-light-border dark:border-dark-border focus:ring-2 focus:ring-primary focus:border-primary"
                  placeholder="Enter phone number"
                />
              ) : (
                <p className="text-slate-900 dark:text-white bg-light-hover dark:bg-dark-hover px-4 py-2 rounded-lg">
                  {profile.phone || <span className="text-slate-500 dark:text-slate-400">Not set</span>}
                </p>
              )}
            </div>

            <div>
              <label className="block text-sm text-slate-500 dark:text-slate-400 mb-1">Title</label>
              {isEditing ? (
                <input
                  type="text"
                  value={editForm.title || ''}
                  onChange={(e) => setEditForm({ ...editForm, title: e.target.value })}
                  className="w-full bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white px-4 py-2 rounded-lg border border-light-border dark:border-dark-border focus:ring-2 focus:ring-primary focus:border-primary"
                  placeholder="Enter job title"
                />
              ) : (
                <p className="text-slate-900 dark:text-white bg-light-hover dark:bg-dark-hover px-4 py-2 rounded-lg">
                  {profile.title || <span className="text-slate-500 dark:text-slate-400">Not set</span>}
                </p>
              )}
            </div>
          </div>

          {isEditing && (
            <div className="flex justify-end gap-3 mt-6 pt-4 border-t border-light-border dark:border-dark-border">
              <button
                onClick={handleCancel}
                className="px-4 py-2 bg-light-hover dark:bg-dark-hover text-slate-900 dark:text-white rounded-lg text-sm transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={saving}
                className="px-4 py-2 bg-primary hover:bg-primary-dark text-white rounded-lg text-sm disabled:opacity-50 transition-colors"
              >
                {saving ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          )}
        </div>

        {/* Account Activity */}
        <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-6">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Account Activity</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-sm text-slate-500 dark:text-slate-400 mb-1">Last Login</label>
              <p className="text-slate-900 dark:text-white">
                {profile.last_login
                  ? new Date(profile.last_login).toLocaleString()
                  : 'Never'}
              </p>
            </div>
            <div>
              <label className="block text-sm text-slate-500 dark:text-slate-400 mb-1">Account Created</label>
              <p className="text-slate-900 dark:text-white">
                {new Date(profile.created_at).toLocaleDateString()}
              </p>
            </div>
          </div>
        </div>

        {/* Security */}
        <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-6">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Security</h2>

          {!showPasswordForm ? (
            <button
              onClick={() => setShowPasswordForm(true)}
              className="px-4 py-2 bg-light-hover dark:bg-dark-hover text-slate-900 dark:text-white rounded-lg text-sm hover:bg-primary/10 transition-colors"
            >
              Change Password
            </button>
          ) : (
            <form onSubmit={handlePasswordChange} className="space-y-4 max-w-md">
              {passwordError && (
                <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 p-3 rounded-lg text-sm">
                  {passwordError}
                </div>
              )}

              <div>
                <label className="block text-sm text-slate-500 dark:text-slate-400 mb-1">Current Password</label>
                <input
                  type="password"
                  value={passwordForm.current_password}
                  onChange={(e) => setPasswordForm({ ...passwordForm, current_password: e.target.value })}
                  className="w-full bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white px-4 py-2 rounded-lg border border-light-border dark:border-dark-border focus:ring-2 focus:ring-primary focus:border-primary"
                  required
                />
              </div>

              <div>
                <label className="block text-sm text-slate-500 dark:text-slate-400 mb-1">New Password</label>
                <input
                  type="password"
                  value={passwordForm.new_password}
                  onChange={(e) => setPasswordForm({ ...passwordForm, new_password: e.target.value })}
                  className="w-full bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white px-4 py-2 rounded-lg border border-light-border dark:border-dark-border focus:ring-2 focus:ring-primary focus:border-primary"
                  required
                  minLength={8}
                />
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Minimum 8 characters</p>
              </div>

              <div>
                <label className="block text-sm text-slate-500 dark:text-slate-400 mb-1">Confirm New Password</label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white px-4 py-2 rounded-lg border border-light-border dark:border-dark-border focus:ring-2 focus:ring-primary focus:border-primary"
                  required
                />
              </div>

              <div className="flex gap-3">
                <button
                  type="button"
                  onClick={() => {
                    setShowPasswordForm(false);
                    setPasswordForm({ current_password: '', new_password: '' });
                    setConfirmPassword('');
                    setPasswordError('');
                  }}
                  className="px-4 py-2 bg-light-hover dark:bg-dark-hover text-slate-900 dark:text-white rounded-lg text-sm transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={changingPassword}
                  className="px-4 py-2 bg-primary hover:bg-primary-dark text-white rounded-lg text-sm disabled:opacity-50 transition-colors"
                >
                  {changingPassword ? 'Changing...' : 'Change Password'}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </PortalLayout>
  );
}
