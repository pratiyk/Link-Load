import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { User, Mail, Lock, CheckCircle, AlertCircle } from 'lucide-react';

const Profile = () => {
  const { user, updateProfile, changePassword } = useAuth();
  const [name, setName] = useState(user?.name || '');
  const [email, setEmail] = useState(user?.email || '');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleProfileUpdate = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);
    
    try {
      const result = await updateProfile({ name, email });
      if (result.success) {
        setSuccess('Profile updated successfully');
      }
    } catch (err) {
      setError(err.message || 'Update failed');
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      setError("Passwords don't match");
      return;
    }
    
    setError('');
    setSuccess('');
    setLoading(true);
    
    try {
      const result = await changePassword(currentPassword, newPassword);
      if (result.success) {
        setSuccess('Password changed successfully');
        // Clear password fields
        setCurrentPassword('');
        setNewPassword('');
        setConfirmPassword('');
      }
    } catch (err) {
      setError(err.message || 'Password change failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: '800px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: 'var(--spacing-6)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-3)', marginBottom: 'var(--spacing-3)' }}>
          <div style={{
            width: '48px',
            height: '48px',
            borderRadius: 'var(--radius-lg)',
            background: 'linear-gradient(135deg, var(--color-accent) 0%, #3a6a03 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 4px 12px rgba(71, 133, 4, 0.2)'
          }}>
            <User size={24} color="white" />
          </div>
          <div>
            <h1 style={{ 
              fontSize: 'var(--font-size-2xl)',
              fontWeight: 'var(--font-weight-bold)',
              marginBottom: 'var(--spacing-1)'
            }}>
              Profile Settings
            </h1>
            <p style={{ color: 'var(--color-text-secondary)', fontSize: 'var(--font-size-sm)' }}>
              Manage your account information and security settings
            </p>
          </div>
        </div>
      </div>

      {/* Alerts */}
      {error && (
        <div style={{
          padding: 'var(--spacing-3)',
          borderRadius: 'var(--radius-md)',
          backgroundColor: '#FEE2E2',
          border: '1px solid #FCA5A5',
          marginBottom: 'var(--spacing-4)',
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--spacing-2)'
        }}>
          <AlertCircle size={18} color="#DC2626" />
          <span style={{ color: '#DC2626', fontSize: 'var(--font-size-sm)' }}>
            {error}
          </span>
        </div>
      )}

      {success && (
        <div style={{
          padding: 'var(--spacing-3)',
          borderRadius: 'var(--radius-md)',
          backgroundColor: '#D1FAE5',
          border: '1px solid #6EE7B7',
          marginBottom: 'var(--spacing-4)',
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--spacing-2)'
        }}>
          <CheckCircle size={18} color="#059669" />
          <span style={{ color: '#059669', fontSize: 'var(--font-size-sm)' }}>
            {success}
          </span>
        </div>
      )}
      
      {/* Update Profile Card */}
      <div className="card" style={{ marginBottom: 'var(--spacing-6)' }}>
        <h3 style={{ 
          fontSize: 'var(--font-size-xl)',
          fontWeight: 'var(--font-weight-semibold)',
          marginBottom: 'var(--spacing-4)',
          paddingBottom: 'var(--spacing-4)',
          borderBottom: '1px solid var(--color-border)',
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--spacing-2)'
        }}>
          <User size={20} />
          Update Profile
        </h3>
        
        <form onSubmit={handleProfileUpdate}>
          <div style={{ marginBottom: 'var(--spacing-4)' }}>
            <label className="input-label">
              <User size={16} style={{ marginRight: 'var(--spacing-2)' }} />
              Full Name
            </label>
            <input 
              type="text" 
              className="input"
              placeholder="Your name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>

          <div style={{ marginBottom: 'var(--spacing-5)' }}>
            <label className="input-label">
              <Mail size={16} style={{ marginRight: 'var(--spacing-2)' }} />
              Email Address
            </label>
            <input 
              type="email" 
              className="input"
              placeholder="you@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>

          <button 
            type="submit" 
            className="btn btn-primary"
            disabled={loading}
          >
            {loading ? 'Updating...' : 'Update Profile'}
          </button>
        </form>
      </div>
      
      {/* Change Password Card */}
      <div className="card">
        <h3 style={{ 
          fontSize: 'var(--font-size-xl)',
          fontWeight: 'var(--font-weight-semibold)',
          marginBottom: 'var(--spacing-4)',
          paddingBottom: 'var(--spacing-4)',
          borderBottom: '1px solid var(--color-border)',
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--spacing-2)'
        }}>
          <Lock size={20} />
          Change Password
        </h3>
        
        <form onSubmit={handlePasswordChange}>
          <div style={{ marginBottom: 'var(--spacing-4)' }}>
            <label className="input-label">
              <Lock size={16} style={{ marginRight: 'var(--spacing-2)' }} />
              Current Password
            </label>
            <input 
              type="password" 
              className="input"
              placeholder="••••••••"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              required
            />
          </div>

          <div style={{ marginBottom: 'var(--spacing-4)' }}>
            <label className="input-label">
              <Lock size={16} style={{ marginRight: 'var(--spacing-2)' }} />
              New Password
            </label>
            <input 
              type="password" 
              className="input"
              placeholder="••••••••"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
            />
          </div>

          <div style={{ marginBottom: 'var(--spacing-5)' }}>
            <label className="input-label">
              <Lock size={16} style={{ marginRight: 'var(--spacing-2)' }} />
              Confirm New Password
            </label>
            <input 
              type="password" 
              className="input"
              placeholder="••••••••"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
            />
          </div>

          <button 
            type="submit" 
            className="btn btn-primary"
            disabled={loading}
          >
            {loading ? 'Changing...' : 'Change Password'}
          </button>
        </form>
      </div>
    </div>
  );
};

export default Profile;