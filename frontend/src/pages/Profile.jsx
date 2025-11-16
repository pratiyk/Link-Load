import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import Layout from '../components/Layout';
import { User, Mail, Lock, CheckCircle, AlertCircle, Globe } from 'lucide-react';
import domainService from '../services/domainService';
import './Profile.css';

const Profile = () => {
  const navigate = useNavigate();
  const { user, updateProfile, changePassword } = useAuth();
  const [name, setName] = useState(user?.name || '');
  const [email, setEmail] = useState(user?.email || '');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [verifiedSites, setVerifiedSites] = useState([]);
  const [loadingSites, setLoadingSites] = useState(true);

  useEffect(() => {
    loadVerifiedSites();
  }, []);

  const loadVerifiedSites = async () => {
    try {
      setLoadingSites(true);
      const profile = await domainService.fetchVerificationProfile();
      const verified = (profile.domains || []).filter(d => d.status === 'verified');
      setVerifiedSites(verified);
    } catch (err) {
      console.error('Failed to load verified sites:', err);
    } finally {
      setLoadingSites(false);
    }
  };

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
    <Layout>
      <div className="profile-container">
        {/* Header */}
        <div className="profile-header">
          <div className="header-content">
            <h1>Profile Settings</h1>
            <button
              onClick={() => navigate('/')}
              className="back-button"
            >
              ← Back to Home
            </button>
          </div>
          <p className="profile-subtitle">Manage your account information, security settings, and verified sites</p>
        </div>

        {/* Alerts */}
        {error && (
          <div className="profile-feedback profile-feedback--error">
            <AlertCircle size={18} />
            <span>{error}</span>
          </div>
        )}

        {success && (
          <div className="profile-feedback profile-feedback--success">
            <CheckCircle size={18} />
            <span>{success}</span>
          </div>
        )}

        {/* Main Content Grid */}
        <div className="profile-grid">
          {/* Update Profile Card */}
          <div className="profile-panel">
            <div className="profile-panel__header profile-panel__header--blue">
              <h2>
                <User size={20} style={{ marginRight: '0.5rem' }} />
                Update Profile
              </h2>
            </div>
            <div className="profile-panel__body">
              <form onSubmit={handleProfileUpdate}>
                <div className="profile-form__group">
                  <label className="profile-form__label">Full Name</label>
                  <input
                    type="text"
                    className="profile-form__input"
                    placeholder="Your name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    required
                  />
                </div>

                <div className="profile-form__group">
                  <label className="profile-form__label">Email Address</label>
                  <input
                    type="email"
                    className="profile-form__input"
                    placeholder="you@example.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                  />
                </div>

                <button
                  type="submit"
                  className="profile-button profile-button--primary"
                  disabled={loading}
                >
                  {loading ? 'Updating...' : 'Update Profile'}
                </button>
              </form>
            </div>
          </div>

          {/* Change Password Card */}
          <div className="profile-panel">
            <div className="profile-panel__header profile-panel__header--pink">
              <h2>
                <Lock size={20} style={{ marginRight: '0.5rem' }} />
                Change Password
              </h2>
            </div>
            <div className="profile-panel__body">
              <form onSubmit={handlePasswordChange}>
                <div className="profile-form__group">
                  <label className="profile-form__label">Current Password</label>
                  <input
                    type="password"
                    className="profile-form__input"
                    placeholder="••••••••"
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    required
                  />
                </div>

                <div className="profile-form__group">
                  <label className="profile-form__label">New Password</label>
                  <input
                    type="password"
                    className="profile-form__input"
                    placeholder="••••••••"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    required
                  />
                </div>

                <div className="profile-form__group">
                  <label className="profile-form__label">Confirm New Password</label>
                  <input
                    type="password"
                    className="profile-form__input"
                    placeholder="••••••••"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    required
                  />
                </div>

                <button
                  type="submit"
                  className="profile-button profile-button--primary"
                  disabled={loading}
                >
                  {loading ? 'Changing...' : 'Change Password'}
                </button>
              </form>
            </div>
          </div>
        </div>

        {/* Verified Sites Section */}
        <div className="profile-panel profile-panel--full">
          <div className="profile-panel__header profile-panel__header--green">
            <h2>
              <Globe size={20} style={{ marginRight: '0.5rem' }} />
              Verified Sites
            </h2>
          </div>
          <div className="profile-panel__body">
            {loadingSites ? (
              <div className="profile-loading">
                <div className="loader"></div>
                <p>Loading verified sites...</p>
              </div>
            ) : verifiedSites.length === 0 ? (
              <div className="profile-empty">
                <p>No verified sites yet.</p>
                <p style={{ fontSize: '0.9rem', color: '#666' }}>
                  Add and verify sites on the <a href="/settings/verification">DNS verification page</a>
                </p>
              </div>
            ) : (
              <div className="profile-sites-grid">
                {verifiedSites.map((site) => (
                  <div key={site.domain} className="profile-site-card">
                    <div className="profile-site-card__header">
                      <Globe size={18} />
                      <h3>{site.domain}</h3>
                    </div>
                    <div className="profile-site-card__body">
                      <p className="profile-site-status">
                        <CheckCircle size={14} />
                        Verified
                      </p>
                      {site.verified_at && (
                        <p className="profile-site-date">
                          Verified: {new Date(site.verified_at).toLocaleDateString()}
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
};

export default Profile;