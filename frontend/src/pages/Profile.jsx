import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import Layout from '../components/Layout';
import { Eye, EyeOff } from 'lucide-react';
import domainService from '../services/domainService';
import scannerService from '../services/scannerService';
import './Profile.css';

const Profile = () => {
  const navigate = useNavigate();
  const { user, updateProfile, changePassword } = useAuth();

  // Tab state
  const [activeTab, setActiveTab] = useState('command');

  // Account form state
  const [name, setName] = useState(user?.name || user?.full_name || '');
  const [email, setEmail] = useState(user?.email || '');

  // Password form state
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);

  // UI state
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Data state
  const [verifiedSites, setVerifiedSites] = useState([]);
  const [loadingSites, setLoadingSites] = useState(true);
  const [scans, setScans] = useState([]);
  const [loadingScans, setLoadingScans] = useState(true);

  useEffect(() => {
    loadVerifiedSites();
    loadUserScans();
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

  const loadUserScans = async () => {
    try {
      setLoadingScans(true);
      const response = await scannerService.listScans(0, 100, null);
      setScans(response.scans || []);
    } catch (err) {
      console.error('Failed to load user scans:', err);
    } finally {
      setLoadingScans(false);
    }
  };

  // Compute mission stats from scans
  const missionStats = useMemo(() => {
    if (!scans.length) {
      return {
        totalMissions: 0,
        completedMissions: 0,
        activeMissions: 0,
        totalThreats: 0,
        criticalThreats: 0,
        highThreats: 0,
        mediumThreats: 0,
        lowThreats: 0,
        avgThreatLevel: 0,
        uniqueTargets: 0,
        missionsByMonth: [],
        recentMissions: []
      };
    }

    const completed = scans.filter(s => s.status === 'completed');
    const active = scans.filter(s => s.status === 'in_progress' || s.status === 'pending');

    let totalThreats = 0;
    let criticalThreats = 0;
    let highThreats = 0;
    let mediumThreats = 0;
    let lowThreats = 0;
    let totalRisk = 0;
    let riskCount = 0;

    completed.forEach(scan => {
      const vulnCount = scan.vulnerability_count || scan.findings_count || 0;
      totalThreats += vulnCount;
      criticalThreats += scan.critical_count || 0;
      highThreats += scan.high_count || 0;
      mediumThreats += scan.medium_count || 0;
      lowThreats += scan.low_count || 0;

      if (scan.risk_score || scan.overall_risk_score) {
        totalRisk += parseFloat(scan.risk_score || scan.overall_risk_score || 0);
        riskCount++;
      }
    });

    const uniqueTargets = new Set(scans.map(s => s.target_url)).size;

    // Get missions by month (last 6 months)
    const missionsByMonth = [];
    const now = new Date();
    for (let i = 5; i >= 0; i--) {
      const monthDate = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const monthName = monthDate.toLocaleString('default', { month: 'short' });
      const monthScans = scans.filter(s => {
        const scanDate = new Date(s.created_at || s.started_at);
        return scanDate.getMonth() === monthDate.getMonth() &&
          scanDate.getFullYear() === monthDate.getFullYear();
      });
      missionsByMonth.push({ month: monthName, count: monthScans.length });
    }

    // Get recent missions (last 5)
    const recentMissions = scans
      .sort((a, b) => new Date(b.created_at || b.started_at) - new Date(a.created_at || a.started_at))
      .slice(0, 5);

    return {
      totalMissions: scans.length,
      completedMissions: completed.length,
      activeMissions: active.length,
      totalThreats,
      criticalThreats,
      highThreats,
      mediumThreats,
      lowThreats,
      avgThreatLevel: riskCount > 0 ? (totalRisk / riskCount).toFixed(1) : 0,
      uniqueTargets,
      missionsByMonth,
      recentMissions
    };
  }, [scans]);

  // Operator status
  const operatorStatus = useMemo(() => {
    const accountAge = user?.created_at
      ? Math.floor((new Date() - new Date(user.created_at)) / (1000 * 60 * 60 * 24))
      : 0;

    return {
      accountAge,
      lastActive: user?.last_login ? new Date(user.last_login).toLocaleString() : 'First deployment',
      clearanceLevel: user?.is_verified ? 'VERIFIED' : 'PENDING',
      operationalStatus: user?.is_active !== false ? 'ACTIVE' : 'INACTIVE',
      securedZones: verifiedSites.length
    };
  }, [user, verifiedSites]);

  const heroStats = useMemo(() => ([
    {
      id: 'clearance',
      label: 'Clearance',
      value: operatorStatus.clearanceLevel || 'PENDING',
      detail: operatorStatus.operationalStatus === 'ACTIVE' ? 'Account active' : 'Account inactive',
      tone: 'cyan'
    },
    {
      id: 'active',
      label: 'Active Missions',
      value: missionStats.activeMissions || 0,
      detail: 'Running scans',
      tone: 'yellow'
    },
    {
      id: 'completed',
      label: 'Completed',
      value: missionStats.completedMissions || 0,
      detail: 'Closed operations',
      tone: 'green'
    },
    {
      id: 'zones',
      label: 'Verified Zones',
      value: operatorStatus.securedZones || 0,
      detail: 'Domains secured',
      tone: 'pink'
    },
    {
      id: 'risk',
      label: 'Avg Risk',
      value: missionStats.avgThreatLevel || 0,
      detail: '/10 threat index',
      tone: 'coral'
    }
  ]), [operatorStatus, missionStats]);

  const heroIntel = useMemo(() => {
    const monthsTracked = missionStats.missionsByMonth.length || 1;
    const missionTempo = missionStats.missionsByMonth.reduce((sum, item) => sum + item.count, 0) / monthsTracked;
    const threatDensity = missionStats.totalMissions ? Math.round(missionStats.totalThreats / missionStats.totalMissions) : 0;
    const completionRate = missionStats.totalMissions
      ? Math.round((missionStats.completedMissions / missionStats.totalMissions) * 100)
      : 0;

    return [
      {
        id: 'tempo',
        label: 'Mission Tempo',
        value: `${missionTempo.toFixed(1)}/mo`,
        caption: 'Avg scans per month'
      },
      {
        id: 'density',
        label: 'Threat Density',
        value: threatDensity,
        caption: 'Issues per scan'
      },
      {
        id: 'completion',
        label: 'Completion Rate',
        value: `${completionRate}%`,
        caption: 'Missions closed'
      }
    ];
  }, [missionStats]);

  const latestMission = useMemo(() => missionStats.recentMissions?.[0] || null, [missionStats]);
  const formatMissionStatus = (status = '') => status.replace(/_/g, ' ').toUpperCase();

  const handleProfileUpdate = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);

    try {
      const payload = {
        full_name: name?.trim() || '',
        email: email?.trim().toLowerCase()
      };
      const result = await updateProfile(payload);
      if (result.success) {
        setSuccess('Profile updated successfully');
      }
    } catch (err) {
      const message = typeof err === 'string' ? err : err?.message || 'Update failed';
      setError(message);
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
        setCurrentPassword('');
        setNewPassword('');
        setConfirmPassword('');
      }
    } catch (err) {
      const message = typeof err === 'string' ? err : err?.message || 'Password change failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const tabs = [
    { id: 'command', label: 'Account', color: 'cyan' },
    { id: 'security', label: 'Security', color: 'coral' },
    { id: 'intel', label: 'Analytics', color: 'green' },
    { id: 'zones', label: 'Verified Sites', color: 'yellow' }
  ];

  // Command Center Tab - Operator Profile & Stats
  const renderCommandTab = () => (
    <div className="profile-tab-content">
      {/* Overview Stats */}
      <div className="stats-overview-grid">
        <div className="stat-overview-card cyan-bg">
          <div className="stat-number">{missionStats.totalMissions}</div>
          <h3 className="stat-title">Total Scans</h3>
          <p className="stat-desc">Security scans executed</p>
        </div>
        <div className="stat-overview-card green-bg">
          <div className="stat-number">{missionStats.completedMissions}</div>
          <h3 className="stat-title">Completed</h3>
          <p className="stat-desc">Successfully finished scans</p>
        </div>
        <div className="stat-overview-card coral-bg">
          <div className="stat-number">{missionStats.totalThreats}</div>
          <h3 className="stat-title">Vulnerabilities</h3>
          <p className="stat-desc">Security issues identified</p>
        </div>
        <div className="stat-overview-card yellow-bg">
          <div className="stat-number">{missionStats.uniqueTargets}</div>
          <h3 className="stat-title">Unique Domains</h3>
          <p className="stat-desc">Domains analyzed</p>
        </div>
      </div>

      <div className="profile-grid">
        {/* Account Details */}
        <div className="profile-panel">
          <div className="profile-panel__header profile-panel__header--cyan">
            <h2>Account Details</h2>
          </div>
          <div className="profile-panel__body">
            <form onSubmit={handleProfileUpdate}>
              <div className="profile-form__group">
                <label className="profile-form__label">Name</label>
                <input
                  type="text"
                  className="profile-form__input"
                  placeholder="Enter your name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                />
              </div>

              <div className="profile-form__group">
                <label className="profile-form__label">Email</label>
                <input
                  type="email"
                  className="profile-form__input"
                  placeholder="you@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>

              <div className="profile-form__group">
                <label className="profile-form__label">Username</label>
                <input
                  type="text"
                  className="profile-form__input"
                  value={user?.username || 'N/A'}
                  disabled
                />
                <span className="profile-form__hint">Username cannot be changed</span>
              </div>

              <button
                type="submit"
                className="profile-button profile-button--primary"
                disabled={loading}
              >
                {loading ? 'Updating...' : 'Update Credentials'}
              </button>
            </form>
          </div>
        </div>

        {/* Account Status */}
        <div className="profile-panel">
          <div className="profile-panel__header profile-panel__header--pink">
            <h2>Account Status</h2>
          </div>
          <div className="profile-panel__body">
            <div className="status-grid">
              <div className="status-item">
                <span className="status-label">Member Since</span>
                <span className="status-value">
                  {user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'}
                </span>
              </div>
              <div className="status-item">
                <span className="status-label">Account Age</span>
                <span className="status-value">{operatorStatus.accountAge} days</span>
              </div>
              <div className="status-item">
                <span className="status-label">Last Active</span>
                <span className="status-value">{operatorStatus.lastActive}</span>
              </div>
              <div className="status-item">
                <span className="status-label">Account Status</span>
                <span className={`status-badge ${operatorStatus.operationalStatus === 'ACTIVE' ? 'badge--active' : 'badge--inactive'}`}>
                  {operatorStatus.operationalStatus}
                </span>
              </div>
              <div className="status-item">
                <span className="status-label">Email Status</span>
                <span className={`status-badge ${operatorStatus.clearanceLevel === 'VERIFIED' ? 'badge--verified' : 'badge--pending'}`}>
                  {operatorStatus.clearanceLevel}
                </span>
              </div>
              <div className="status-item">
                <span className="status-label">Verified Sites</span>
                <span className="status-value">{operatorStatus.securedZones}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  // Access Control Tab - Security Settings
  const renderSecurityTab = () => (
    <div className="profile-tab-content">
      <div className="profile-grid">
        {/* Change Password */}
        <div className="profile-panel">
          <div className="profile-panel__header profile-panel__header--coral">
            <h2>Change Password</h2>
          </div>
          <div className="profile-panel__body">
            <form onSubmit={handlePasswordChange}>
              <div className="profile-form__group">
                <label className="profile-form__label">Current Password</label>
                <div className="profile-form__input-wrapper">
                  <input
                    type={showCurrentPassword ? 'text' : 'password'}
                    className="profile-form__input"
                    placeholder="Enter current password"
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    required
                  />
                  <button
                    type="button"
                    className="profile-form__toggle"
                    onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                  >
                    {showCurrentPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
              </div>

              <div className="profile-form__group">
                <label className="profile-form__label">New Password</label>
                <div className="profile-form__input-wrapper">
                  <input
                    type={showNewPassword ? 'text' : 'password'}
                    className="profile-form__input"
                    placeholder="Enter new password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    required
                  />
                  <button
                    type="button"
                    className="profile-form__toggle"
                    onClick={() => setShowNewPassword(!showNewPassword)}
                  >
                    {showNewPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
                <span className="profile-form__hint">
                  Min 12 chars with uppercase, lowercase, number, special char
                </span>
              </div>

              <div className="profile-form__group">
                <label className="profile-form__label">Confirm New Password</label>
                <input
                  type="password"
                  className="profile-form__input"
                  placeholder="Confirm new password"
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
                {loading ? 'Updating...' : 'Change Password'}
              </button>
            </form>
          </div>
        </div>

        {/* Security Checklist */}
        <div className="profile-panel">
          <div className="profile-panel__header profile-panel__header--green">
            <h2>Security Checklist</h2>
          </div>
          <div className="profile-panel__body">
            <div className="clearance-list">
              <div className={`clearance-item ${operatorStatus.clearanceLevel === 'VERIFIED' ? 'clearance--ok' : 'clearance--warning'}`}>
                <div className="clearance-content">
                  <span className="clearance-title">Email Verified</span>
                  <span className="clearance-status">
                    {operatorStatus.clearanceLevel === 'VERIFIED' ? 'Verified' : 'Pending verification'}
                  </span>
                </div>
              </div>

              <div className="clearance-item clearance--ok">
                <div className="clearance-content">
                  <span className="clearance-title">Password Strength</span>
                  <span className="clearance-status">Strong</span>
                </div>
              </div>

              <div className="clearance-item clearance--warning">
                <div className="clearance-content">
                  <span className="clearance-title">Two-Factor Auth</span>
                  <span className="clearance-status">Not enabled</span>
                </div>
              </div>

              <div className={`clearance-item ${operatorStatus.operationalStatus === 'ACTIVE' ? 'clearance--ok' : 'clearance--warning'}`}>
                <div className="clearance-content">
                  <span className="clearance-title">Account Status</span>
                  <span className="clearance-status">{operatorStatus.operationalStatus}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  // Mission Intel Tab - Analytics
  const renderIntelTab = () => (
    <div className="profile-tab-content">
      {/* Vulnerability Breakdown */}
      <div className="profile-panel profile-panel--full">
        <div className="profile-panel__header profile-panel__header--coral">
          <h2>Vulnerability Breakdown</h2>
          <div className="header-badge">{missionStats.totalThreats}</div>
        </div>
        <div className="profile-panel__body">
          <div className="threat-distribution">
            <div className="threat-row">
              <div className="threat-label">
                <span className="threat-indicator threat--critical"></span>
                Critical
              </div>
              <div className="threat-bar-track">
                <div
                  className="threat-bar-fill threat-fill--critical"
                  style={{ width: `${missionStats.totalThreats ? (missionStats.criticalThreats / missionStats.totalThreats * 100) : 0}%` }}
                ></div>
              </div>
              <span className="threat-count">{missionStats.criticalThreats}</span>
            </div>

            <div className="threat-row">
              <div className="threat-label">
                <span className="threat-indicator threat--high"></span>
                High
              </div>
              <div className="threat-bar-track">
                <div
                  className="threat-bar-fill threat-fill--high"
                  style={{ width: `${missionStats.totalThreats ? (missionStats.highThreats / missionStats.totalThreats * 100) : 0}%` }}
                ></div>
              </div>
              <span className="threat-count">{missionStats.highThreats}</span>
            </div>

            <div className="threat-row">
              <div className="threat-label">
                <span className="threat-indicator threat--medium"></span>
                Medium
              </div>
              <div className="threat-bar-track">
                <div
                  className="threat-bar-fill threat-fill--medium"
                  style={{ width: `${missionStats.totalThreats ? (missionStats.mediumThreats / missionStats.totalThreats * 100) : 0}%` }}
                ></div>
              </div>
              <span className="threat-count">{missionStats.mediumThreats}</span>
            </div>

            <div className="threat-row">
              <div className="threat-label">
                <span className="threat-indicator threat--low"></span>
                Low
              </div>
              <div className="threat-bar-track">
                <div
                  className="threat-bar-fill threat-fill--low"
                  style={{ width: `${missionStats.totalThreats ? (missionStats.lowThreats / missionStats.totalThreats * 100) : 0}%` }}
                ></div>
              </div>
              <span className="threat-count">{missionStats.lowThreats}</span>
            </div>
          </div>

          <div className="threat-summary">
            <span>Average Risk Score: <strong>{missionStats.avgThreatLevel}/10</strong></span>
          </div>
        </div>
      </div>

      {/* Scan Activity */}
      <div className="profile-panel profile-panel--full">
        <div className="profile-panel__header profile-panel__header--green">
          <h2>Scan Activity</h2>
        </div>
        <div className="profile-panel__body">
          <div className="activity-chart">
            {missionStats.missionsByMonth.map((item, idx) => (
              <div key={idx} className="activity-column">
                <div className="activity-bar-wrapper">
                  <div
                    className="activity-bar-fill"
                    style={{
                      height: `${Math.max(missionStats.missionsByMonth.reduce((max, i) => Math.max(max, i.count), 1) > 0
                        ? (item.count / Math.max(...missionStats.missionsByMonth.map(i => i.count), 1) * 100)
                        : 0, item.count > 0 ? 10 : 0)}%`
                    }}
                  ></div>
                </div>
                <span className="activity-month">{item.month}</span>
                <span className="activity-count">{item.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Scans */}
      <div className="profile-panel profile-panel--full">
        <div className="profile-panel__header profile-panel__header--yellow">
          <h2>Recent Scans</h2>
        </div>
        <div className="profile-panel__body">
          {loadingScans ? (
            <div className="profile-loading">
              <div className="loader"></div>
              <p>Loading scan data...</p>
            </div>
          ) : missionStats.recentMissions.length === 0 ? (
            <div className="profile-empty">
              <p>No scans yet. Run your first scan to see activity here.</p>
            </div>
          ) : (
            <div className="missions-list">
              {missionStats.recentMissions.map((mission, idx) => (
                <div
                  key={mission.id || idx}
                  className="mission-item"
                  onClick={() => mission.status === 'completed' && navigate(`/scan/${mission.id}`)}
                  style={{ cursor: mission.status === 'completed' ? 'pointer' : 'default' }}
                >
                  <div className="mission-info">
                    <span className="mission-target">{mission.target_url}</span>
                    <span className="mission-date">
                      {new Date(mission.created_at || mission.started_at).toLocaleDateString()}
                    </span>
                  </div>
                  <div className="mission-meta">
                    <span className={`mission-status status--${mission.status}`}>
                      {mission.status === 'completed' ? 'COMPLETE' :
                        mission.status === 'in_progress' ? 'IN PROGRESS' :
                          mission.status === 'pending' ? 'QUEUED' : 'FAILED'}
                    </span>
                    {mission.vulnerability_count !== undefined && (
                      <span className="mission-threats">
                        {mission.vulnerability_count} vulns
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );

  // Secured Zones Tab - Verified Domains
  const renderZonesTab = () => (
    <div className="profile-tab-content">
      <div className="profile-panel profile-panel--full">
        <div className="profile-panel__header profile-panel__header--green">
          <h2>Verified Sites</h2>
          <button
            className="profile-button profile-button--small"
            onClick={() => navigate('/settings/verification')}
          >
            Add Site
          </button>
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
              <p className="empty-hint">
                Verify domain ownership to enable enhanced scanning capabilities.
              </p>
              <button
                className="profile-button profile-button--primary"
                onClick={() => navigate('/settings/verification')}
                style={{ marginTop: '1rem' }}
              >
                Verify a Site
              </button>
            </div>
          ) : (
            <div className="zones-grid">
              {verifiedSites.map((site) => (
                <div key={site.domain} className="zone-card">
                  <div className="zone-card__header">
                    <h3>{site.domain}</h3>
                  </div>
                  <div className="zone-card__body">
                    <div className="zone-status">VERIFIED</div>
                    {site.verified_at && (
                      <p className="zone-date">
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
  );

  return (
    <Layout>
      <div className="profile-container">
        <header className="profile-header">
          <div className="profile-header__bar">
            <h1>Profile</h1>
            <button onClick={() => navigate('/')} className="back-button">
              Return to Base
            </button>
          </div>
        </header>

        {/* Hero */}
        <section className="profile-hero">
          <div className="profile-hero__content">
            <p className="profile-hero__kicker">Operator Console // Profile Sync</p>
            <h1>Operator Status Sheet</h1>
            <p className="profile-hero__lede">
              Keep your credentials, security posture, and mission intel synchronized with the rest of the Link&Load deck.
            </p>
            <div className="profile-hero__meta">
              <span className="profile-chip">
                Member Since {user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'}
              </span>
              <span className="profile-chip">Last Active {operatorStatus.lastActive}</span>
            </div>
            <div className="profile-hero__actions">
              <button
                type="button"
                className="profile-cta profile-cta--primary"
                onClick={() => navigate('/')}
              >
                Launch Console
              </button>
              <button
                type="button"
                className="profile-cta profile-cta--secondary"
                onClick={() => navigate('/mission-file')}
              >
                Mission File
              </button>
            </div>

            <div className="profile-hero__intel">
              <div className="intel-callout">
                <div className="intel-callout__body">
                  <span className="intel-callout__label">Latest Mission</span>
                  {latestMission ? (
                    <>
                      <div className="intel-callout__target">{latestMission.target_url || 'Unknown target'}</div>
                      <div className="intel-callout__meta">
                        <span>
                          {latestMission.created_at || latestMission.started_at
                            ? new Date(latestMission.created_at || latestMission.started_at).toLocaleString()
                            : 'Awaiting deployment'}
                        </span>
                        {typeof latestMission.vulnerability_count === 'number' && (
                          <span>• {latestMission.vulnerability_count} findings</span>
                        )}
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="intel-callout__target">No missions logged</div>
                      <p className="intel-callout__note">
                        Run your first scan to populate mission intel and threat history.
                      </p>
                    </>
                  )}
                </div>
                <div className="intel-callout__status">
                  <span className={`intel-status intel-status--${(latestMission?.status || 'pending').toLowerCase()}`}>
                    {latestMission ? formatMissionStatus(latestMission.status) : 'PENDING'}
                  </span>
                </div>
              </div>

              <div className="intel-metrics">
                {heroIntel.map((metric) => (
                  <div key={metric.id} className="intel-metric-card">
                    <span className="intel-metric__label">{metric.label}</span>
                    <span className="intel-metric__value">{metric.value}</span>
                    <span className="intel-metric__caption">{metric.caption}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <div className="profile-hero__status">
            {heroStats.map((stat) => (
              <div key={stat.id} className={`hero-stat hero-stat--${stat.tone}`}>
                <span className="hero-stat__label">{stat.label}</span>
                <span className="hero-stat__value">{stat.value}</span>
                <span className="hero-stat__detail">{stat.detail}</span>
              </div>
            ))}
          </div>
        </section>

        {/* Tabs Navigation */}
        <div className="profile-tabs-container">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              className={`profile-tab profile-tab--${tab.color} ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Alerts */}
        {error && (
          <div className="profile-feedback profile-feedback--error">
            <span>{error}</span>
          </div>
        )}

        {success && (
          <div className="profile-feedback profile-feedback--success">
            <span>{success}</span>
          </div>
        )}

        {/* Tab Content */}
        {activeTab === 'command' && renderCommandTab()}
        {activeTab === 'security' && renderSecurityTab()}
        {activeTab === 'intel' && renderIntelTab()}
        {activeTab === 'zones' && renderZonesTab()}
      </div>
    </Layout>
  );
};

export default Profile;