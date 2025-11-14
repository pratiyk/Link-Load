import React, { useMemo, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  Lock,
  Mail,
  AlertCircle
} from 'lucide-react';
import './Login.css';
import logo from '../assets/logo.png';
import { isSupabaseConfigured } from '../services/supabaseClient';

const isTrustedLocalhost = (hostname) => {
  const normalized = (hostname || '').toLowerCase();
  if (['localhost', '127.0.0.1', '::1', '0.0.0.0'].includes(normalized)) {
    return true;
  }
  return normalized.endsWith('.localhost') || normalized.endsWith('.local') || normalized.endsWith('.test');
};

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const { login } = useAuth();
  const supabaseReady = isSupabaseConfigured;

  const isSecureContext = useMemo(() => {
    if (typeof window === 'undefined') {
      return true;
    }
    return window.location.protocol === 'https:' || isTrustedLocalhost(window.location.hostname);
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (!isSecureContext) {
        throw new Error('Switch to an HTTPS connection before signing in.');
      }
      const normalizedEmail = email.trim().toLowerCase();
      const result = await login(normalizedEmail, password);
      if (result.success) {
        navigate('/');
      } else if (result?.error) {
        setError(result.error);
      }
    } catch (err) {
      console.error('Login error:', err);
      setError(err?.message || 'Unable to sign in. Check your credentials and try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-page__frame">
        <header className="login-brand">
          <div className="login-brand__inner">
            <span className="login-brand__tab" aria-hidden="true" />
            <div className="login-brand__logo-wrap">
              <img src={logo} alt="Link&Load Logo" className="login-brand__logo" />
            </div>
            <div className="login-brand__text">
              <h1 className="login-brand__title">The War Room, Unlocked.</h1>
              <p className="login-brand__subtitle">It's the Difference Between a Mosh Pit and a SWAT Team.

              </p>
            </div>
            <span className="login-brand__chip" aria-hidden="true" />
          </div>
        </header>
        <section className="login-card">
          <div className="login-card__surface">
            <div className="login-card__header">
              <div className="login-card__badge">
                <Lock size={30} color="#000" />
              </div>
              <h1 className="login-card__title">Welcome back</h1>
              <p className="login-card__subtitle">
                Sign in. (The only vulnerability left is an empty chair.)
              </p>
            </div>

            {!isSecureContext && (
              <div className="login-alert" role="alert">
                <AlertCircle size={18} />
                <span>
                  Secure sign-in requires HTTPS. Access Link&amp;Load over an encrypted connection before entering credentials.
                </span>
              </div>
            )}

            {error && (
              <div className="login-alert" role="alert">
                <AlertCircle size={18} />
                <span>{error}</span>
              </div>
            )}

            {!supabaseReady && (
              <div className="login-alert" role="alert">
                <AlertCircle size={18} />
                <span>
                  Supabase authentication is not fully configured. Add REACT_APP_SUPABASE_URL and REACT_APP_SUPABASE_ANON_KEY to enable direct login, or rely on the legacy backend credentials.
                </span>
              </div>
            )}

            <form className="login-form" onSubmit={handleSubmit}>
              <div className="login-input-group">
                <label className="login-input-label" htmlFor="login-email">
                  <Mail size={16} />
                  Email address
                </label>
                <input
                  id="login-email"
                  type="email"
                  className="login-input"
                  placeholder="you@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value.replace(/\s+/g, ''))}
                  autoComplete="email"
                  required
                />
              </div>

              <div className="login-input-group">
                <label className="login-input-label" htmlFor="login-password">
                  <Lock size={16} />
                  Password
                </label>
                <input
                  id="login-password"
                  type="password"
                  className="login-input"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                  required
                />
              </div>

              <button
                type="submit"
                className="login-submit"
                disabled={loading || !isSecureContext}
              >
                {loading ? 'Signing in…' : 'Sign in'}
              </button>
            </form>

            <div className="login-meta">
              Don't have an account?
              <Link className="login-meta__link" to="/register">
                Create one now
              </Link>
            </div>

            <div className="login-note">
              Need to verify a domain? Sign in first, then open the
              {' '}
              <Link to="/settings/verification" className="login-note__link">
                DNS Verification
              </Link>
              {' '}workspace from the navigation.
            </div>
          </div>
        </section>
      </div>
    </div>
  );
};

export default Login;