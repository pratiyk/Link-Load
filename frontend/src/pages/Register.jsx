import React, { useMemo, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { UserPlus, Mail, Lock, Sparkles, ShieldCheck } from 'lucide-react';
import { supabase, isSupabaseConfigured } from '../services/supabaseClient';
import './Login.css';
import './Register.css';
import logo from '../assets/logo.png';

const isTrustedLocalhost = (hostname) => {
  const normalized = (hostname || '').toLowerCase();
  if (['localhost', '127.0.0.1', '::1', '0.0.0.0'].includes(normalized)) {
    return true;
  }
  return normalized.endsWith('.localhost') || normalized.endsWith('.local') || normalized.endsWith('.test');
};

const initialFormState = {
  fullName: '',
  email: '',
  password: '',
  confirmPassword: ''
};

const Register = () => {
  const [formData, setFormData] = useState(initialFormState);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const navigate = useNavigate();

  const supabaseReady = Boolean(isSupabaseConfigured && supabase);
  const isSecureContext = useMemo(() => {
    if (typeof window === 'undefined') {
      return true;
    }
    return window.location.protocol === 'https:' || isTrustedLocalhost(window.location.hostname);
  }, []);

  const handleChange = (field) => (event) => {
    setFormData((previous) => ({
      ...previous,
      [field]: event.target.value
    }));
  };

  const handleEmailChange = (event) => {
    const sanitizedValue = event.target.value.replace(/\s+/g, '');
    setFormData((previous) => ({
      ...previous,
      email: sanitizedValue
    }));
  };

  const validateForm = () => {
    const email = formData.email.trim();
    if (!email || !formData.password || !formData.confirmPassword) {
      return 'Email and password fields are required.';
    }

    if (formData.password !== formData.confirmPassword) {
      return 'Passwords do not match. Please try again.';
    }

    const password = formData.password;
    if (password.length < 12) {
      return 'Password must be at least 12 characters long.';
    }
    if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/\d/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
      return 'Choose a password with uppercase, lowercase, number, and symbol characters.';
    }

    return '';
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError('');
    setSuccess('');

    if (!supabaseReady) {
      setError('Supabase authentication is not configured. Please contact your administrator to add REACT_APP_SUPABASE_URL and REACT_APP_SUPABASE_ANON_KEY.');
      return;
    }

    const validationError = validateForm();
    if (validationError) {
      setError(validationError);
      return;
    }

    setLoading(true);

    try {
      if (!isSecureContext) {
        throw new Error('Switch to an HTTPS connection before creating an account.');
      }
      const normalizedEmail = formData.email.trim().toLowerCase();
      const normalizedFullName = formData.fullName.trim() || undefined;
      const { error: signUpError } = await supabase.auth.signUp({
        email: normalizedEmail,
        password: formData.password,
        options: {
          data: {
            full_name: normalizedFullName
          }
        }
      });

      if (signUpError) {
        throw new Error('Unable to create account. Please try again later.');
      }

      setSuccess('Registration successful! Check your inbox to confirm your email.');
      setFormData(initialFormState);

      setTimeout(() => {
        navigate('/login');
      }, 3200);
    } catch (registrationError) {
      console.error('Registration error:', registrationError);
      setError(registrationError?.message || 'Unable to complete registration right now. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page register-page">
      <div className="login-page__frame">
        <header className="login-brand">
          <div className="login-brand__inner">
            <span className="login-brand__tab" aria-hidden="true" />
            <div className="login-brand__logo-wrap">
              <img src={logo} alt="Link&Load Logo" className="login-brand__logo" />
            </div>
            <div className="login-brand__text">
              <h1 className="login-brand__title">Breaches Hate Company.</h1>
              <p className="login-brand__subtitle">
                We Don't Just Connect the Dots. We Obliterate the Threat.
              </p>
            </div>
            <span className="login-brand__chip" aria-hidden="true" />
          </div>
        </header>

        <section className="login-card register-card">
          <div className="login-card__surface">
            <div className="login-card__header">
              <div className="login-card__badge">
                <UserPlus size={30} color="#000" />
              </div>
              <h1 className="login-card__title">Create your account</h1>
              <p className="login-card__subtitle">
                We use Supabase Auth so your credentials stay encrypted end-to-end. Confirm your email to activate advanced scanning features.
              </p>
            </div>

            {!isSecureContext && (
              <div className="login-alert" role="alert" style={{ background: 'rgba(241, 86, 63, 0.12)' }}>
                <ShieldCheck size={18} />
                <span>A secure HTTPS connection is required to protect registration details. Switch to an encrypted link before continuing.</span>
              </div>
            )}

            {!supabaseReady && (
              <div className="login-alert" role="alert" style={{ background: 'rgba(241, 86, 63, 0.12)' }}>
                <ShieldCheck size={18} />
                <span>
                  Supabase credentials are missing. Add REACT_APP_SUPABASE_URL and REACT_APP_SUPABASE_ANON_KEY to enable account creation.
                </span>
              </div>
            )}

            {error && (
              <div className="login-alert" role="alert">
                <ShieldCheck size={18} />
                <span>{error}</span>
              </div>
            )}

            {success && (
              <div className="login-alert" role="status" style={{ background: 'rgba(113, 208, 140, 0.2)' }}>
                <Sparkles size={18} />
                <span>{success}</span>
              </div>
            )}

            <form className="login-form" onSubmit={handleSubmit}>
              <div className="login-input-group">
                <label className="login-input-label" htmlFor="register-fullname">
                  <UserPlus size={16} />
                  Full name (optional)
                </label>
                <input
                  id="register-fullname"
                  type="text"
                  className="login-input"
                  placeholder="Ada Lovelace"
                  value={formData.fullName}
                  onChange={handleChange('fullName')}
                  autoComplete="name"
                />
              </div>

              <div className="login-input-group">
                <label className="login-input-label" htmlFor="register-email">
                  <Mail size={16} />
                  Work email
                </label>
                <input
                  id="register-email"
                  type="email"
                  className="login-input"
                  placeholder="you@company.com"
                  value={formData.email}
                  onChange={handleEmailChange}
                  autoComplete="email"
                  required
                />
              </div>

              <div className="login-input-group">
                <label className="login-input-label" htmlFor="register-password">
                  <Lock size={16} />
                  Password
                </label>
                <input
                  id="register-password"
                  type="password"
                  className="login-input"
                  placeholder="••••••••"
                  value={formData.password}
                  onChange={handleChange('password')}
                  autoComplete="new-password"
                  required
                />
              </div>

              <div className="login-input-group">
                <label className="login-input-label" htmlFor="register-confirm-password">
                  <Lock size={16} />
                  Confirm password
                </label>
                <input
                  id="register-confirm-password"
                  type="password"
                  className="login-input"
                  placeholder="••••••••"
                  value={formData.confirmPassword}
                  onChange={handleChange('confirmPassword')}
                  autoComplete="new-password"
                  required
                />
              </div>

              <button
                type="submit"
                className="login-submit"
                disabled={loading || !supabaseReady || !isSecureContext}
                aria-disabled={!supabaseReady || loading || !isSecureContext}
                style={!supabaseReady || !isSecureContext ? { opacity: 0.5, cursor: 'not-allowed' } : undefined}
              >
                {loading ? 'Creating account…' : !isSecureContext ? 'Enable HTTPS' : supabaseReady ? 'Create account' : 'Configure Supabase'}
              </button>
            </form>

            <div className="register-password-policy">
              Passwords must be at least 12 characters long and include uppercase, lowercase, numeric, and symbol characters.
            </div>

            <div className="register-legal">
              By clicking create account you agree to the Link&amp;Load Terms of Service and acknowledge our Privacy Policy. We will never share your credentials.
            </div>

            <div className="login-meta">
              Already have an account?
              <Link className="login-meta__link" to="/login">
                Sign in instead
              </Link>
            </div>
          </div>
        </section>

        <section className="register-support">
          <div className="register-support__surface">
            <h2 className="dns-card__title">Why Supabase Auth?</h2>
            <ul className="register-benefits">
              <li>
                <ShieldCheck size={18} />
                <span>Session management with row-level security ensures your vulnerability data stays isolated per workspace.</span>
              </li>
              <li>
                <Sparkles size={18} />
                <span>Instant verification emails let teams onboard quickly while keeping malicious actors out.</span>
              </li>
              <li>
                <Mail size={18} />
                <span>Bring your own SMTP to align with corporate email policies without extra configuration.</span>
              </li>
            </ul>
            <p className="register-legal">
              After verifying your email, return to the login screen to access Link&amp;Load. Contact support if you need SSO or SCIM provisioning.
            </p>
          </div>
        </section>
      </div>
    </div>
  );
};

export default Register;