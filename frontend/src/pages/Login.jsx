import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Lock, Mail, AlertCircle } from 'lucide-react';

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const { login } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    
    try {
      const result = await login(email, password);
      if (result.success) {
        navigate('/');
      }
    } catch (err) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ 
      display: 'flex', 
      justifyContent: 'center', 
      alignItems: 'center',
      minHeight: 'calc(100vh - 70px)',
      padding: 'var(--spacing-6)'
    }}>
      <div className="card" style={{ maxWidth: '450px', width: '100%' }}>
        <div style={{ textAlign: 'center', marginBottom: 'var(--spacing-6)' }}>
          <div style={{
            width: '60px',
            height: '60px',
            borderRadius: 'var(--radius-lg)',
            background: 'linear-gradient(135deg, var(--color-accent) 0%, #3a6a03 100%)',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: 'var(--spacing-4)',
            boxShadow: '0 4px 12px rgba(71, 133, 4, 0.2)'
          }}>
            <Lock size={28} color="white" />
          </div>
          <h1 style={{ 
            fontSize: 'var(--font-size-2xl)',
            fontWeight: 'var(--font-weight-bold)',
            marginBottom: 'var(--spacing-2)'
          }}>
            Welcome Back
          </h1>
          <p style={{ 
            color: 'var(--color-text-secondary)',
            fontSize: 'var(--font-size-base)'
          }}>
            Sign in to your Link&Load account
          </p>
        </div>

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

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 'var(--spacing-4)' }}>
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

          <div style={{ marginBottom: 'var(--spacing-5)' }}>
            <label className="input-label">
              <Lock size={16} style={{ marginRight: 'var(--spacing-2)' }} />
              Password
            </label>
            <input 
              type="password" 
              className="input"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>

          <button 
            type="submit" 
            className="btn btn-primary"
            style={{ width: '100%', marginBottom: 'var(--spacing-4)' }}
            disabled={loading}
          >
            {loading ? 'Signing in...' : 'Sign In'}
          </button>

          <div style={{ 
            textAlign: 'center', 
            color: 'var(--color-text-secondary)',
            fontSize: 'var(--font-size-sm)'
          }}>
            Don't have an account?{' '}
            <a 
              href="/register"
              style={{
                color: 'var(--color-accent)',
                textDecoration: 'none',
                fontWeight: 'var(--font-weight-medium)'
              }}
            >
              Create account
            </a>
          </div>
        </form>
      </div>
    </div>
  );
};

export default Login;