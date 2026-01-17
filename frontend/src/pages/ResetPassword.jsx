import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import Layout from '../components/Layout';
import {
    Lock,
    AlertCircle,
    CheckCircle
} from 'lucide-react';
import './Login.css';
import logo from '../assets/logo.png';

const ResetPassword = () => {
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState(false);
    const [searchParams] = useSearchParams();
    const navigate = useNavigate();

    const token = searchParams.get('token');

    useEffect(() => {
        if (!token) {
            setError('Invalid or missing reset token. Please request a new password reset link.');
        }
    }, [token]);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');

        if (password !== confirmPassword) {
            setError('Passwords do not match');
            return;
        }

        if (password.length < 8) {
            setError('Password must be at least 8 characters long');
            return;
        }

        setLoading(true);

        try {
            const response = await fetch(`${process.env.REACT_APP_API_URL || 'http://localhost:8000'}/api/v1/auth/reset-password`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    token,
                    new_password: password
                }),
            });

            if (!response.ok) {
                const data = await response.json();
                throw new Error(data.detail || 'Failed to reset password');
            }

            setSuccess(true);

            // Redirect to login after 3 seconds
            setTimeout(() => {
                navigate('/login');
            }, 3000);
        } catch (err) {
            console.error('Reset password error:', err);
            setError(err?.message || 'Unable to reset password. Please try again or request a new reset link.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <Layout>
            <div className="login-page">
                <div className="login-page__frame">
                    <header className="login-brand">
                        <div className="login-brand__inner">
                            <span className="login-brand__tab" aria-hidden="true" />
                            <div className="login-brand__logo-wrap">
                                <img src={logo} alt="Link&Load Logo" className="login-brand__logo" />
                            </div>
                            <div className="login-brand__text">
                                <h1 className="login-brand__title">Create New Password</h1>
                                <p className="login-brand__subtitle">
                                    Choose a strong password for your account.
                                </p>
                            </div>
                            <span className="login-brand__chip" aria-hidden="true" />
                        </div>
                    </header>
                    <section className="login-card">
                        <div className="login-card__surface">
                            {!success ? (
                                <>
                                    <div className="login-card__header">
                                        <div className="login-card__badge">
                                            <Lock size={30} color="#000" />
                                        </div>
                                        <h1 className="login-card__title">Reset Password</h1>
                                        <p className="login-card__subtitle">
                                            Enter your new password below.
                                        </p>
                                    </div>

                                    {error && (
                                        <div className="login-alert" role="alert">
                                            <AlertCircle size={18} />
                                            <span>{error}</span>
                                        </div>
                                    )}

                                    <form className="login-form" onSubmit={handleSubmit}>
                                        <div className="login-input-group">
                                            <label className="login-input-label" htmlFor="new-password">
                                                <Lock size={16} />
                                                New Password
                                            </label>
                                            <input
                                                id="new-password"
                                                type="password"
                                                className="login-input"
                                                placeholder="••••••••"
                                                value={password}
                                                onChange={(e) => setPassword(e.target.value)}
                                                autoComplete="new-password"
                                                required
                                                disabled={!token}
                                            />
                                        </div>

                                        <div className="login-input-group">
                                            <label className="login-input-label" htmlFor="confirm-password">
                                                <Lock size={16} />
                                                Confirm Password
                                            </label>
                                            <input
                                                id="confirm-password"
                                                type="password"
                                                className="login-input"
                                                placeholder="••••••••"
                                                value={confirmPassword}
                                                onChange={(e) => setConfirmPassword(e.target.value)}
                                                autoComplete="new-password"
                                                required
                                                disabled={!token}
                                            />
                                        </div>

                                        <button
                                            type="submit"
                                            className="login-submit"
                                            disabled={loading || !token}
                                        >
                                            {loading ? 'Resetting...' : 'Reset Password'}
                                        </button>
                                    </form>

                                    <div className="login-meta">
                                        <Link className="login-meta__link" to="/login">
                                            Back to login
                                        </Link>
                                    </div>
                                </>
                            ) : (
                                <>
                                    <div className="login-card__header">
                                        <div className="login-card__badge login-card__badge--success">
                                            <CheckCircle size={30} color="#000" />
                                        </div>
                                        <h1 className="login-card__title">Password Reset Successful</h1>
                                        <p className="login-card__subtitle">
                                            Your password has been successfully reset. You can now log in with your new password.
                                        </p>
                                    </div>

                                    <div className="login-note" style={{ textAlign: 'center', marginTop: 'var(--spacing-4)' }}>
                                        Redirecting to login page...
                                    </div>

                                    <div className="login-meta" style={{ marginTop: 'var(--spacing-4)' }}>
                                        <Link className="login-meta__link" to="/login">
                                            Go to login
                                        </Link>
                                    </div>
                                </>
                            )}
                        </div>
                    </section>
                </div>
            </div>
        </Layout>
    );
};

export default ResetPassword;
