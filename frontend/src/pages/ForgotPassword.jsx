import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import Layout from '../components/Layout';
import {
    Mail,
    AlertCircle,
    CheckCircle,
    ArrowLeft
} from 'lucide-react';
import './Login.css';
import logo from '../assets/logo.png';

const ForgotPassword = () => {
    const [email, setEmail] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        try {
            const normalizedEmail = email.trim().toLowerCase();

            // TODO: Call forgot password API
            const response = await fetch(`${process.env.REACT_APP_API_URL || 'http://localhost:8000'}/api/v1/auth/forgot-password`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email: normalizedEmail }),
            });

            if (!response.ok) {
                const data = await response.json();
                throw new Error(data.detail || 'Failed to send reset email');
            }

            setSuccess(true);
        } catch (err) {
            console.error('Forgot password error:', err);
            setError(err?.message || 'Unable to process request. Please try again.');
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
                                <h1 className="login-brand__title">Reset Your Password</h1>
                                <p className="login-brand__subtitle">
                                    We'll send you instructions to reset your password.
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
                                            <Mail size={30} color="#000" />
                                        </div>
                                        <h1 className="login-card__title">Forgot Password?</h1>
                                        <p className="login-card__subtitle">
                                            Enter your email address and we'll send you a link to reset your password.
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
                                            <label className="login-input-label" htmlFor="reset-email">
                                                <Mail size={16} />
                                                Email address
                                            </label>
                                            <input
                                                id="reset-email"
                                                type="email"
                                                className="login-input"
                                                placeholder="you@example.com"
                                                value={email}
                                                onChange={(e) => setEmail(e.target.value.replace(/\s+/g, ''))}
                                                autoComplete="email"
                                                required
                                            />
                                        </div>

                                        <button
                                            type="submit"
                                            className="login-submit"
                                            disabled={loading}
                                        >
                                            {loading ? 'Sending...' : 'Send Reset Link'}
                                        </button>
                                    </form>

                                    <div className="login-meta">
                                        <Link className="login-meta__link" to="/login">
                                            <ArrowLeft size={16} style={{ marginRight: '4px' }} />
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
                                        <h1 className="login-card__title">Check Your Email</h1>
                                        <p className="login-card__subtitle">
                                            If an account exists with <strong>{email}</strong>, you'll receive a password reset link shortly.
                                        </p>
                                    </div>

                                    <div className="login-note" style={{ textAlign: 'center', marginTop: 'var(--spacing-4)' }}>
                                        Didn't receive the email? Check your spam folder or{' '}
                                        <button
                                            onClick={() => {
                                                setSuccess(false);
                                                setEmail('');
                                            }}
                                            className="login-note__link"
                                            style={{
                                                background: 'none',
                                                border: 'none',
                                                cursor: 'pointer',
                                                padding: 0,
                                                font: 'inherit'
                                            }}
                                        >
                                            try again
                                        </button>
                                        .
                                    </div>

                                    <div className="login-meta" style={{ marginTop: 'var(--spacing-4)' }}>
                                        <Link className="login-meta__link" to="/login">
                                            <ArrowLeft size={16} style={{ marginRight: '4px' }} />
                                            Back to login
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

export default ForgotPassword;
