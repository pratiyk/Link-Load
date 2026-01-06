import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Layout from '../components/Layout';
import '../styles/capability.css';
import { useAuth } from '../context/AuthContext';

const ApiSecurity = () => {
    const { isAuthenticated, loading } = useAuth();
    const navigate = useNavigate();
    const destination = '/capabilities/api-security';

    useEffect(() => {
        if (!loading && !isAuthenticated) {
            navigate('/login', { replace: true, state: { from: destination } });
        }
    }, [loading, isAuthenticated, navigate]);

    if (loading) {
        return (
            <Layout>
                <div className="capability-page capability-page--loading">Checking access...</div>
            </Layout>
        );
    }

    if (!isAuthenticated) {
        return null;
    }

    return (
        <Layout>
            <div className="capability-page">
                <div className="capability-shell">
                    <header className="capability-hero capability-hero--blue">
                        <span className="capability-hero__badge">Module</span>
                        <h1 className="capability-hero__title">API Security Scanning</h1>
                        <p className="capability-hero__lead">
                            Continuously evaluate every REST and GraphQL endpoint for broken authentication, excessive data exposure,
                            and the critical issues highlighted in the OWASP API Security Top 10.
                        </p>
                    </header>

                    <section className="capability-overview">
                        <div className="capability-panel">
                            <h2 className="capability-panel__title">Coverage Highlights</h2>
                            <p className="capability-panel__text">
                                Automated interrogation of service definitions and live endpoints keeps your microservices safe even as new routes land in production.
                            </p>
                            <ul className="capability-checklist">
                                <li>Broken object level authorization and IDOR detection</li>
                                <li>Authentication token misuse and session fixation</li>
                                <li>Mass assignment and schema drift identification</li>
                                <li>Rate limiting, pagination, and throttling validation</li>
                                <li>Inventory of undocumented or shadow endpoints</li>
                            </ul>
                        </div>

                        <div className="capability-panel capability-panel--accent">
                            <h2 className="capability-panel__title">Workflow</h2>
                            <p className="capability-panel__text">
                                Feed Link&Load an OpenAPI/Swagger document or allow it to discover routes dynamically.
                                The engine replays critical paths with crafted payloads and stores trace evidence for remediation.
                            </p>
                            <div className="capability-card__list">
                                <ul>
                                    <li>Specification linting and schema validation</li>
                                    <li>Authenticated replay with least-privilege tokens</li>
                                    <li>Intelligent fuzzing with context-aware payloads</li>
                                    <li>AI narrative summarising exploit paths and fixes</li>
                                </ul>
                            </div>
                        </div>
                    </section>

                    <section className="capability-grid">
                        <div className="capability-card">
                            <h3 className="capability-card__title">Runtime Signals</h3>
                            <p className="capability-card__body">
                                Capture response codes, latency variations, and anomalous payload reflections to surface silent failures that slip past unit tests.
                            </p>
                        </div>
                        <div className="capability-card">
                            <h3 className="capability-card__title">Validation Packs</h3>
                            <p className="capability-card__body">
                                Targeted packs cover login flows, commerce APIs, developer portals, and partner integrations. Each pack is versioned and regression tested.
                            </p>
                        </div>
                        <div className="capability-card">
                            <h3 className="capability-card__title">Evidence Bundle</h3>
                            <p className="capability-card__body">
                                Export failing calls, payloads, replay curls, and the generated remediation plan directly to engineering workstreams.
                            </p>
                        </div>
                    </section>

                    <section className="capability-meta">
                        <div className="capability-meta__item">
                            <span className="capability-meta__label">Specification Support</span>
                            <span className="capability-meta__value">OpenAPI 2.0/3.x, Postman, GraphQL SDL</span>
                        </div>
                        <div className="capability-meta__item">
                            <span className="capability-meta__label">Execution Window</span>
                            <span className="capability-meta__value">5 – 25 minutes per service depending on depth</span>
                        </div>
                        <div className="capability-meta__item">
                            <span className="capability-meta__label">Output Formats</span>
                            <span className="capability-meta__value">PDF report, JSON export, Jira ticket payload</span>
                        </div>
                    </section>

                    <section className="capability-callout">
                        <h2 className="capability-callout__title">Next Steps</h2>
                        <ol className="capability-steps">
                            <li>Upload or link an OpenAPI specification or allow discovery by providing a seed endpoint.</li>
                            <li>Select the authentication profile (API key, OAuth 2.0, service account) to replay secured routes safely.</li>
                            <li>Review the AI summary and push failing requests to your remediation backlog with one click.</li>
                        </ol>
                    </section>
                </div>
            </div>
        </Layout>
    );
};

export default ApiSecurity;
