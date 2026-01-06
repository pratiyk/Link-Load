import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Layout from '../components/Layout';
import '../styles/capability.css';
import { useAuth } from '../context/AuthContext';

const CloudSecurityPosture = () => {
    const { isAuthenticated, loading } = useAuth();
    const navigate = useNavigate();
    const destination = '/capabilities/cloud-security-posture';

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
                    <header className="capability-hero capability-hero--coral">
                        <span className="capability-hero__badge">Module</span>
                        <h1 className="capability-hero__title">Cloud Security Posture</h1>
                        <p className="capability-hero__lead">
                            Continuously audit AWS, Azure, and Google Cloud to surface misconfigurations, privilege drift, and compliance gaps across every account.
                        </p>
                    </header>

                    <section className="capability-overview">
                        <div className="capability-panel">
                            <h2 className="capability-panel__title">Control Families</h2>
                            <p className="capability-panel__text">
                                Automated policies benchmarked against CIS, NIST, and cloud provider best practices keep infrastructure defensible.
                            </p>
                            <ul className="capability-checklist">
                                <li>Identity and access management posture</li>
                                <li>Network exposure including internet facing services</li>
                                <li>Data protection: encryption at rest and in transit</li>
                                <li>Logging, monitoring, and detective controls</li>
                                <li>Cost-aware tagging and asset ownership coverage</li>
                            </ul>
                        </div>

                        <div className="capability-panel capability-panel--accent">
                            <h2 className="capability-panel__title">Asset Inventory</h2>
                            <p className="capability-panel__text">
                                Link&Load builds a time series inventory of resources, detects drift, and highlights changes that bypass infrastructure as code pipelines.
                            </p>
                            <div className="capability-card__list">
                                <ul>
                                    <li>Unified view across accounts, regions, and providers</li>
                                    <li>Automatic tagging of critical data stores and production workloads</li>
                                    <li>Change detection alerts with before and after snapshots</li>
                                    <li>Lifecycle policies to flag orphaned or abandoned assets</li>
                                </ul>
                            </div>
                        </div>
                    </section>

                    <section className="capability-grid">
                        <div className="capability-card">
                            <h3 className="capability-card__title">Real-Time Guardrails</h3>
                            <p className="capability-card__body">
                                Event driven checks run seconds after configuration changes, blocking risky updates and opening incidents with contextual guidance.
                            </p>
                        </div>
                        <div className="capability-card">
                            <h3 className="capability-card__title">Compliance Console</h3>
                            <p className="capability-card__body">
                                Track readiness for SOC 2, ISO 27001, PCI-DSS, and HIPAA with control level status, evidence links, and executive scorecards.
                            </p>
                        </div>
                        <div className="capability-card">
                            <h3 className="capability-card__title">Risk Prioritisation</h3>
                            <p className="capability-card__body">
                                Combine exploitability, blast radius, and business context to focus teams on the misconfigurations that matter most.
                            </p>
                        </div>
                    </section>

                    <section className="capability-meta">
                        <div className="capability-meta__item">
                            <span className="capability-meta__label">Supported Providers</span>
                            <span className="capability-meta__value">AWS, Azure, Google Cloud</span>
                        </div>
                        <div className="capability-meta__item">
                            <span className="capability-meta__label">Scan Frequency</span>
                            <span className="capability-meta__value">Continuous change monitoring with scheduled deep scans</span>
                        </div>
                        <div className="capability-meta__item">
                            <span className="capability-meta__label">Integrations</span>
                            <span className="capability-meta__value">Slack, Microsoft Teams, Jira, ServiceNow, Splunk</span>
                        </div>
                    </section>

                    <section className="capability-callout">
                        <h2 className="capability-callout__title">Next Steps</h2>
                        <ol className="capability-steps">
                            <li>Connect cloud accounts using read-only roles generated by the setup wizard.</li>
                            <li>Enable guardrails for production environments and assign response owners.</li>
                            <li>Schedule executive posture reports and route high risk findings to ticketing systems.</li>
                        </ol>
                    </section>
                </div>
            </div>
        </Layout>
    );
};

export default CloudSecurityPosture;
