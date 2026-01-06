import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Layout from '../components/Layout';
import '../styles/capability.css';
import { useAuth } from '../context/AuthContext';

const SourceCodeSecurity = () => {
    const { isAuthenticated, loading } = useAuth();
    const navigate = useNavigate();
    const destination = '/capabilities/source-code-security';

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
                    <header className="capability-hero capability-hero--green">
                        <span className="capability-hero__badge">Module</span>
                        <h1 className="capability-hero__title">Source Code Security (SAST)</h1>
                        <p className="capability-hero__lead">
                            Apply static application security testing on every pull request to keep injection flaws, insecure cryptography, and secret exposure out of main.
                        </p>
                    </header>

                    <section className="capability-overview">
                        <div className="capability-panel">
                            <h2 className="capability-panel__title">Supported Stacks</h2>
                            <p className="capability-panel__text">
                                Optimised rule packs and taint tracking are ready for the languages your teams rely on.
                            </p>
                            <ul className="capability-checklist">
                                <li>Python, JavaScript/TypeScript, Go, Java, C#</li>
                                <li>Infrastructure as code policies (Terraform, CloudFormation)</li>
                                <li>Container manifests and Dockerfiles</li>
                                <li>Configuration and secret scanning across repositories</li>
                            </ul>
                        </div>

                        <div className="capability-panel capability-panel--accent">
                            <h2 className="capability-panel__title">Pipeline Integration</h2>
                            <p className="capability-panel__text">
                                Execute scans locally, in CI, or on the Link&Load build agents. Findings are deduplicated and pushed back into version control workflows.
                            </p>
                            <div className="capability-card__list">
                                <ul>
                                    <li>GitHub, GitLab, and Bitbucket checks with inline annotations</li>
                                    <li>Baseline management to suppress approved findings</li>
                                    <li>Branch protection gates tied to severity thresholds</li>
                                    <li>Pull request badges summarising compliance status</li>
                                </ul>
                            </div>
                        </div>
                    </section>

                    <section className="capability-grid">
                        <div className="capability-card">
                            <h3 className="capability-card__title">Guided Remediation</h3>
                            <p className="capability-card__body">
                                Every finding ships with language specific examples, secure library suggestions, and optional AI generated patches for review.
                            </p>
                        </div>
                        <div className="capability-card">
                            <h3 className="capability-card__title">Hotspot Tracking</h3>
                            <p className="capability-card__body">
                                Monitor critical files and functions; trigger targeted scans when sensitive areas change to minimise noise while staying protected.
                            </p>
                        </div>
                        <div className="capability-card">
                            <h3 className="capability-card__title">Compliance Mapping</h3>
                            <p className="capability-card__body">
                                Map SAST coverage directly to OWASP ASVS, PCI-DSS, and SOC 2 requirements for audit dashboards and customer reports.
                            </p>
                        </div>
                    </section>

                    <section className="capability-meta">
                        <div className="capability-meta__item">
                            <span className="capability-meta__label">Trigger Points</span>
                            <span className="capability-meta__value">Push, merge request, nightly scheduled scan</span>
                        </div>
                        <div className="capability-meta__item">
                            <span className="capability-meta__label">Median Runtime</span>
                            <span className="capability-meta__value">Under 6 minutes for typical services</span>
                        </div>
                        <div className="capability-meta__item">
                            <span className="capability-meta__label">Artifact Storage</span>
                            <span className="capability-meta__value">Encrypted SARIF, JSON, and PDF exports retained for 180 days</span>
                        </div>
                    </section>

                    <section className="capability-callout">
                        <h2 className="capability-callout__title">Next Steps</h2>
                        <ol className="capability-steps">
                            <li>Connect your repository provider and select the branches or projects to monitor.</li>
                            <li>Choose severity guardrails and configure baseline timeouts to manage technical debt.</li>
                            <li>Adopt the recommended pre-commit hooks so developers catch issues before CI runs.</li>
                        </ol>
                    </section>
                </div>
            </div>
        </Layout>
    );
};

export default SourceCodeSecurity;
