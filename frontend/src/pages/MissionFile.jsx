import React from 'react';
import { useNavigate } from 'react-router-dom';
import Layout from '../components/Layout';
import '../styles/mission.css';
import logo from '../assets/logo.png';

const capabilityHighlights = [
    {
        id: 'vectors',
        title: 'Multi-Vector Scanning Array',
        description: 'OWASP ZAP, Nuclei, Wapiti, and Nikto run in parallel formation to cut recon time, blending DAST, template signatures, black-box fuzzing, and web server hardening checks.',
        badge: 'Recon Stack',
        color: 'coral'
    },
    {
        id: 'intel',
        title: 'AI Intelligence Cell',
        description: 'Groq, OpenAI, and Anthropic models analyze findings, draft mission briefs, and fallback gracefully thanks to cached summaries and heuristics.',
        badge: 'Intel Core',
        color: 'yellow'
    },
    {
        id: 'mitre',
        title: 'MITRE ATT&CK Correlation',
        description: 'Live TAXII pulls with offline cache guarantee ATT&CK technique mapping, even when the feed is dark.',
        badge: 'Attack Graph',
        color: 'green'
    },
    {
        id: 'risk',
        title: 'Risk Quant Matrix',
        description: 'CVSS, exploit intel, and business context fuse into a 0-10 risk score that powers remediation windows and ROI math.',
        badge: 'Score Engine',
        color: 'blue'
    },
    {
        id: 'telemetry',
        title: 'Real-Time Telemetry',
        description: 'WebSockets broadcast every stage, so squads watch scanners crawl, attack, and report in real time.',
        badge: 'Ops Feed',
        color: 'pink'
    }
];

const architectureLayers = [
    {
        title: 'Command Center',
        detail: 'React 18 dashboard with Tailwind styling, scan console widgets, and D3-powered intel cards.'
    },
    {
        title: 'Operations Hub',
        detail: 'FastAPI on Python 3.12 orchestrates missions, enforces rate limits, and streams WebSocket updates.'
    },
    {
        title: 'Scanner Fleet',
        detail: 'Containerized OWASP ZAP (8090), Nuclei templates, and Wapiti runners synchronized through the backend queue.'
    },
    {
        title: 'Intelligence Fusion',
        detail: 'LLM analysis, MITRE mapper, and remediation planner translate telemetry into exec-ready guidance.'
    },
    {
        title: 'Data Vault',
        detail: 'Supabase/PostgreSQL with row-level security, audit trails, and mission history retention.'
    }
];

const scannerCards = [
    {
        callSign: 'Unit 01',
        name: 'OWASP ZAP',
        description: 'Spider, AJAX crawler, auth replay, and active attack payloads for deep DAST coverage.',
        status: 'Active'
    },
    {
        callSign: 'Unit 02',
        name: 'Nuclei',
        description: '8k+ community templates for CVEs, misconfigurations, exposed panels, and sensitive services.',
        status: 'Ready'
    },
    {
        callSign: 'Unit 03',
        name: 'Wapiti',
        description: 'Black-box fuzzing, injection sweeps, and file handling probes without source access.',
        status: 'Ready'
    },
    {
        callSign: 'Unit 04',
        name: 'Nikto',
        description: 'Comprehensive web server scanner testing 6700+ dangerous files, misconfigurations, and outdated software.',
        status: 'Ready'
    }
];

const openSourceFacts = [
    {
        label: 'License',
        value: 'MIT',
        lines: ['MIT'],
        detail: 'Operate freely with attribution—perfect for red, blue, and purple teams.'
    },
    {
        label: 'Repository',
        value: 'github.com/pratiyk/Link-Load',
        lines: ['github.com/', 'pratiyk', 'Link-Load'],
        detail: 'Issues and pull requests keep the arsenal sharp.'
    },
    {
        label: 'Stack',
        value: 'FastAPI · React · Docker · Supabase',
        lines: ['FastAPI', 'React', 'Docker', 'Supabase'],
        detail: 'Python 3.12, Node 18, Tailwind, Redis, and Postgres under one roof.'
    },
    {
        label: 'Mission Docs',
        value: 'README · SECURITY · Model Cards',
        lines: ['README', 'SECURITY', 'Model Cards'],
        detail: 'Everything from deployment to intel sources is documented.'
    }
];

const missionStats = [
    {
        label: 'Status',
        value: 'OPERATIONAL',
        detail: 'Field-ready, health-checked containers.'
    },
    {
        label: 'Scanner Stack',
        value: 'ZAP · Nuclei · Wapiti · Nikto',
        detail: 'Four-unit concurrent formation compresses recon windows.'
    },
    {
        label: 'Intel Core',
        value: 'Groq + OpenAI + Anthropic',
        detail: 'LLM fallback chain plus offline MITRE cache.'
    }
];

const missionProtocols = [
    {
        title: 'Deployment Protocol',
        body: 'Docker Compose stack with dedicated containers for backend, frontend, scanners, Postgres, and optional Nginx. Start scripts exist for Windows operators.'
    },
    {
        title: 'Security Protocols',
        body: 'JWT auth, Supabase row-level security, DNS TXT verification, strict CORS, and layered rate limiting safeguard every mission.'
    },
    {
        title: 'Responsible Recon',
        body: 'Link&Load is built for authorized testing. Domain authorization workflows and logging enforce ethical usage.'
    }
];

const MissionFile = () => {
    const navigate = useNavigate();

    return (
        <Layout>
            <div className="mission-page">
                <header className="mission-top-bar">
                    <div className="mission-top-bar__bar">
                        <h1 className="mission-top-bar__title">Mission File</h1>
                        <button type="button" className="back-button" onClick={() => navigate('/')}>
                            Return to Base
                        </button>
                    </div>
                </header>

                <div className="mission-content">
                    <section className="mission-hero">
                        <div className="mission-hero__content">
                            <p className="mission-hero__kicker">Mission File // Open Source Recon</p>
                            <h1>Link&amp;Load</h1>
                            <h2>Tactical Dossier</h2>
                            <p className="mission-hero__lede">
                                Link&amp;Load is an open-source cyber reconnaissance platform engineered for security teams that need rapid intel.
                                It coordinates multi-vector scanners, AI analysis, and MITRE ATT&amp;CK mapping to deliver battlefield-ready reports.
                            </p>
                            <div className="mission-cta">
                                <button type="button" className="mission-cta__primary" onClick={() => navigate('/')}>Launch Console</button>
                                <a
                                    className="mission-cta__secondary"
                                    href="https://github.com/pratiyk/Link-Load"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    View Repository
                                </a>
                            </div>
                        </div>
                        <div className="mission-hero__badgecard">
                            <img src={logo} alt="Link&Load emblem" className="mission-hero__logo" />
                            <div className="mission-hero__stats">
                                {missionStats.map((stat) => (
                                    <div key={stat.label} className="mission-stat">
                                        <span className="mission-stat__label">{stat.label}</span>
                                        <span className="mission-stat__value">{stat.value}</span>
                                        <span className="mission-stat__detail">{stat.detail}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </section>

                    <section className="mission-section">
                        <div className="mission-section__header">
                            <h2>Core Capabilities</h2>
                            <p>Highlights pulled from the Mission Brief—everything the README promises, rendered as a tactical checklist.</p>
                        </div>
                        <div className="mission-capabilities">
                            {capabilityHighlights.map((item) => (
                                <article key={item.id} className={`mission-card mission-card--${item.color}`}>
                                    <span className="mission-card__badge">{item.badge}</span>
                                    <h3>{item.title}</h3>
                                    <p>{item.description}</p>
                                </article>
                            ))}
                        </div>
                    </section>

                    <section className="mission-section mission-architecture">
                        <div className="mission-section__header">
                            <h2>System Architecture</h2>
                            <p>Command paths mirrored from the ASCII diagram: Command Center → Operations Hub → Scanner Fleet → Intelligence → Data Vault.</p>
                        </div>
                        <div className="architecture-flow" aria-label="Command path">
                            {architectureLayers.map((layer, index) => (
                                <React.Fragment key={`${layer.title}-flow`}>
                                    <span className="architecture-flow__node">{layer.title}</span>
                                    {index < architectureLayers.length - 1 && (
                                        <span className="architecture-flow__arrow" aria-hidden="true">→</span>
                                    )}
                                </React.Fragment>
                            ))}
                        </div>
                        <div className="architecture-grid">
                            {architectureLayers.map((layer) => (
                                <div key={layer.title} className="architecture-tile">
                                    <h4>{layer.title}</h4>
                                    <p>{layer.detail}</p>
                                </div>
                            ))}
                        </div>
                    </section>

                    <section className="mission-section mission-scanners">
                        <div className="mission-section__header">
                            <h2>Scanner Arsenal</h2>
                            <p>Each unit is containerized, wired into the backend, and reports through unified telemetry.</p>
                        </div>
                        <div className="scanner-grid">
                            {scannerCards.map((scanner) => (
                                <article key={scanner.name} className="scanner-card">
                                    <header>
                                        <span className="scanner-callsign">{scanner.callSign}</span>
                                        <span className="scanner-status">{scanner.status}</span>
                                    </header>
                                    <h3>{scanner.name}</h3>
                                    <p>{scanner.description}</p>
                                </article>
                            ))}
                        </div>
                    </section>

                    <section className="mission-section mission-protocols">
                        <div className="mission-section__header">
                            <h2>Operational Protocols</h2>
                            <p>Procedures excerpted from the README deployment, security, and responsible-use sections.</p>
                        </div>
                        <div className="protocol-grid">
                            {missionProtocols.map((protocol) => (
                                <article key={protocol.title} className="protocol-card">
                                    <h3>{protocol.title}</h3>
                                    <p>{protocol.body}</p>
                                </article>
                            ))}
                        </div>
                    </section>

                    <section className="mission-section mission-open-source">
                        <div className="mission-section__header">
                            <h2>Open Source Protocol</h2>
                            <p>Link&amp;Load is transparent tooling—fork it, audit it, or embed it in your stack.</p>
                        </div>
                        <div className="open-source-grid">
                            {openSourceFacts.map((fact) => {
                                const valueLines = fact.lines
                                    || (fact.value.includes(' · ')
                                        ? fact.value.split(' · ')
                                        : [fact.value]);

                                return (
                                    <article key={fact.label} className="open-source-card">
                                        <span className="open-source-label">{fact.label}</span>
                                        <div className="open-source-value">
                                            {valueLines.map((line, idx) => (
                                                <span
                                                    key={`${fact.label}-${idx}`}
                                                    className="open-source-value__line"
                                                >
                                                    {line}
                                                </span>
                                            ))}
                                        </div>
                                        <p className="open-source-detail">{fact.detail}</p>
                                    </article>
                                );
                            })}
                        </div>
                    </section>

                    <section className="mission-section mission-cta-panel">
                        <div className="mission-cta-panel__content">
                            <div>
                                <p className="mission-cta-panel__kicker">Ready for Deployment</p>
                                <h2>Spin up the stack, verify your domain, and start charting attack surfaces.</h2>
                            </div>
                            <div className="mission-cta-panel__actions">
                                <a
                                    className="mission-cta__secondary"
                                    href="https://github.com/pratiyk/Link-Load#deployment-protocol"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    Deployment Guide
                                </a>
                            </div>
                        </div>
                    </section>
                </div>
            </div>
        </Layout>
    );
};

export default MissionFile;
