import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Link, Navigate } from "react-router-dom";
import {
    AlertCircle,
    CheckCircle2,
    ClipboardCopy,
    Globe,
    Plus,
    RefreshCcw,
    ShieldCheck,
    Trash2,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import domainService from "../services/domainService";
import Layout from "../components/Layout";
import "./Verification.css";

const sanitizeDomainValue = (value) => {
    const trimmed = (value || "").trim().toLowerCase();
    if (!trimmed) {
        return "";
    }
    const withoutScheme = trimmed.replace(/^[a-z]+:\/\//, "");
    const core = withoutScheme.split(/[/?#]/)[0];
    return core
        .replace(/[^a-z0-9.-]/g, "-")
        .replace(/-+/g, "-")
        .replace(/^-+|-+$/g, "");
};

const hostLabelFor = (prefix, domain) => `${prefix}.${domain}`;
const recordValueFor = (token) => `linkload-site-verification=${token}`;

const Verification = () => {
    const { user, isAuthenticated, loading: authLoading } = useAuth();
    const [pageLoading, setPageLoading] = useState(true);
    const [domains, setDomains] = useState([]);
    const [accountToken, setAccountToken] = useState("");
    const [hostPrefix, setHostPrefix] = useState("_linkload");
    const [domainInput, setDomainInput] = useState("");
    const [formError, setFormError] = useState("");
    const [formSuccess, setFormSuccess] = useState("");
    const [submitting, setSubmitting] = useState(false);
    const [verifying, setVerifying] = useState({});
    const [copyFeedback, setCopyFeedback] = useState({});
    const [tokenCopyState, setTokenCopyState] = useState("idle");
    const [rotating, setRotating] = useState(false);

    const sanitizedInput = useMemo(() => sanitizeDomainValue(domainInput), [domainInput]);

    const loadProfile = useCallback(async () => {
        try {
            setPageLoading(true);
            const profile = await domainService.fetchVerificationProfile();
            setDomains(profile.domains || []);
            setAccountToken(profile.verification_token);
            setHostPrefix(profile.host_prefix || "_linkload");
            setCopyFeedback({});
            setVerifying({});
            setTokenCopyState("idle");
        } catch (error) {
            console.error("Failed to load verification profile", error);
            setFormError(
                error?.message || "Unable to load verification data. Refresh and try again."
            );
        } finally {
            setPageLoading(false);
        }
    }, []);

    useEffect(() => {
        if (!authLoading && isAuthenticated) {
            loadProfile();
        }
    }, [authLoading, isAuthenticated, loadProfile]);

    const resetFeedback = () => {
        setFormError("");
        setFormSuccess("");
    };

    const verifiedCount = useMemo(() => domains.filter((entry) => entry.status === "verified").length, [domains]);
    const pendingCount = useMemo(() => domains.filter((entry) => entry.status === "pending").length, [domains]);
    const attentionCount = useMemo(() => domains.filter((entry) => entry.status === "error").length, [domains]);

    const handleAddDomain = async (event) => {
        event.preventDefault();
        resetFeedback();

        const sanitized = sanitizeDomainValue(domainInput);
        if (!sanitized) {
            setFormError("Enter the domain or subdomain you want to verify.");
            return;
        }

        if (domains.some((entry) => entry.domain === sanitized)) {
            setFormError("That domain is already tracked.");
            return;
        }

        setSubmitting(true);
        try {
            const created = await domainService.createDomain(sanitized);
            setDomains((previous) => [created, ...previous]);
            setDomainInput("");
            setFormSuccess("Domain added. Publish the TXT record, then run Verify.");
        } catch (error) {
            console.error("Failed to register domain", error);
            setFormError(error?.message || "Unable to add domain. Try again later.");
        } finally {
            setSubmitting(false);
        }
    };

    const handleCopyToken = async () => {
        if (!accountToken) {
            return;
        }
        try {
            await navigator.clipboard.writeText(recordValueFor(accountToken));
            setTokenCopyState("copied");
        } catch (error) {
            console.error("Token copy failed", error);
            setTokenCopyState("error");
        } finally {
            setTimeout(() => setTokenCopyState("idle"), 2200);
        }
    };

    const handleVerifyDomain = async (domainId) => {
        resetFeedback();
        setVerifying((previous) => ({ ...previous, [domainId]: true }));
        try {
            const result = await domainService.verifyDomain(domainId);
            setDomains((previous) =>
                previous.map((entry) => (entry.id === domainId ? result.domain : entry))
            );
            setFormSuccess(result.message);
        } catch (error) {
            console.error("Verification error", error);
            setFormError(error?.message || "Verification attempt failed. Try again after DNS propagation.");
        } finally {
            setVerifying((previous) => ({ ...previous, [domainId]: false }));
        }
    };

    const handleDeleteDomain = async (domainId) => {
        resetFeedback();
        try {
            await domainService.deleteDomain(domainId);
            setDomains((previous) => previous.filter((entry) => entry.id !== domainId));
            setFormSuccess("Domain removed from verification list.");
        } catch (error) {
            console.error("Failed to delete domain", error);
            setFormError(error?.message || "Unable to remove domain right now.");
        }
    };

    const handleCopyRecord = async (entry) => {
        const hostLabel = hostLabelFor(hostPrefix, entry.domain);
        const value = recordValueFor(entry.token);
        const record = `Type: TXT\nHost: ${hostLabel}\nValue: "${value}"\nTTL: 300`;

        try {
            await navigator.clipboard.writeText(record);
            setCopyFeedback((previous) => ({ ...previous, [entry.id]: "copied" }));
        } catch (error) {
            console.error("Copy failed", error);
            setCopyFeedback((previous) => ({ ...previous, [entry.id]: "error" }));
        } finally {
            setTimeout(() => {
                setCopyFeedback((previous) => ({ ...previous, [entry.id]: "idle" }));
            }, 2200);
        }
    };

    const handleRotateToken = async () => {
        resetFeedback();
        setRotating(true);
        try {
            const profile = await domainService.rotateVerificationToken();
            setDomains(profile.domains || []);
            setAccountToken(profile.verification_token);
            setCopyFeedback({});
            setVerifying({});
            setFormSuccess("New verification token generated. Update TXT records before verifying again.");
        } catch (error) {
            console.error("Token rotation failed", error);
            setFormError(error?.message || "Unable to rotate token right now.");
        } finally {
            setRotating(false);
        }
    };

    if (!authLoading && !isAuthenticated) {
        return <Navigate to="/login" replace state={{ from: "/settings/verification" }} />;
    }

    if (authLoading || pageLoading) {
        return (
            <Layout>
                <div className="loading-container">
                    <div className="loader"></div>
                    <p>Loading verification workspace…</p>
                </div>
            </Layout>
        );
    }

    const recordValue = recordValueFor(accountToken);

    return (
        <Layout>
            <div className="verification-shell">
                <header className="verification-header">
                    <div className="header-content">
                        <h1 className="verification-header__title">DNS verification</h1>
                        <Link to="/" className="back-button">← Back to Home</Link>
                    </div>
                    <p className="verification-header__subtitle">
                        Prove that you control a domain before unlocking authenticated scans and organization-wide automations.
                    </p>
                </header>

                <section className="verification-meta" aria-label="Verification summary">
                    <article className="verification-meta-card">
                        <p className="verification-meta-label">Domains tracked</p>
                        <p className="verification-meta-value">{domains.length || 0}</p>
                        <p className="verification-meta-caption">Across your workspace</p>
                    </article>
                    <article className="verification-meta-card">
                        <p className="verification-meta-label">Verified</p>
                        <p className="verification-meta-value">{verifiedCount}</p>
                        <p className="verification-meta-caption">Ready for authenticated scans</p>
                    </article>
                    <article className="verification-meta-card">
                        <p className="verification-meta-label">Pending checks</p>
                        <p className="verification-meta-value">{pendingCount}</p>
                        <p className="verification-meta-caption">Waiting on DNS propagation</p>
                    </article>
                    <article className="verification-meta-card">
                        <p className="verification-meta-label">Needs attention</p>
                        <p className="verification-meta-value">{attentionCount}</p>
                        <p className="verification-meta-caption">Records to reconfigure</p>
                    </article>
                    <article className="verification-meta-card verification-meta-card--code">
                        <p className="verification-meta-label">Account TXT value</p>
                        <code className="verification-meta-code">{recordValue}</code>
                        <button type="button" className="verification-meta-copy" onClick={handleCopyToken}>
                            {tokenCopyState === "copied" ? "Copied" : tokenCopyState === "error" ? "Failed" : "Copy value"}
                        </button>
                    </article>
                </section>

                <div className="verification-divider" role="presentation" />

                <section className="verification-panel">
                    <div className="verification-panel__header verification-panel__header--pink">
                        <h2>TXT record overview</h2>
                    </div>
                    <div className="verification-panel__body">
                        <div className="verification-callout" aria-live="polite">
                            <ShieldCheck size={20} aria-hidden="true" />
                            <div>
                                <p className="verification-callout__title">TXT verification overview</p>
                                <p className="verification-callout__body">
                                    Publish a TXT record named <strong>{hostPrefix}.your-domain</strong> with the value <code>{recordValue}</code>. Once DNS propagates, run the Verify action to confirm ownership.
                                </p>
                            </div>
                        </div>
                        <section className="verification-highlight-grid" aria-label="TXT guidance">
                            <div className="verification-highlight-card verification-highlight-card--blue">
                                <p className="verification-highlight-label">TXT host template</p>
                                <p className="verification-highlight-value">{hostLabelFor(hostPrefix, "your-domain")}</p>
                                <p className="verification-highlight-hint">Use this as the Host/Name field when creating the record.</p>
                            </div>
                            <div className="verification-highlight-card verification-highlight-card--yellow">
                                <p className="verification-highlight-label">TXT value</p>
                                <p className="verification-highlight-value verification-highlight-value--code">{recordValue}</p>
                                <p className="verification-highlight-hint">Keep the value exactly as provided, including the prefix.</p>
                            </div>
                            <div className="verification-highlight-card verification-highlight-card--green">
                                <p className="verification-highlight-label">Why verification matters</p>
                                <p className="verification-highlight-copy">
                                    Verified domains unlock authenticated scanning, automated remediation hints, and protect sensitive findings from untrusted users.
                                </p>
                                <ul className="verification-highlight-list">
                                    <li>No rogue scans on someone else&rsquo;s infra</li>
                                    <li>Scoped access to vulnerability data</li>
                                    <li>Better prioritization for your teams</li>
                                </ul>
                            </div>
                        </section>
                    </div>
                </section>

                <div className="verification-divider verification-divider--plain" role="presentation" />

                {(formError || formSuccess) && (
                    <div
                        className={`verification-feedback ${formError ? "verification-feedback--error" : "verification-feedback--success"}`}
                        role="alert"
                    >
                        {formError ? <AlertCircle size={18} aria-hidden="true" /> : <CheckCircle2 size={18} aria-hidden="true" />}
                        <span>{formError || formSuccess}</span>
                    </div>
                )}

                <section className="verification-panel">
                    <div className="verification-panel__header verification-panel__header--gold">
                        <h2>Domains & verification</h2>
                    </div>
                    <div className="verification-panel__body verification-panel__body--grid">
                        <section className="verification-card">
                            <header className="verification-card__header">
                                <h2 className="verification-card__title">Domains</h2>
                                <button
                                    type="button"
                                    className="verification-rotate"
                                    onClick={handleRotateToken}
                                    disabled={rotating}
                                >
                                    <RefreshCcw size={16} aria-hidden="true" />
                                    {rotating ? "Rotating token…" : "Rotate token"}
                                </button>
                            </header>

                            <form className="verification-form" onSubmit={handleAddDomain}>
                                <label className="verification-form__label" htmlFor="verification-domain">
                                    <span>Add a domain</span>
                                    <small>We will generate the TXT host and instructions automatically.</small>
                                </label>
                                <div className="verification-form__control">
                                    <Globe size={18} aria-hidden="true" />
                                    <input
                                        id="verification-domain"
                                        type="text"
                                        value={domainInput}
                                        onChange={(event) => setDomainInput(event.target.value)}
                                        placeholder="https://sub.example.com"
                                        autoComplete="off"
                                    />
                                    <button type="submit" disabled={submitting || !sanitizedInput}>
                                        <Plus size={16} aria-hidden="true" />
                                        {submitting ? "Adding…" : "Add"}
                                    </button>
                                </div>
                            </form>

                            <div className="verification-table" role="region" aria-live="polite">
                                {domains.length === 0 ? (
                                    <div className="verification-table__empty">
                                        <p>No domains tracked yet.</p>
                                        <p>Add your primary domain to get started.</p>
                                    </div>
                                ) : (
                                    <table>
                                        <thead>
                                            <tr>
                                                <th scope="col">Domain</th>
                                                <th scope="col">TXT host</th>
                                                <th scope="col">Status</th>
                                                <th scope="col">Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {domains.map((entry) => {
                                                const hostLabel = hostLabelFor(hostPrefix, entry.domain);
                                                const status = entry.status;
                                                const copyState = copyFeedback[entry.id] || "idle";
                                                const verifyingDomain = Boolean(verifying[entry.id]);

                                                return (
                                                    <tr key={entry.id}>
                                                        <td>
                                                            <div className="verification-table__domain">
                                                                <span className="verification-table__name">{entry.domain}</span>
                                                                <span className="verification-table__token">{recordValueFor(entry.token)}</span>
                                                            </div>
                                                        </td>
                                                        <td>
                                                            <code className="verification-table__host">{hostLabel}</code>
                                                        </td>
                                                        <td>
                                                            <span className={`verification-status verification-status--${status}`}>
                                                                {status === "verified" && "Verified"}
                                                                {status === "pending" && "Pending"}
                                                                {status === "error" && "Check record"}
                                                            </span>
                                                        </td>
                                                        <td>
                                                            <div className="verification-actions__group">
                                                                <button
                                                                    type="button"
                                                                    className="verification-action"
                                                                    onClick={() => handleCopyRecord(entry)}
                                                                >
                                                                    <ClipboardCopy size={14} aria-hidden="true" />
                                                                    {copyState === "copied"
                                                                        ? "Copied"
                                                                        : copyState === "error"
                                                                            ? "Failed"
                                                                            : "Copy"}
                                                                </button>
                                                                <button
                                                                    type="button"
                                                                    className="verification-action"
                                                                    onClick={() => handleVerifyDomain(entry.id)}
                                                                    disabled={verifyingDomain}
                                                                >
                                                                    <ShieldCheck size={14} aria-hidden="true" />
                                                                    {verifyingDomain ? "Verifying…" : "Verify"}
                                                                </button>
                                                                <button
                                                                    type="button"
                                                                    className="verification-action verification-action--danger"
                                                                    onClick={() => handleDeleteDomain(entry.id)}
                                                                >
                                                                    <Trash2 size={14} aria-hidden="true" />
                                                                    Remove
                                                                </button>
                                                            </div>
                                                            {entry.last_error && (
                                                                <p className="verification-error-hint">{entry.last_error}</p>
                                                            )}
                                                        </td>
                                                    </tr>
                                                );
                                            })}
                                        </tbody>
                                    </table>
                                )}
                            </div>
                        </section>

                        <aside className="verification-guide">
                            <h2>How to publish the TXT record</h2>
                            <ol>
                                <li>
                                    Sign in to your DNS provider (Cloudflare, Route53, GoDaddy, etc.) and open the DNS management console.
                                </li>
                                <li>
                                    Create a new TXT record. Use <strong>{hostPrefix}.your-domain</strong> as the host/value name.
                                </li>
                                <li>
                                    Paste <code>{recordValue}</code> into the value/content field. Set TTL to 300 seconds if you can, otherwise accept the default.
                                </li>
                                <li>
                                    Save the record, wait for propagation (usually a few minutes), then click <em>Verify</em> next to the matching domain.
                                </li>
                                <li>
                                    Once Link&Load marks the domain as verified, you can remove the TXT record if your policies require a clean zone file.
                                </li>
                            </ol>

                            <div className="verification-tip">
                                <AlertCircle size={18} aria-hidden="true" />
                                <p>
                                    Verification runs against public DNS resolvers. Corporate split-horizon DNS or private host files will not satisfy the check—publish the record on the public zone.
                                </p>
                            </div>

                            <div className="verification-user">
                                <p className="verification-user__label">Signed in as</p>
                                <p className="verification-user__detail">{user?.email || "Unknown"}</p>
                            </div>
                        </aside>
                    </div>
                </section>
            </div>
        </Layout>
    );
};

export default Verification;
