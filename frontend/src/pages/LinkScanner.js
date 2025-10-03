import React, { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { scanLink } from "../services/linkScanner";
import { Link as LinkIcon, ScanSearch, ShieldCheck, AlertOctagon, CheckCircle2, Loader, Globe } from "lucide-react";

export default function LinkScanner() {
  const [url, setUrl] = useState("");

  const mutation = useMutation({
    mutationFn: scanLink,
  });

  const handleSubmit = (e) => {
    e.preventDefault();
    if (url.trim()) {
      mutation.mutate({ url }); // Pass as object!
    }
  };

  return (
    <div style={{ maxWidth: '900px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: 'var(--spacing-6)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-3)', marginBottom: 'var(--spacing-3)' }}>
          <div style={{
            width: '48px',
            height: '48px',
            borderRadius: 'var(--radius-lg)',
            background: 'linear-gradient(135deg, var(--color-accent) 0%, #3a6a03 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 4px 12px rgba(71, 133, 4, 0.2)'
          }}>
            <LinkIcon size={24} color="white" />
          </div>
          <div>
            <h1 style={{ 
              fontSize: 'var(--font-size-2xl)',
              fontWeight: 'var(--font-weight-bold)',
              marginBottom: 'var(--spacing-1)'
            }}>
              Link Scanner
            </h1>
            <p style={{ color: 'var(--color-text-secondary)', fontSize: 'var(--font-size-sm)' }}>
              Analyze URLs for potential security threats and malicious content
            </p>
          </div>
        </div>
      </div>

      {/* Scan Form */}
      <div className="card" style={{ marginBottom: 'var(--spacing-6)' }}>
        <form onSubmit={handleSubmit}>
          <label className="input-label">
            <Search size={16} style={{ marginRight: 'var(--spacing-2)' }} />
            Enter URL to Scan
          </label>
          <div style={{ display: 'flex', gap: 'var(--spacing-3)' }}>
            <input
              type="url"
              className="input"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              style={{ flex: 1 }}
              required
            />
            <button
              type="submit"
              className="btn btn-primary"
              disabled={mutation.isLoading}
              style={{ minWidth: '120px' }}
            >
              {mutation.isLoading ? (
                <>
                  <Loader size={18} className="spinner" />
                  Scanning...
                </>
              ) : (
                <>
                  <Search size={18} />
                  Scan Link
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Loading State */}
      {mutation.isLoading && (
        <div className="card" style={{ textAlign: 'center', padding: 'var(--spacing-8)' }}>
          <Loader size={48} className="spinner" style={{ 
            margin: '0 auto var(--spacing-4)',
            color: 'var(--color-accent)'
          }} />
          <h3 style={{ 
            fontSize: 'var(--font-size-lg)',
            fontWeight: 'var(--font-weight-semibold)',
            marginBottom: 'var(--spacing-2)'
          }}>
            Scanning Link...
          </h3>
          <p style={{ color: 'var(--color-text-secondary)' }}>
            Analyzing URL for security threats and malicious content
          </p>
        </div>
      )}

      {/* Error State */}
      {mutation.error && (
        <div style={{
          padding: 'var(--spacing-4)',
          borderRadius: 'var(--radius-lg)',
          backgroundColor: '#FEE2E2',
          border: '1px solid #FCA5A5',
          display: 'flex',
          alignItems: 'flex-start',
          gap: 'var(--spacing-3)'
        }}>
          <AlertTriangle size={24} color="#DC2626" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <h3 style={{ 
              color: '#DC2626',
              fontWeight: 'var(--font-weight-semibold)',
              marginBottom: 'var(--spacing-1)'
            }}>
              Scan Failed
            </h3>
            <p style={{ color: '#991B1B' }}>
              {mutation.error.response?.data?.detail || mutation.error.message || "Something went wrong"}
            </p>
          </div>
        </div>
      )}

      {/* Results */}
      {mutation.data && (
        <div className="card">
          <div style={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: 'var(--spacing-2)', 
            marginBottom: 'var(--spacing-4)',
            paddingBottom: 'var(--spacing-4)',
            borderBottom: '1px solid var(--color-border)'
          }}>
            <Shield size={24} color="var(--color-accent)" />
            <h3 style={{ 
              fontSize: 'var(--font-size-xl)',
              fontWeight: 'var(--font-weight-semibold)'
            }}>
              Scan Results
            </h3>
          </div>

          {/* Results Content */}
          <div style={{
            backgroundColor: 'var(--color-bg-secondary)',
            padding: 'var(--spacing-4)',
            borderRadius: 'var(--radius-md)',
            fontSize: 'var(--font-size-sm)',
            fontFamily: 'Monaco, Courier, monospace',
            overflowX: 'auto',
            maxHeight: '500px',
            overflowY: 'auto'
          }}>
            <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {JSON.stringify(mutation.data, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}