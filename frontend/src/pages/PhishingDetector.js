import React, { useState } from "react";
import { scanPhishingURL } from "../services/phishingDetector";
import { ShieldQuestion, ScanSearch, AlertOctagon, CheckCircle2, Loader, AlertCircle, Mail } from "lucide-react";

export default function PhishingDetector() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const validateUrl = (inputUrl) => {
    try {
      const u = new URL(inputUrl);
      return u.protocol === "http:" || u.protocol === "https:";
    } catch {
      return false;
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setResult(null);
    if (!validateUrl(url)) {
      setError("Enter a valid URL starting with http:// or https://");
      return;
    }
    setLoading(true);
    try {
      const data = await scanPhishingURL(url);
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: '900px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: 'var(--spacing-6)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-3)', marginBottom: 'var(--spacing-3)' }}>
          <div style={{
            width: '56px',
            height: '56px',
            borderRadius: 'var(--radius-lg)',
            background: 'linear-gradient(135deg, #478504 0%, #3a6a03 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 8px 16px rgba(71, 133, 4, 0.2)',
            flexShrink: 0
          }}>
            <ShieldQuestion size={28} color="white" strokeWidth={2} />
          </div>
          <div>
            <h1 style={{ 
              fontSize: 'var(--font-size-2xl)',
              fontWeight: 'var(--font-weight-bold)',
              marginBottom: 'var(--spacing-1)'
            }}>
              Phishing Detector
            </h1>
            <p style={{ color: 'var(--color-text-secondary)', fontSize: 'var(--font-size-sm)' }}>
              Identify suspicious URLs and potential phishing attempts
            </p>
          </div>
        </div>
      </div>

      {/* Scan Form */}
      <div className="card" style={{ marginBottom: 'var(--spacing-6)' }}>
        <form onSubmit={handleSubmit}>
          <label className="input-label" style={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-2)' }}>
            <ScanSearch size={16} style={{ color: 'var(--color-accent)', flexShrink: 0 }} />
            <span>Enter URL to Analyze</span>
          </label>
          <div style={{ display: 'flex', gap: 'var(--spacing-3)' }}>
            <input 
              type="url" 
              className="input"
              placeholder="https://suspicious-site.com"
              value={url} 
              onChange={(e) => setUrl(e.target.value)} 
              style={{ flex: 1 }}
              required 
            />
            <button 
              type="submit" 
              className="btn btn-primary"
              style={{ minWidth: '140px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 'var(--spacing-2)' }}
              disabled={loading}
            >
              {loading ? (
                <>
                  <Loader size={18} className="spinner" strokeWidth={2} />
                  <span>Analyzing...</span>
                </>
              ) : (
                <>
                  <ScanSearch size={18} strokeWidth={2} />
                  <span>Scan URL</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Loading State */}
      {loading && (
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
            Analyzing URL...
          </h3>
          <p style={{ color: 'var(--color-text-secondary)' }}>
            Checking for phishing indicators and suspicious patterns
          </p>
        </div>
      )}

      {/* Error State */}
      {error && (
        <div style={{
          padding: 'var(--spacing-4)',
          borderRadius: 'var(--radius-lg)',
          backgroundColor: '#FEE2E2',
          border: '1px solid #FCA5A5',
          display: 'flex',
          alignItems: 'flex-start',
          gap: 'var(--spacing-3)'
        }}>
          <AlertOctagon size={24} color="#DC2626" style={{ flexShrink: 0, marginTop: '2px' }} strokeWidth={2} />
          <div>
            <h3 style={{ 
              color: '#DC2626',
              fontWeight: 'var(--font-weight-semibold)',
              marginBottom: 'var(--spacing-1)'
            }}>
              Validation Error
            </h3>
            <p style={{ color: '#991B1B' }}>{error}</p>
          </div>
        </div>
      )}

      {/* Results */}
      {result && !loading && !error && (
        <div className="card">
          <div style={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: 'var(--spacing-2)', 
            marginBottom: 'var(--spacing-5)',
            paddingBottom: 'var(--spacing-4)',
            borderBottom: '1px solid var(--color-border)'
          }}>
            {result.is_phishing ? (
              <AlertOctagon size={24} color="#DC2626" strokeWidth={2} />
            ) : (
              <CheckCircle2 size={24} color="#059669" strokeWidth={2} />
            )}
            <h3 style={{ 
              fontSize: 'var(--font-size-xl)',
              fontWeight: 'var(--font-weight-semibold)'
            }}>
              Analysis Complete
            </h3>
          </div>

          <div style={{ display: 'grid', gap: 'var(--spacing-4)' }}>
            <div>
              <p style={{ 
                fontSize: 'var(--font-size-sm)', 
                color: 'var(--color-text-secondary)',
                marginBottom: 'var(--spacing-1)'
              }}>
                Analyzed URL
              </p>
              <p style={{ 
                fontFamily: 'Monaco, Courier, monospace',
                fontSize: 'var(--font-size-sm)',
                padding: 'var(--spacing-2)',
                backgroundColor: 'var(--color-bg-secondary)',
                borderRadius: 'var(--radius-md)',
                wordBreak: 'break-all'
              }}>
                {result.url}
              </p>
            </div>

            <div>
              <p style={{ 
                fontSize: 'var(--font-size-sm)', 
                color: 'var(--color-text-secondary)',
                marginBottom: 'var(--spacing-2)'
              }}>
                Detection Status
              </p>
              <div style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 'var(--spacing-2)',
                padding: 'var(--spacing-3) var(--spacing-4)',
                borderRadius: 'var(--radius-lg)',
                backgroundColor: result.is_phishing ? '#FEE2E2' : '#D1FAE5',
                border: `2px solid ${result.is_phishing ? '#FCA5A5' : '#6EE7B7'}`,
              }}>
                {result.is_phishing ? (
                  <AlertOctagon size={20} color="#DC2626" strokeWidth={2} />
                ) : (
                  <CheckCircle2 size={20} color="#059669" strokeWidth={2} />
                )}
                <span style={{
                  fontSize: 'var(--font-size-lg)',
                  fontWeight: 'var(--font-weight-semibold)',
                  color: result.is_phishing ? '#DC2626' : '#059669'
                }}>
                  {result.is_phishing ? "⚠️ Phishing Detected" : "✅ Benign"}
                </span>
              </div>
            </div>

            <div>
              <p style={{ 
                fontSize: 'var(--font-size-sm)', 
                color: 'var(--color-text-secondary)',
                marginBottom: 'var(--spacing-2)'
              }}>
                Confidence Score
              </p>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-3)' }}>
                <div style={{ 
                  flex: 1, 
                  height: '12px', 
                  backgroundColor: 'var(--color-bg-secondary)',
                  borderRadius: 'var(--radius-full)',
                  overflow: 'hidden'
                }}>
                  <div style={{
                    height: '100%',
                    width: `${(result.probability * 100)}%`,
                    backgroundColor: result.is_phishing ? '#DC2626' : '#059669',
                    borderRadius: 'var(--radius-full)',
                    transition: 'width 0.5s ease'
                  }}></div>
                </div>
                <span style={{ 
                  fontSize: 'var(--font-size-xl)',
                  fontWeight: 'var(--font-weight-bold)',
                  color: result.is_phishing ? '#DC2626' : '#059669',
                  minWidth: '70px',
                  textAlign: 'right'
                }}>
                  {(result.probability * 100).toFixed(1)}%
                </span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
