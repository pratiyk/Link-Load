import React, { useState } from "react";
import axios from "axios";
import { Eye, Mail, ScanSearch, AlertOctagon, Database, Loader, ShieldAlert } from "lucide-react";

export default function DarkWebScanner() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState([]);
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setResults([]);
    setLoading(true);

    try {
      const res = await axios.post("http://localhost:8000/api/darkweb_scan", { email });

      if (!res.data || res.data.length === 0) {
        setError("No dark web leaks found for this email.");
      } else {
        setResults(res.data);
      }
    } catch (err) {
      console.error(err);
      setError("Failed to check dark web. Please try again.");
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
            background: 'linear-gradient(135deg, #7C3AED 0%, #6D28D9 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 8px 16px rgba(124, 58, 237, 0.25)',
            flexShrink: 0
          }}>
            <Eye size={28} color="white" strokeWidth={2} />
          </div>
          <div>
            <h1 style={{ 
              fontSize: 'var(--font-size-2xl)',
              fontWeight: 'var(--font-weight-bold)',
              marginBottom: 'var(--spacing-1)'
            }}>
              Dark Web Scanner
            </h1>
            <p style={{ color: 'var(--color-text-secondary)', fontSize: 'var(--font-size-sm)' }}>
              Check if your credentials have been compromised in data breaches
            </p>
          </div>
        </div>
      </div>

      {/* Scan Form */}
      <div className="card" style={{ marginBottom: 'var(--spacing-6)' }}>
        <form onSubmit={handleSubmit}>
          <label className="input-label">
            <Mail size={16} style={{ marginRight: 'var(--spacing-2)' }} />
            Email Address to Check
          </label>
          <div style={{ display: 'flex', gap: 'var(--spacing-3)' }}>
            <input
              type="email"
              className="input"
              placeholder="your@email.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              style={{ flex: 1 }}
              required
            />
            <button 
              type="submit" 
              className="btn btn-primary"
              style={{ minWidth: '150px' }}
              disabled={loading}
            >
              {loading ? (
                <>
                  <Loader size={18} className="spinner" />
                  Checking...
                </>
              ) : (
                <>
                  <Search size={18} />
                  Check Breaches
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
            color: '#7C3AED'
          }} />
          <h3 style={{ 
            fontSize: 'var(--font-size-lg)',
            fontWeight: 'var(--font-weight-semibold)',
            marginBottom: 'var(--spacing-2)'
          }}>
            Searching Dark Web Databases...
          </h3>
          <p style={{ color: 'var(--color-text-secondary)' }}>
            This may take a few moments
          </p>
        </div>
      )}

      {/* Error State */}
      {error && (
        <div style={{
          padding: 'var(--spacing-4)',
          borderRadius: 'var(--radius-lg)',
          backgroundColor: results.length === 0 ? '#D1FAE5' : '#FEE2E2',
          border: `1px solid ${results.length === 0 ? '#6EE7B7' : '#FCA5A5'}`,
          display: 'flex',
          alignItems: 'flex-start',
          gap: 'var(--spacing-3)'
        }}>
          {results.length === 0 ? (
            <>
              <Database size={24} color="#059669" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <h3 style={{ 
                  color: '#059669',
                  fontWeight: 'var(--font-weight-semibold)',
                  marginBottom: 'var(--spacing-1)'
                }}>
                  Good News!
                </h3>
                <p style={{ color: '#047857' }}>{error}</p>
              </div>
            </>
          ) : (
            <>
              <AlertTriangle size={24} color="#DC2626" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <h3 style={{ 
                  color: '#DC2626',
                  fontWeight: 'var(--font-weight-semibold)',
                  marginBottom: 'var(--spacing-1)'
                }}>
                  Scan Failed
                </h3>
                <p style={{ color: '#991B1B' }}>{error}</p>
              </div>
            </>
          )}
        </div>
      )}

      {/* Results */}
      {results.length > 0 && (
        <div className="card">
          <div style={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: 'var(--spacing-2)', 
            marginBottom: 'var(--spacing-4)',
            paddingBottom: 'var(--spacing-4)',
            borderBottom: '1px solid var(--color-border)'
          }}>
            <AlertTriangle size={24} color="#DC2626" />
            <h3 style={{ 
              fontSize: 'var(--font-size-xl)',
              fontWeight: 'var(--font-weight-semibold)',
              color: '#DC2626'
            }}>
              ⚠️ Leaked Credentials Found ({results.length})
            </h3>
          </div>

          <p style={{ 
            marginBottom: 'var(--spacing-5)',
            color: 'var(--color-text-secondary)',
            fontSize: 'var(--font-size-sm)'
          }}>
            Your email was found in {results.length} data breach{results.length > 1 ? 'es' : ''}. 
            Please change your passwords immediately.
          </p>

          {results.map((result, index) => (
            <div 
              key={index} 
              style={{
                marginBottom: index < results.length - 1 ? 'var(--spacing-5)' : 0,
                paddingBottom: index < results.length - 1 ? 'var(--spacing-5)' : 0,
                borderBottom: index < results.length - 1 ? '1px solid var(--color-border)' : 'none'
              }}
            >
              <div style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 'var(--spacing-2)',
                padding: 'var(--spacing-2) var(--spacing-3)',
                backgroundColor: '#FEE2E2',
                borderRadius: 'var(--radius-md)',
                marginBottom: 'var(--spacing-3)'
              }}>
                <Database size={16} color="#DC2626" />
                <h4 style={{ 
                  color: '#DC2626',
                  fontWeight: 'var(--font-weight-semibold)',
                  fontSize: 'var(--font-size-base)'
                }}>
                  Source: {result.source}
                </h4>
              </div>
              
              <div style={{
                backgroundColor: 'var(--color-bg-secondary)',
                padding: 'var(--spacing-4)',
                borderRadius: 'var(--radius-md)'
              }}>
                {Array.isArray(result.data) && result.data.length > 0 ? (
                  <ul style={{ 
                    listStyle: 'none', 
                    padding: 0,
                    margin: 0,
                    display: 'grid',
                    gap: 'var(--spacing-3)'
                  }}>
                    {result.data.map((item, i) => (
                      <li 
                        key={i}
                        style={{
                          padding: 'var(--spacing-3)',
                          backgroundColor: 'white',
                          borderRadius: 'var(--radius-md)',
                          border: '1px solid var(--color-border)'
                        }}
                      >
                        {Object.entries(item).map(([key, value]) => (
                          <div 
                            key={key}
                            style={{
                              display: 'flex',
                              marginBottom: 'var(--spacing-2)',
                              fontSize: 'var(--font-size-sm)'
                            }}
                          >
                            <strong style={{ 
                              minWidth: '120px',
                              color: 'var(--color-text-secondary)',
                              textTransform: 'capitalize'
                            }}>
                              {key}:
                            </strong>
                            <span style={{ 
                              color: 'var(--color-text-primary)',
                              wordBreak: 'break-all'
                            }}>
                              {String(value)}
                            </span>
                          </div>
                        ))}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p style={{ 
                    color: 'var(--color-text-secondary)',
                    fontSize: 'var(--font-size-sm)',
                    fontStyle: 'italic'
                  }}>
                    No specific leak details available.
                  </p>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}