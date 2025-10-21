// src/pages/ThreatScanner.js
import React, { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { scanThreat } from "../services/threatScanner";
import {
  ShieldCheck,
  ScanSearch,
  AlertOctagon,
  TrendingUp,
  Award,
  Loader,
  Activity,
  AlertTriangle,
  Shield,
} from "lucide-react";

export default function ThreatScanner() {
  const [input, setInput] = useState("");

  const mutation = useMutation({
    mutationFn: scanThreat,
  });

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!input.trim()) return;
    mutation.mutate(input.trim());
  };

  return (
    <div style={{ maxWidth: "1000px", margin: "0 auto" }}>
      {/* Header */}
      <div style={{ marginBottom: "var(--spacing-6)" }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "var(--spacing-3)",
            marginBottom: "var(--spacing-3)",
          }}
        >
          <div
            style={{
              width: "56px",
              height: "56px",
              borderRadius: "var(--radius-lg)",
              background: "linear-gradient(135deg, #3B82F6 0%, #2563EB 100%)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              boxShadow: "0 8px 16px rgba(59, 130, 246, 0.25)",
              flexShrink: 0,
            }}
          >
            <ShieldCheck size={28} color="white" strokeWidth={2} />
          </div>
          <div>
            <h1
              style={{
                fontSize: "var(--font-size-2xl)",
                fontWeight: "var(--font-weight-bold)",
                marginBottom: "var(--spacing-1)",
              }}
            >
              Threat Intelligence Scanner
            </h1>
            <p
              style={{
                color: "var(--color-text-secondary)",
                fontSize: "var(--font-size-sm)",
              }}
            >
              Analyze domains and IP addresses for malicious activity
            </p>
          </div>
        </div>
      </div>

      {/* Scan Form */}
      <div className="card" style={{ marginBottom: "var(--spacing-6)" }}>
        <form onSubmit={handleSubmit}>
          <label
            className="input-label"
            style={{
              display: "flex",
              alignItems: "center",
              gap: "var(--spacing-2)",
              marginBottom: "var(--spacing-2)",
            }}
          >
            <ScanSearch
              size={16}
              style={{ color: "var(--color-accent)", flexShrink: 0 }}
              strokeWidth={2}
            />
            <span>Domain or IP Address</span>
          </label>
          <div style={{ display: "flex", gap: "var(--spacing-3)" }}>
            <input
              type="text"
              className="input"
              placeholder="example.com or 192.168.1.1"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              style={{ flex: 1 }}
              required
            />
            <button
              type="submit"
              className="btn btn-primary"
              style={{
                minWidth: "140px",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: "var(--spacing-2)",
              }}
              disabled={mutation.isLoading}
            >
              {mutation.isLoading ? (
                <>
                  <Loader size={18} className="spinner" strokeWidth={2} />
                  <span>Analyzing...</span>
                </>
              ) : (
                <>
                  <ScanSearch size={18} strokeWidth={2} />
                  <span>Analyze Threat</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Loading State */}
      {mutation.isLoading && (
        <div
          className="card"
          style={{ textAlign: "center", padding: "var(--spacing-8)" }}
        >
          <Loader
            size={48}
            className="spinner"
            style={{
              margin: "0 auto var(--spacing-4)",
              color: "var(--color-accent)",
            }}
          />
          <h3
            style={{
              fontSize: "var(--font-size-lg)",
              fontWeight: "var(--font-weight-semibold)",
              marginBottom: "var(--spacing-2)",
            }}
          >
            Analyzing Threat Level...
          </h3>
          <p style={{ color: "var(--color-text-secondary)" }}>
            Checking multiple threat intelligence sources
          </p>
        </div>
      )}

      {/* Error State */}
      {mutation.error && (
        <div
          style={{
            padding: "var(--spacing-4)",
            borderRadius: "var(--radius-lg)",
            backgroundColor: "#FEE2E2",
            border: "1px solid #FCA5A5",
            display: "flex",
            alignItems: "flex-start",
            gap: "var(--spacing-3)",
          }}
        >
          <AlertTriangle
            size={24}
            color="#DC2626"
            style={{ flexShrink: 0, marginTop: "2px" }}
          />
          <div>
            <h3
              style={{
                color: "#DC2626",
                fontWeight: "var(--font-weight-semibold)",
                marginBottom: "var(--spacing-1)",
              }}
            >
              Analysis Failed
            </h3>
            <p style={{ color: "#991B1B" }}>{mutation.error.message}</p>
          </div>
        </div>
      )}

      {/* Results */}
      {mutation.data && (
        <>
          {/* Summary Cards */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
              gap: "var(--spacing-4)",
              marginBottom: "var(--spacing-6)",
            }}
          >
            {/* Threat Score Card */}
            <div
              className="card"
              style={{
                background: "linear-gradient(135deg, #3B82F6 0%, #2563EB 100%)",
                color: "white",
                border: "none",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "var(--spacing-2)",
                  marginBottom: "var(--spacing-3)",
                }}
              >
                <TrendingUp size={20} />
                <h3
                  style={{
                    fontSize: "var(--font-size-base)",
                    fontWeight: "var(--font-weight-semibold)",
                  }}
                >
                  Threat Score
                </h3>
              </div>
              <p
                style={{
                  fontSize: "2.5rem",
                  fontWeight: "var(--font-weight-bold)",
                  marginBottom: "var(--spacing-1)",
                }}
              >
                {mutation.data?.threat_score || "N/A"}
              </p>
              <p style={{ fontSize: "var(--font-size-sm)", opacity: 0.9 }}>
                0-100 scale
              </p>
            </div>

            {/* Malicious Indicators Card */}
            <div
              className="card"
              style={{
                background: "linear-gradient(135deg, #F97316 0%, #EA580C 100%)",
                color: "white",
                border: "none",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "var(--spacing-2)",
                  marginBottom: "var(--spacing-3)",
                }}
              >
                <AlertTriangle size={20} />
                <h3
                  style={{
                    fontSize: "var(--font-size-base)",
                    fontWeight: "var(--font-weight-semibold)",
                  }}
                >
                  Malicious Indicators
                </h3>
              </div>
              <p
                style={{
                  fontSize: "2.5rem",
                  fontWeight: "var(--font-weight-bold)",
                  marginBottom: "var(--spacing-1)",
                }}
              >
                {mutation.data?.malicious_indicators?.length || 0}
              </p>
              <p style={{ fontSize: "var(--font-size-sm)", opacity: 0.9 }}>
                Detected threats
              </p>
            </div>

            {/* Reputation Card */}
            <div
              className="card"
              style={{
                background: "linear-gradient(135deg, #10B981 0%, #059669 100%)",
                color: "white",
                border: "none",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "var(--spacing-2)",
                  marginBottom: "var(--spacing-3)",
                }}
              >
                <Award size={20} />
                <h3
                  style={{
                    fontSize: "var(--font-size-base)",
                    fontWeight: "var(--font-weight-semibold)",
                  }}
                >
                  Reputation
                </h3>
              </div>
              <p
                style={{
                  fontSize: "2.5rem",
                  fontWeight: "var(--font-weight-bold)",
                  marginBottom: "var(--spacing-1)",
                }}
              >
                {mutation.data?.reputation || "N/A"}
              </p>
              <p style={{ fontSize: "var(--font-size-sm)", opacity: 0.9 }}>
                Community rating
              </p>
            </div>
          </div>

          {/* Detailed Results Card */}
          <div className="card">
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "var(--spacing-2)",
                marginBottom: "var(--spacing-4)",
                paddingBottom: "var(--spacing-4)",
                borderBottom: "1px solid var(--color-border)",
              }}
            >
              <Shield size={24} color="var(--color-accent)" />
              <h3
                style={{
                  fontSize: "var(--font-size-xl)",
                  fontWeight: "var(--font-weight-semibold)",
                }}
              >
                Threat Analysis Details
              </h3>
            </div>
            <div
              style={{
                backgroundColor: "var(--color-bg-secondary)",
                padding: "var(--spacing-4)",
                borderRadius: "var(--radius-md)",
                fontSize: "var(--font-size-sm)",
                fontFamily: "Monaco, Courier, monospace",
                overflowX: "auto",
                maxHeight: "500px",
                overflowY: "auto",
              }}
            >
              <pre
                style={{
                  margin: 0,
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                }}
              >
                {JSON.stringify(mutation.data, null, 2)}
              </pre>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
