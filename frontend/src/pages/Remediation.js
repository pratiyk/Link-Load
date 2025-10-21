// src/pages/Remediation.js
import React, { useEffect, useState, useMemo } from "react";
import { useLocation } from "react-router-dom";
import apiClient, { API_ENDPOINTS } from "../config/api";
import SeverityBadge from "../components/SeverityBadge";
import {
  Wrench,
  Download,
  FileText,
  CheckCircle2,
  AlertOctagon,
  Loader,
  XCircle,
  Terminal,
  Package,
  AlertTriangle,
  CheckCircle,
} from "lucide-react";

export default function Remediation() {
  const location = useLocation();
  const scannedData = location.state?.vulns || [];

  const [remediationSteps, setRemediationSteps] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchRemediation = async () => {
      if (!scannedData.length) return;

      setLoading(true);
      setError("");

      const mappedVulns = scannedData.map((vuln) => ({
        id: vuln.id || "N/A",
        package: vuln.package || vuln.id || "unknown-package",
        ecosystem: vuln.ecosystem || "PyPI",
        severity:
          vuln.severity !== undefined && vuln.severity !== null
            ? parseFloat(vuln.severity)
            : 0.0,
      }));

      try {
        const response = await axios.post(
          "http://localhost:8000/api/remediate",
          mappedVulns
        );
        setRemediationSteps(response.data);
      } catch (err) {
        console.error(err);
        setError("Failed to generate remediation plan.");
      } finally {
        setLoading(false);
      }
    };

    fetchRemediation();
  }, [scannedData]);

  // Calculate remediation summary
  const remediationSummary = useMemo(() => {
    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      total: remediationSteps.length,
      fixable: 0,
    };

    remediationSteps.forEach((step) => {
      const severity = step.severity;
      if (severity >= 9.0) counts.critical++;
      else if (severity >= 7.0) counts.high++;
      else if (severity >= 4.0) counts.medium++;
      else if (severity > 0) counts.low++;

      if (step.fixable) counts.fixable++;
    });

    return counts;
  }, [remediationSteps]);

  const handleExportText = () => {
    const content = remediationSteps
      .map(
        (r, i) =>
          `#${i + 1} ${r.id}\nSeverity: ${r.severity}\nRisk Level: ${
            r.risk_level
          }\nFixable: ${r.fixable ? "Yes" : "No"}\nRemediation: ${
            r.fix_command || "Manual review required."
          }\n\n`
      )
      .join("");

    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "remediation_plan.txt";
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportShell = async () => {
    try {
      const mappedVulns = scannedData.map((vuln) => ({
        id: vuln.id || "N/A",
        package: vuln.package || vuln.id || "unknown-package",
        ecosystem: vuln.ecosystem || "PyPI",
        severity:
          vuln.severity !== undefined && vuln.severity !== null
            ? parseFloat(vuln.severity)
            : 0.0,
      }));

      const response = await apiClient.post(
        API_ENDPOINTS.remediationExport,
        mappedVulns,
        { responseType: "blob" }
      );

      const blob = new Blob([response.data], { type: "text/x-sh" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "remediate.sh";
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error(err);
      alert("Failed to export remediation script.");
    }
  };

  return (
    <div style={{ maxWidth: "1200px", margin: "0 auto" }}>
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
              background: "linear-gradient(135deg, #10B981 0%, #059669 100%)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              boxShadow: "0 8px 16px rgba(16, 185, 129, 0.25)",
              flexShrink: 0,
            }}
          >
            <Wrench size={28} color="white" strokeWidth={2} />
          </div>
          <div>
            <h1
              style={{
                fontSize: "var(--font-size-2xl)",
                fontWeight: "var(--font-weight-bold)",
                marginBottom: "var(--spacing-1)",
              }}
            >
              Remediation Plan
            </h1>
            <p
              style={{
                color: "var(--color-text-secondary)",
                fontSize: "var(--font-size-sm)",
              }}
            >
              Automated fixes and recommendations for discovered vulnerabilities
            </p>
          </div>
        </div>
      </div>

      {/* Summary Cards */}
      {remediationSteps.length > 0 && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
            gap: "var(--spacing-4)",
            marginBottom: "var(--spacing-6)",
          }}
        >
          <div
            className="card"
            style={{
              background: "linear-gradient(135deg, #7C3AED 0%, #6D28D9 100%)",
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
                Total Issues
              </h3>
            </div>
            <p
              style={{
                fontSize: "2.5rem",
                fontWeight: "var(--font-weight-bold)",
                marginBottom: "var(--spacing-1)",
              }}
            >
              {remediationSummary.total}
            </p>
            <p style={{ fontSize: "var(--font-size-sm)", opacity: 0.9 }}>
              Vulnerabilities to fix
            </p>
          </div>

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
              <CheckCircle size={20} />
              <h3
                style={{
                  fontSize: "var(--font-size-base)",
                  fontWeight: "var(--font-weight-semibold)",
                }}
              >
                Auto-Fixable
              </h3>
            </div>
            <p
              style={{
                fontSize: "2.5rem",
                fontWeight: "var(--font-weight-bold)",
                marginBottom: "var(--spacing-1)",
              }}
            >
              {remediationSummary.fixable}
            </p>
            <p style={{ fontSize: "var(--font-size-sm)", opacity: 0.9 }}>
              Can be fixed automatically
            </p>
          </div>

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
              <XCircle size={20} />
              <h3
                style={{
                  fontSize: "var(--font-size-base)",
                  fontWeight: "var(--font-weight-semibold)",
                }}
              >
                Manual Fix Required
              </h3>
            </div>
            <p
              style={{
                fontSize: "2.5rem",
                fontWeight: "var(--font-weight-bold)",
                marginBottom: "var(--spacing-1)",
              }}
            >
              {remediationSummary.total - remediationSummary.fixable}
            </p>
            <p style={{ fontSize: "var(--font-size-sm)", opacity: 0.9 }}>
              Need manual intervention
            </p>
          </div>
        </div>
      )}

      {/* Export Buttons */}
      {remediationSteps.length > 0 && !loading && !error && (
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: "var(--spacing-3)",
            marginBottom: "var(--spacing-6)",
          }}
        >
          <button onClick={handleExportText} className="btn btn-secondary">
            <FileText size={18} />
            Export as Text (.txt)
          </button>

          <button onClick={handleExportShell} className="btn btn-secondary">
            <Terminal size={18} />
            Download Shell Script (.sh)
          </button>
        </div>
      )}

      {/* Loading State */}
      {loading && (
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
            Generating Remediation Steps...
          </h3>
          <p style={{ color: "var(--color-text-secondary)" }}>
            Creating automated fixes and manual recommendations
          </p>
        </div>
      )}

      {/* Error State */}
      {error && (
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
              Generation Failed
            </h3>
            <p style={{ color: "#991B1B" }}>{error}</p>
          </div>
        </div>
      )}

      {/* Empty State */}
      {remediationSteps.length === 0 && !loading && !error && (
        <div
          className="card"
          style={{ textAlign: "center", padding: "var(--spacing-12)" }}
        >
          <Wrench
            size={64}
            style={{
              margin: "0 auto var(--spacing-4)",
              color: "var(--color-text-tertiary)",
              opacity: 0.5,
            }}
          />
          <h3
            style={{
              fontSize: "var(--font-size-lg)",
              fontWeight: "var(--font-weight-semibold)",
              marginBottom: "var(--spacing-2)",
              color: "var(--color-text-primary)",
            }}
          >
            No Remediation Plan Available
          </h3>
          <p
            style={{
              color: "var(--color-text-secondary)",
              fontSize: "var(--font-size-base)",
            }}
          >
            {scannedData.length
              ? "No remediation steps were generated for the scanned vulnerabilities"
              : "Run a vulnerability scan first to generate a remediation plan"}
          </p>
        </div>
      )}

      {/* Remediation Steps */}
      {remediationSteps.length > 0 && !loading && !error && (
        <div style={{ display: "grid", gap: "var(--spacing-5)" }}>
          {remediationSteps.map((step, index) => (
            <div key={index} className="card">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "flex-start",
                  marginBottom: "var(--spacing-3)",
                }}
              >
                <div>
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "var(--spacing-2)",
                      marginBottom: "var(--spacing-2)",
                    }}
                  >
                    <span
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        justifyContent: "center",
                        width: "28px",
                        height: "28px",
                        borderRadius: "var(--radius-full)",
                        backgroundColor: "var(--color-accent)",
                        color: "white",
                        fontSize: "var(--font-size-sm)",
                        fontWeight: "var(--font-weight-bold)",
                      }}
                    >
                      {index + 1}
                    </span>
                    <h3
                      style={{
                        fontSize: "var(--font-size-lg)",
                        fontWeight: "var(--font-weight-semibold)",
                      }}
                    >
                      {step.id}
                    </h3>
                  </div>
                  <p
                    style={{
                      fontSize: "var(--font-size-sm)",
                      color: "var(--color-text-secondary)",
                      marginLeft: "36px",
                    }}
                  >
                    {step.package} ({step.ecosystem})
                  </p>
                </div>
                <SeverityBadge severity={step.severity} />
              </div>

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))",
                  gap: "var(--spacing-4)",
                  marginTop: "var(--spacing-4)",
                  padding: "var(--spacing-4)",
                  backgroundColor: "var(--color-bg-secondary)",
                  borderRadius: "var(--radius-md)",
                }}
              >
                <div>
                  <p
                    style={{
                      fontSize: "var(--font-size-sm)",
                      marginBottom: "var(--spacing-2)",
                    }}
                  >
                    <strong style={{ color: "var(--color-text-secondary)" }}>
                      Risk Level:
                    </strong>{" "}
                    <span
                      style={{
                        color: "var(--color-text-primary)",
                        fontWeight: "var(--font-weight-medium)",
                      }}
                    >
                      {step.risk_level}
                    </span>
                  </p>
                  <p
                    style={{
                      fontSize: "var(--font-size-sm)",
                      display: "flex",
                      alignItems: "center",
                      gap: "var(--spacing-2)",
                    }}
                  >
                    <strong style={{ color: "var(--color-text-secondary)" }}>
                      Status:
                    </strong>{" "}
                    {step.fixable ? (
                      <>
                        <CheckCircle size={16} color="#059669" />
                        <span
                          style={{
                            color: "#059669",
                            fontWeight: "var(--font-weight-semibold)",
                          }}
                        >
                          Auto-Fixable
                        </span>
                      </>
                    ) : (
                      <>
                        <XCircle size={16} color="#DC2626" />
                        <span
                          style={{
                            color: "#DC2626",
                            fontWeight: "var(--font-weight-semibold)",
                          }}
                        >
                          Manual Fix Required
                        </span>
                      </>
                    )}
                  </p>
                </div>

                <div>
                  <p
                    style={{
                      fontSize: "var(--font-size-sm)",
                      fontWeight: "var(--font-weight-semibold)",
                      color: "var(--color-text-secondary)",
                      marginBottom: "var(--spacing-2)",
                      display: "flex",
                      alignItems: "center",
                      gap: "var(--spacing-2)",
                    }}
                  >
                    <Terminal size={16} />
                    Remediation Command:
                  </p>
                  <div
                    style={{
                      padding: "var(--spacing-3)",
                      backgroundColor: "white",
                      borderRadius: "var(--radius-md)",
                      border: "1px solid var(--color-border)",
                    }}
                  >
                    <code
                      style={{
                        fontSize: "var(--font-size-sm)",
                        fontFamily: "Monaco, Courier, monospace",
                        color: "var(--color-text-primary)",
                        wordBreak: "break-all",
                        display: "block",
                      }}
                    >
                      {step.fix_command ||
                        "Manual review required - no automated fix available"}
                    </code>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
