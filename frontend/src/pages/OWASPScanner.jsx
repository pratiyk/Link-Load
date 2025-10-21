import React, { useState, useEffect, useCallback } from "react";
import { useAuth } from "../context/AuthContext";
import { scannerApi } from "../services/scannerApi";
import { useNavigate } from "react-router-dom";
import {
  ShieldAlert,
  Play,
  Pause,
  Download,
  History,
  Settings,
  AlertOctagon,
  CheckCircle2,
  XCircle,
  Clock,
  Loader,
  FileText,
  Globe,
  Shield,
  Activity,
  ScanSearch,
  AlertTriangle,
  CheckCircle,
} from "lucide-react";

const OWASPScanner = () => {
  const { user, isAuthenticated, scans, addScan, updateScan } = useAuth();
  const [activeTab, setActiveTab] = useState("new-scan");
  const [scanConfig, setScanConfig] = useState({
    target_url: "",
    scan_types: ["zap_active", "nuclei"],
    include_low_risk: false,
    max_scan_time: 1800,
    authenticated: false,
    custom_headers: {},
    scan_depth: 2,
  });
  const [currentScan, setCurrentScan] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [scanResults, setScanResults] = useState(null);
  const navigate = useNavigate();

  // Redirect to login if not authenticated
  useEffect(() => {
    if (!isAuthenticated) {
      navigate("/login");
    }
  }, [isAuthenticated, navigate]);

  // Initialize from URL params
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const scanId = params.get("scanId");

    if (scanId) {
      const scan = scans.find((s) => s.scan_id === scanId);
      if (scan) {
        handleViewScan(scan);
      }
    }
  }, [scans]);

  const startScan = async () => {
    if (!scanConfig.target_url) {
      setError("Please enter a valid URL");
      return;
    }

    try {
      setLoading(true);
      setError("");

      const response = await scannerApi.startScan({
        ...scanConfig,
        user_id: user.id,
      });

      const scan = {
        scan_id: response.scan_id,
        target_url: scanConfig.target_url,
        scan_types: scanConfig.scan_types,
        status: "queued",
        started_at: new Date().toISOString(),
        progress: 0,
      };

      addScan(scan);
      setCurrentScan(scan);
      setActiveTab("scan-progress");
      setScanResults(null);

      // Start polling for updates
      pollScanProgress(response.scan_id);
    } catch (err) {
      console.error("Scan start failed:", err);
      setError(err.response?.data?.detail || "Failed to start scan");
    } finally {
      setLoading(false);
    }
  };

  const pollScanProgress = useCallback(
    async (scanId) => {
      const interval = setInterval(async () => {
        try {
          const progress = await scannerApi.getScanProgress(scanId);
          updateScan(scanId, progress);

          if (progress.status === "completed" || progress.status === "failed") {
            clearInterval(interval);
            if (progress.status === "completed") {
              fetchScanResults(scanId);
            }
          }
        } catch (err) {
          console.error("Progress check failed:", err);
          clearInterval(interval);
        }
      }, 5000);
    },
    [updateScan]
  );

  const fetchScanResults = async (scanId) => {
    try {
      const results = await scannerApi.getScanResult(scanId);
      setScanResults(results);
      updateScan(scanId, {
        vulnerabilities: results.vulnerabilities,
        summary: results.summary,
      });
    } catch (err) {
      console.error("Failed to fetch results:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleViewScan = (scan) => {
    setCurrentScan(scan);

    if (scan.status === "completed" && scan.vulnerabilities) {
      setScanResults({
        vulnerabilities: scan.vulnerabilities,
        summary: scan.summary,
      });
      setActiveTab("results");
    } else if (scan.status === "in-progress") {
      setActiveTab("scan-progress");
      pollScanProgress(scan.scan_id);
    } else {
      setActiveTab("scan-details");
    }
  };

  const cancelScan = async () => {
    if (!currentScan) return;

    try {
      await scannerApi.cancelScan(currentScan.scan_id);
      updateScan(currentScan.scan_id, { status: "cancelled" });
      setCurrentScan((prev) => ({ ...prev, status: "cancelled" }));
    } catch (err) {
      console.error("Cancel scan failed:", err);
      setError("Failed to cancel scan");
    }
  };

  const exportReport = async (format = "pdf") => {
    if (!currentScan) return;

    try {
      const response = await scannerApi.exportScanResults(currentScan.scan_id, {
        format,
        include_false_positives: false,
        include_low_risk: scanConfig.include_low_risk,
      });

      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute(
        "download",
        `scan-report-${currentScan.scan_id}.${format}`
      );
      document.body.appendChild(link);
      link.click();
      link.remove();

      // toast.success(`Report exported as ${format.toUpperCase()}`);
    } catch (err) {
      console.error("Export failed:", err);
      // toast.error("Failed to export report");
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case "completed":
        return (
          <CheckCircle2
            size={20}
            style={{ color: "#10B981" }}
            strokeWidth={2}
          />
        );
      case "failed":
        return (
          <XCircle size={20} style={{ color: "#DC2626" }} strokeWidth={2} />
        );
      case "cancelled":
        return (
          <XCircle size={20} style={{ color: "#F59E0B" }} strokeWidth={2} />
        );
      case "in-progress":
        return <Clock size={20} style={{ color: "#3B82F6" }} strokeWidth={2} />;
      default:
        return (
          <Clock size={20} style={{ color: "var(--color-text-tertiary)" }} />
        );
    }
  };

  return (
    <div
      style={{
        maxWidth: "1400px",
        margin: "0 auto",
        padding: "var(--spacing-8) var(--spacing-4)",
      }}
    >
      {/* Header with gradient icon */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "var(--spacing-3)",
          marginBottom: "var(--spacing-6)",
        }}
      >
        <div
          style={{
            width: "56px",
            height: "56px",
            borderRadius: "var(--radius-lg)",
            background: "linear-gradient(135deg, #DC2626 0%, #991B1B 100%)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            boxShadow: "0 8px 16px rgba(220, 38, 38, 0.25)",
            flexShrink: 0,
          }}
        >
          <ShieldAlert size={28} color="white" strokeWidth={2} />
        </div>
        <div>
          <h1
            style={{
              fontSize: "var(--font-size-2xl)",
              fontWeight: "700",
              color: "var(--color-text-primary)",
              margin: 0,
            }}
          >
            OWASP Security Scanner
          </h1>
          <p
            style={{
              fontSize: "var(--font-size-sm)",
              color: "var(--color-text-secondary)",
              margin: 0,
            }}
          >
            Comprehensive vulnerability scanning with ZAP & Nuclei
          </p>
        </div>
        <div
          style={{
            marginLeft: "auto",
            display: "flex",
            gap: "var(--spacing-2)",
          }}
        >
          <button
            className={
              activeTab === "bookmark" ? "btn btn-primary" : "btn btn-secondary"
            }
            onClick={() => setActiveTab("bookmark")}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "var(--spacing-2)",
            }}
          >
            <History size={18} />
            Scan History
          </button>
          {currentScan && (
            <button
              className="btn btn-secondary"
              onClick={() => exportReport("pdf")}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "var(--spacing-2)",
              }}
            >
              <Download size={18} />
              Export
            </button>
          )}
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div
          style={{
            padding: "var(--spacing-4)",
            borderRadius: "var(--radius-lg)",
            backgroundColor: "#FEE2E2",
            border: "1px solid #FCA5A5",
            marginBottom: "var(--spacing-6)",
            display: "flex",
            gap: "var(--spacing-3)",
          }}
        >
          <AlertTriangle size={24} color="#DC2626" style={{ flexShrink: 0 }} />
          <div>
            <h3
              style={{
                color: "#DC2626",
                fontWeight: "600",
                fontSize: "var(--font-size-base)",
                margin: "0 0 var(--spacing-1) 0",
              }}
            >
              Scan Error
            </h3>
            <p style={{ color: "#991B1B", margin: 0 }}>{error}</p>
          </div>
        </div>
      )}

      {/* Modern Tab Navigation */}
      <div
        style={{
          display: "flex",
          gap: "var(--spacing-2)",
          borderBottom: "2px solid var(--color-border)",
          marginBottom: "var(--spacing-6)",
          overflowX: "auto",
        }}
      >
        <button
          style={{
            padding: "var(--spacing-3) var(--spacing-4)",
            fontSize: "var(--font-size-base)",
            fontWeight: "500",
            border: "none",
            borderBottom:
              activeTab === "new-scan"
                ? "2px solid var(--color-accent)"
                : "2px solid transparent",
            background: "transparent",
            color:
              activeTab === "new-scan"
                ? "var(--color-accent)"
                : "var(--color-text-secondary)",
            cursor: "pointer",
            transition: "all 0.2s",
            display: "flex",
            alignItems: "center",
            gap: "var(--spacing-2)",
            marginBottom: "-2px",
          }}
          onClick={() => setActiveTab("new-scan")}
        >
          <Play size={18} />
          New Scan
        </button>
        <button
          style={{
            padding: "var(--spacing-3) var(--spacing-4)",
            fontSize: "var(--font-size-base)",
            fontWeight: "500",
            border: "none",
            borderBottom:
              activeTab === "scan-details"
                ? "2px solid var(--color-accent)"
                : "2px solid transparent",
            background: "transparent",
            color:
              activeTab === "scan-details"
                ? "var(--color-accent)"
                : "var(--color-text-secondary)",
            cursor: currentScan ? "pointer" : "not-allowed",
            transition: "all 0.2s",
            display: "flex",
            alignItems: "center",
            gap: "var(--spacing-2)",
            marginBottom: "-2px",
            opacity: currentScan ? 1 : 0.5,
          }}
          onClick={() => currentScan && setActiveTab("scan-details")}
          disabled={!currentScan}
        >
          <FileText size={18} />
          Scan Details
        </button>
        <button
          style={{
            padding: "var(--spacing-3) var(--spacing-4)",
            fontSize: "var(--font-size-base)",
            fontWeight: "500",
            border: "none",
            borderBottom:
              activeTab === "scan-progress"
                ? "2px solid var(--color-accent)"
                : "2px solid transparent",
            background: "transparent",
            color:
              activeTab === "scan-progress"
                ? "var(--color-accent)"
                : "var(--color-text-secondary)",
            cursor: currentScan ? "pointer" : "not-allowed",
            transition: "all 0.2s",
            display: "flex",
            alignItems: "center",
            gap: "var(--spacing-2)",
            marginBottom: "-2px",
            opacity: currentScan ? 1 : 0.5,
          }}
          onClick={() => currentScan && setActiveTab("scan-progress")}
          disabled={!currentScan}
        >
          <Activity size={18} />
          Progress
        </button>
        <button
          style={{
            padding: "var(--spacing-3) var(--spacing-4)",
            fontSize: "var(--font-size-base)",
            fontWeight: "500",
            border: "none",
            borderBottom:
              activeTab === "results"
                ? "2px solid var(--color-accent)"
                : "2px solid transparent",
            background: "transparent",
            color:
              activeTab === "results"
                ? "var(--color-accent)"
                : "var(--color-text-secondary)",
            cursor: scanResults ? "pointer" : "not-allowed",
            transition: "all 0.2s",
            display: "flex",
            alignItems: "center",
            gap: "var(--spacing-2)",
            marginBottom: "-2px",
            opacity: scanResults ? 1 : 0.5,
          }}
          onClick={() => scanResults && setActiveTab("results")}
          disabled={!scanResults}
        >
          <Shield size={18} />
          Results
        </button>
      </div>

      {/* Tab Content */}
      <div>
        {activeTab === "new-scan" && (
          <div className="card">
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "var(--spacing-2)",
                marginBottom: "var(--spacing-4)",
              }}
            >
              <Settings size={20} color="var(--color-accent)" />
              <h3
                style={{
                  fontSize: "var(--font-size-lg)",
                  fontWeight: "600",
                  margin: 0,
                }}
              >
                Configure New Scan
              </h3>
            </div>

            <div
              style={{
                display: "flex",
                flexDirection: "column",
                gap: "var(--spacing-4)",
              }}
            >
              {/* Target URL Input */}
              <div>
                <label className="input-label">
                  <Globe size={16} />
                  Target URL
                </label>
                <input
                  type="url"
                  value={scanConfig.target_url}
                  onChange={(e) =>
                    setScanConfig({ ...scanConfig, target_url: e.target.value })
                  }
                  placeholder="https://example.com"
                  className="input"
                />
              </div>

              {/* Scan Types */}
              <div>
                <label className="input-label">
                  <Shield size={16} />
                  Scan Types
                </label>
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "var(--spacing-2)",
                    marginTop: "var(--spacing-2)",
                  }}
                >
                  {[
                    {
                      value: "zap_active",
                      label: "ZAP Active Scan (Comprehensive)",
                    },
                    { value: "nuclei", label: "Nuclei Templates (Fast)" },
                    { value: "zap_passive", label: "ZAP Passive Scan (Safe)" },
                  ].map((type) => (
                    <label
                      key={type.value}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        cursor: "pointer",
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={scanConfig.scan_types.includes(type.value)}
                        onChange={(e) => {
                          const newTypes = e.target.checked
                            ? [...scanConfig.scan_types, type.value]
                            : scanConfig.scan_types.filter(
                                (t) => t !== type.value
                              );
                          setScanConfig({
                            ...scanConfig,
                            scan_types: newTypes,
                          });
                        }}
                        style={{
                          marginRight: "var(--spacing-2)",
                          cursor: "pointer",
                        }}
                      />
                      <span style={{ fontSize: "var(--font-size-sm)" }}>
                        {type.label}
                      </span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Options */}
              <div>
                <label className="input-label">
                  <Settings size={16} />
                  Scan Options
                </label>
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "var(--spacing-2)",
                    marginTop: "var(--spacing-2)",
                  }}
                >
                  <label
                    style={{
                      display: "flex",
                      alignItems: "center",
                      cursor: "pointer",
                    }}
                  >
                    <input
                      type="checkbox"
                      id="include-low-risk"
                      checked={scanConfig.include_low_risk}
                      onChange={(e) =>
                        setScanConfig({
                          ...scanConfig,
                          include_low_risk: e.target.checked,
                        })
                      }
                      style={{
                        marginRight: "var(--spacing-2)",
                        cursor: "pointer",
                      }}
                    />
                    <span style={{ fontSize: "var(--font-size-sm)" }}>
                      Include Low Risk Vulnerabilities
                    </span>
                  </label>

                  <label
                    style={{
                      display: "flex",
                      alignItems: "center",
                      cursor: "pointer",
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={scanConfig.authenticated}
                      onChange={(e) =>
                        setScanConfig({
                          ...scanConfig,
                          authenticated: e.target.checked,
                        })
                      }
                      style={{
                        marginRight: "var(--spacing-2)",
                        cursor: "pointer",
                      }}
                    />
                    <span style={{ fontSize: "var(--font-size-sm)" }}>
                      Authenticated Scan
                    </span>
                  </label>
                </div>
              </div>

              {/* Start Scan Button */}
              <button
                onClick={startScan}
                disabled={loading || !scanConfig.target_url}
                className="btn btn-primary"
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "var(--spacing-2)",
                }}
              >
                {loading ? (
                  <>
                    <Loader size={20} className="spinner" />
                    Starting Scan...
                  </>
                ) : (
                  <>
                    <Play size={20} />
                    Start Security Scan
                  </>
                )}
              </button>
            </div>
          </div>
        )}

        {activeTab === "scan-details" && currentScan && (
          <div className="card">
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "var(--spacing-2)",
                marginBottom: "var(--spacing-5)",
              }}
            >
              <FileText size={20} color="var(--color-accent)" />
              <h3
                style={{
                  fontSize: "var(--font-size-lg)",
                  fontWeight: "600",
                  margin: 0,
                }}
              >
                Scan Configuration
              </h3>
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))",
                gap: "var(--spacing-6)",
              }}
            >
              <div>
                <div style={{ marginBottom: "var(--spacing-4)" }}>
                  <label
                    style={{
                      fontSize: "var(--font-size-sm)",
                      fontWeight: "600",
                      color: "var(--color-text-secondary)",
                      marginBottom: "var(--spacing-1)",
                      display: "block",
                    }}
                  >
                    Scan ID
                  </label>
                  <p
                    style={{
                      fontSize: "var(--font-size-base)",
                      color: "var(--color-text-primary)",
                      margin: 0,
                      fontFamily: "monospace",
                      backgroundColor: "var(--color-bg-secondary)",
                      padding: "var(--spacing-2)",
                      borderRadius: "var(--radius-md)",
                    }}
                  >
                    {currentScan.scan_id}
                  </p>
                </div>

                <div style={{ marginBottom: "var(--spacing-4)" }}>
                  <label
                    style={{
                      fontSize: "var(--font-size-sm)",
                      fontWeight: "600",
                      color: "var(--color-text-secondary)",
                      marginBottom: "var(--spacing-1)",
                      display: "block",
                    }}
                  >
                    Target URL
                  </label>
                  <p
                    style={{
                      fontSize: "var(--font-size-base)",
                      color: "var(--color-text-primary)",
                      margin: 0,
                      wordBreak: "break-all",
                    }}
                  >
                    {currentScan.target_url}
                  </p>
                </div>

                <div>
                  <label
                    style={{
                      fontSize: "var(--font-size-sm)",
                      fontWeight: "600",
                      color: "var(--color-text-secondary)",
                      marginBottom: "var(--spacing-1)",
                      display: "block",
                    }}
                  >
                    Started At
                  </label>
                  <p
                    style={{
                      fontSize: "var(--font-size-base)",
                      color: "var(--color-text-primary)",
                      margin: 0,
                    }}
                  >
                    {new Date(currentScan.started_at).toLocaleString()}
                  </p>
                </div>
              </div>

              <div>
                <div style={{ marginBottom: "var(--spacing-4)" }}>
                  <label
                    style={{
                      fontSize: "var(--font-size-sm)",
                      fontWeight: "600",
                      color: "var(--color-text-secondary)",
                      marginBottom: "var(--spacing-2)",
                      display: "block",
                    }}
                  >
                    Scan Types
                  </label>
                  <div
                    style={{
                      display: "flex",
                      flexWrap: "wrap",
                      gap: "var(--spacing-2)",
                    }}
                  >
                    {currentScan.scan_types.map((type) => (
                      <span
                        key={type}
                        className="badge badge-info"
                        style={{ fontSize: "var(--font-size-xs)" }}
                      >
                        {type}
                      </span>
                    ))}
                  </div>
                </div>

                <div style={{ marginBottom: "var(--spacing-4)" }}>
                  <label
                    style={{
                      fontSize: "var(--font-size-sm)",
                      fontWeight: "600",
                      color: "var(--color-text-secondary)",
                      marginBottom: "var(--spacing-2)",
                      display: "block",
                    }}
                  >
                    Status
                  </label>
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "var(--spacing-2)",
                    }}
                  >
                    {getStatusIcon(currentScan.status)}
                    <span
                      style={{
                        textTransform: "capitalize",
                        fontSize: "var(--font-size-base)",
                        fontWeight: "500",
                      }}
                    >
                      {currentScan.status.replace("-", " ")}
                    </span>
                  </div>
                </div>

                {currentScan.completed_at && (
                  <div>
                    <label
                      style={{
                        fontSize: "var(--font-size-sm)",
                        fontWeight: "600",
                        color: "var(--color-text-secondary)",
                        marginBottom: "var(--spacing-1)",
                        display: "block",
                      }}
                    >
                      Completed At
                    </label>
                    <p
                      style={{
                        fontSize: "var(--font-size-base)",
                        color: "var(--color-text-primary)",
                        margin: 0,
                      }}
                    >
                      {new Date(currentScan.completed_at).toLocaleString()}
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === "scan-progress" && currentScan && (
          <div className="card">
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginBottom: "var(--spacing-5)",
                flexWrap: "wrap",
                gap: "var(--spacing-3)",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "var(--spacing-2)",
                }}
              >
                <Activity size={20} color="var(--color-accent)" />
                <h3
                  style={{
                    fontSize: "var(--font-size-lg)",
                    fontWeight: "600",
                    margin: 0,
                  }}
                >
                  Scan Progress
                </h3>
              </div>
              <button
                className="btn btn-secondary"
                onClick={cancelScan}
                disabled={currentScan.status !== "in-progress"}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "var(--spacing-2)",
                }}
              >
                <Pause size={18} />
                Cancel Scan
              </button>
            </div>

            {/* Progress Bar */}
            <div style={{ marginBottom: "var(--spacing-6)" }}>
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  marginBottom: "var(--spacing-2)",
                  fontSize: "var(--font-size-sm)",
                  color: "var(--color-text-secondary)",
                }}
              >
                <span style={{ fontWeight: "500" }}>
                  {currentScan.current_step || "Initializing scan..."}
                </span>
                <span
                  style={{ fontWeight: "600", color: "var(--color-accent)" }}
                >
                  {Math.round(currentScan.progress || 0)}%
                </span>
              </div>
              <div
                style={{
                  width: "100%",
                  height: "12px",
                  backgroundColor: "var(--color-bg-secondary)",
                  borderRadius: "var(--radius-full)",
                  overflow: "hidden",
                  boxShadow: "inset 0 1px 3px rgba(0,0,0,0.1)",
                }}
              >
                <div
                  style={{
                    height: "100%",
                    borderRadius: "var(--radius-full)",
                    transition: "all 0.3s ease",
                    width: `${currentScan.progress || 0}%`,
                    background:
                      currentScan.status === "failed"
                        ? "linear-gradient(90deg, #DC2626 0%, #991B1B 100%)"
                        : currentScan.status === "cancelled"
                        ? "linear-gradient(90deg, #F59E0B 0%, #D97706 100%)"
                        : "linear-gradient(90deg, #478504 0%, #3a6a03 100%)",
                    boxShadow: "0 2px 8px rgba(71, 133, 4, 0.3)",
                  }}
                ></div>
              </div>
            </div>

            {/* Stats Cards */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                gap: "var(--spacing-4)",
                marginBottom: "var(--spacing-5)",
              }}
            >
              <div
                className="card"
                style={{
                  background:
                    "linear-gradient(135deg, #3B82F6 0%, #2563EB 100%)",
                  color: "white",
                  border: "none",
                  textAlign: "center",
                }}
              >
                <div
                  style={{
                    fontSize: "var(--font-size-sm)",
                    opacity: 0.9,
                    marginBottom: "var(--spacing-2)",
                  }}
                >
                  URLs Scanned
                </div>
                <div
                  style={{
                    fontSize: "2.5rem",
                    fontWeight: "bold",
                    lineHeight: 1,
                  }}
                >
                  {currentScan.scanned_urls || 0}
                </div>
              </div>

              <div
                className="card"
                style={{
                  background:
                    "linear-gradient(135deg, #F97316 0%, #EA580C 100%)",
                  color: "white",
                  border: "none",
                  textAlign: "center",
                }}
              >
                <div
                  style={{
                    fontSize: "var(--font-size-sm)",
                    opacity: 0.9,
                    marginBottom: "var(--spacing-2)",
                  }}
                >
                  Vulnerabilities Found
                </div>
                <div
                  style={{
                    fontSize: "2.5rem",
                    fontWeight: "bold",
                    lineHeight: 1,
                  }}
                >
                  {currentScan.vulnerabilities_found || 0}
                </div>
              </div>

              <div
                className="card"
                style={{
                  background:
                    "linear-gradient(135deg, #10B981 0%, #059669 100%)",
                  color: "white",
                  border: "none",
                  textAlign: "center",
                }}
              >
                <div
                  style={{
                    fontSize: "var(--font-size-sm)",
                    opacity: 0.9,
                    marginBottom: "var(--spacing-2)",
                  }}
                >
                  Estimated Time
                </div>
                <div
                  style={{
                    fontSize: "2.5rem",
                    fontWeight: "bold",
                    lineHeight: 1,
                  }}
                >
                  {currentScan.estimated_time_remaining
                    ? `${Math.ceil(currentScan.estimated_time_remaining / 60)}m`
                    : "—"}
                </div>
              </div>
            </div>

            {currentScan.status === "completed" && (
              <div style={{ textAlign: "center" }}>
                <button
                  className="btn btn-primary"
                  onClick={() => setActiveTab("results")}
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: "var(--spacing-2)",
                  }}
                >
                  <Shield size={20} />
                  View Scan Results
                </button>
              </div>
            )}
          </div>
        )}

        {activeTab === "results" && scanResults && (
          <div className="card">
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "var(--spacing-2)",
                marginBottom: "var(--spacing-5)",
              }}
            >
              <Shield size={20} color="var(--color-accent)" />
              <h3
                style={{
                  fontSize: "var(--font-size-lg)",
                  fontWeight: "600",
                  margin: 0,
                }}
              >
                Vulnerability Report
              </h3>
            </div>

            {scanResults.summary && (
              <div style={{ marginBottom: "var(--spacing-6)" }}>
                <h4
                  style={{
                    fontSize: "var(--font-size-base)",
                    fontWeight: "600",
                    color: "var(--color-text-secondary)",
                    marginBottom: "var(--spacing-4)",
                  }}
                >
                  Summary
                </h4>
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
                    gap: "var(--spacing-3)",
                  }}
                >
                  <div
                    className="card"
                    style={{
                      background:
                        "linear-gradient(135deg, #DC2626 0%, #991B1B 100%)",
                      color: "white",
                      border: "none",
                      textAlign: "center",
                      padding: "var(--spacing-4)",
                    }}
                  >
                    <div
                      style={{
                        fontSize: "2.5rem",
                        fontWeight: "bold",
                        lineHeight: 1,
                        marginBottom: "var(--spacing-2)",
                      }}
                    >
                      {scanResults.summary.critical || 0}
                    </div>
                    <div
                      style={{ fontSize: "var(--font-size-sm)", opacity: 0.9 }}
                    >
                      Critical
                    </div>
                  </div>

                  <div
                    className="card"
                    style={{
                      background:
                        "linear-gradient(135deg, #F97316 0%, #EA580C 100%)",
                      color: "white",
                      border: "none",
                      textAlign: "center",
                      padding: "var(--spacing-4)",
                    }}
                  >
                    <div
                      style={{
                        fontSize: "2.5rem",
                        fontWeight: "bold",
                        lineHeight: 1,
                        marginBottom: "var(--spacing-2)",
                      }}
                    >
                      {scanResults.summary.high || 0}
                    </div>
                    <div
                      style={{ fontSize: "var(--font-size-sm)", opacity: 0.9 }}
                    >
                      High
                    </div>
                  </div>

                  <div
                    className="card"
                    style={{
                      background:
                        "linear-gradient(135deg, #F59E0B 0%, #D97706 100%)",
                      color: "white",
                      border: "none",
                      textAlign: "center",
                      padding: "var(--spacing-4)",
                    }}
                  >
                    <div
                      style={{
                        fontSize: "2.5rem",
                        fontWeight: "bold",
                        lineHeight: 1,
                        marginBottom: "var(--spacing-2)",
                      }}
                    >
                      {scanResults.summary.medium || 0}
                    </div>
                    <div
                      style={{ fontSize: "var(--font-size-sm)", opacity: 0.9 }}
                    >
                      Medium
                    </div>
                  </div>

                  <div
                    className="card"
                    style={{
                      background:
                        "linear-gradient(135deg, #3B82F6 0%, #2563EB 100%)",
                      color: "white",
                      border: "none",
                      textAlign: "center",
                      padding: "var(--spacing-4)",
                    }}
                  >
                    <div
                      style={{
                        fontSize: "2.5rem",
                        fontWeight: "bold",
                        lineHeight: 1,
                        marginBottom: "var(--spacing-2)",
                      }}
                    >
                      {scanResults.summary.low || 0}
                    </div>
                    <div
                      style={{ fontSize: "var(--font-size-sm)", opacity: 0.9 }}
                    >
                      Low
                    </div>
                  </div>
                </div>
              </div>
            )}

            <h4
              style={{
                fontSize: "var(--font-size-base)",
                fontWeight: "600",
                color: "var(--color-text-secondary)",
                marginBottom: "var(--spacing-4)",
              }}
            >
              Detected Vulnerabilities
            </h4>

            {scanResults.vulnerabilities &&
            scanResults.vulnerabilities.length > 0 ? (
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: "var(--spacing-3)",
                }}
              >
                {scanResults.vulnerabilities.map((vuln, index) => (
                  <div
                    key={index}
                    className="card"
                    onClick={() => setSelectedVuln(vuln)}
                    style={{
                      cursor: "pointer",
                      transition: "all 0.2s",
                      border: "1px solid var(--color-border)",
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.borderColor = "var(--color-accent)";
                      e.currentTarget.style.boxShadow =
                        "0 4px 12px rgba(0,0,0,0.1)";
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.borderColor = "var(--color-border)";
                      e.currentTarget.style.boxShadow = "none";
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "flex-start",
                        marginBottom: "var(--spacing-2)",
                        gap: "var(--spacing-3)",
                      }}
                    >
                      <h5
                        style={{
                          fontWeight: "600",
                          fontSize: "var(--font-size-base)",
                          margin: 0,
                          flex: 1,
                        }}
                      >
                        {vuln.name}
                      </h5>
                      <span
                        className={`badge ${
                          vuln.severity === "critical"
                            ? "badge-danger"
                            : vuln.severity === "high"
                            ? "badge-danger"
                            : vuln.severity === "medium"
                            ? "badge-warning"
                            : "badge-info"
                        }`}
                        style={{
                          textTransform: "uppercase",
                          fontSize: "var(--font-size-xs)",
                          flexShrink: 0,
                        }}
                      >
                        {vuln.severity}
                      </span>
                    </div>
                    <p
                      style={{
                        color: "var(--color-text-secondary)",
                        marginBottom: "var(--spacing-2)",
                        fontSize: "var(--font-size-sm)",
                        wordBreak: "break-all",
                      }}
                    >
                      <Globe
                        size={14}
                        style={{
                          display: "inline",
                          marginRight: "var(--spacing-1)",
                          verticalAlign: "middle",
                        }}
                      />
                      {vuln.url}
                    </p>
                    <p
                      style={{
                        fontSize: "var(--font-size-sm)",
                        color: "var(--color-text-tertiary)",
                        margin: 0,
                        lineHeight: 1.5,
                      }}
                    >
                      {vuln.description}
                    </p>
                  </div>
                ))}
              </div>
            ) : (
              <div
                style={{
                  textAlign: "center",
                  padding: "var(--spacing-8)",
                  color: "var(--color-text-tertiary)",
                }}
              >
                <CheckCircle
                  size={48}
                  style={{
                    color: "#10B981",
                    marginBottom: "var(--spacing-3)",
                  }}
                />
                <p
                  style={{
                    fontSize: "var(--font-size-base)",
                    fontWeight: "500",
                    margin: 0,
                  }}
                >
                  No vulnerabilities detected
                </p>
                <p
                  style={{
                    fontSize: "var(--font-size-sm)",
                    margin: "var(--spacing-2) 0 0 0",
                  }}
                >
                  Your application appears to be secure!
                </p>
              </div>
            )}
          </div>
        )}

        {activeTab === "bookmark" && (
          <div className="card">
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "var(--spacing-2)",
                marginBottom: "var(--spacing-5)",
              }}
            >
              <History size={20} color="var(--color-accent)" />
              <h3
                style={{
                  fontSize: "var(--font-size-lg)",
                  fontWeight: "600",
                  margin: 0,
                }}
              >
                Scan History
              </h3>
            </div>

            {scans && scans.length > 0 ? (
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: "var(--spacing-3)",
                }}
              >
                {scans.map((scan) => (
                  <div
                    key={scan.scan_id}
                    className="card"
                    onClick={() => handleViewScan(scan)}
                    style={{
                      cursor: "pointer",
                      transition: "all 0.2s",
                      border: "1px solid var(--color-border)",
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.borderColor = "var(--color-accent)";
                      e.currentTarget.style.boxShadow =
                        "0 4px 12px rgba(0,0,0,0.1)";
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.borderColor = "var(--color-border)";
                      e.currentTarget.style.boxShadow = "none";
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        gap: "var(--spacing-3)",
                        flexWrap: "wrap",
                      }}
                    >
                      <div style={{ flex: 1, minWidth: "200px" }}>
                        <h5
                          style={{
                            fontWeight: "600",
                            fontSize: "var(--font-size-base)",
                            margin: "0 0 var(--spacing-1) 0",
                            wordBreak: "break-all",
                          }}
                        >
                          {scan.target_url}
                        </h5>
                        <p
                          style={{
                            fontSize: "var(--font-size-sm)",
                            color: "var(--color-text-tertiary)",
                            margin: 0,
                          }}
                        >
                          <Clock
                            size={14}
                            style={{
                              display: "inline",
                              marginRight: "var(--spacing-1)",
                              verticalAlign: "middle",
                            }}
                          />
                          {new Date(scan.started_at).toLocaleString()}
                        </p>
                      </div>
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: "var(--spacing-2)",
                        }}
                      >
                        {getStatusIcon(scan.status)}
                        <span
                          style={{
                            textTransform: "capitalize",
                            fontSize: "var(--font-size-sm)",
                            fontWeight: "500",
                          }}
                        >
                          {scan.status.replace("-", " ")}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div
                style={{
                  textAlign: "center",
                  padding: "var(--spacing-8)",
                  color: "var(--color-text-tertiary)",
                }}
              >
                <History
                  size={48}
                  style={{
                    color: "var(--color-text-tertiary)",
                    marginBottom: "var(--spacing-3)",
                  }}
                />
                <p
                  style={{
                    fontSize: "var(--font-size-base)",
                    fontWeight: "500",
                    margin: 0,
                  }}
                >
                  No scan history available
                </p>
                <p
                  style={{
                    fontSize: "var(--font-size-sm)",
                    margin: "var(--spacing-2) 0 0 0",
                  }}
                >
                  Start a new scan to see your history here
                </p>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Vulnerability Details Modal */}
      {selectedVuln && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            backgroundColor: "rgba(0, 0, 0, 0.5)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
            padding: "var(--spacing-4)",
          }}
          onClick={() => setSelectedVuln(null)}
        >
          <div
            className="card"
            style={{
              maxWidth: "600px",
              width: "100%",
              maxHeight: "80vh",
              overflowY: "auto",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                display: "flex",
                alignItems: "flex-start",
                justifyContent: "space-between",
                marginBottom: "var(--spacing-4)",
                gap: "var(--spacing-3)",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "var(--spacing-2)",
                  flex: 1,
                }}
              >
                <AlertTriangle size={24} color="#DC2626" />
                <h3
                  style={{
                    fontSize: "var(--font-size-xl)",
                    fontWeight: "700",
                    margin: 0,
                  }}
                >
                  Vulnerability Details
                </h3>
              </div>
              <button
                onClick={() => setSelectedVuln(null)}
                style={{
                  background: "transparent",
                  border: "none",
                  cursor: "pointer",
                  padding: "var(--spacing-1)",
                  color: "var(--color-text-tertiary)",
                  transition: "color 0.2s",
                }}
                onMouseEnter={(e) =>
                  (e.currentTarget.style.color = "var(--color-text-primary)")
                }
                onMouseLeave={(e) =>
                  (e.currentTarget.style.color = "var(--color-text-tertiary)")
                }
              >
                <XCircle size={24} />
              </button>
            </div>

            <div
              style={{
                display: "flex",
                flexDirection: "column",
                gap: "var(--spacing-4)",
              }}
            >
              <div>
                <label
                  style={{
                    fontSize: "var(--font-size-sm)",
                    fontWeight: "600",
                    color: "var(--color-text-secondary)",
                    display: "block",
                    marginBottom: "var(--spacing-1)",
                  }}
                >
                  Vulnerability Name
                </label>
                <p
                  style={{
                    fontSize: "var(--font-size-base)",
                    color: "var(--color-text-primary)",
                    margin: 0,
                    fontWeight: "500",
                  }}
                >
                  {selectedVuln.name}
                </p>
              </div>

              <div>
                <label
                  style={{
                    fontSize: "var(--font-size-sm)",
                    fontWeight: "600",
                    color: "var(--color-text-secondary)",
                    display: "block",
                    marginBottom: "var(--spacing-1)",
                  }}
                >
                  Severity Level
                </label>
                <span
                  className={`badge ${
                    selectedVuln.severity === "critical"
                      ? "badge-danger"
                      : selectedVuln.severity === "high"
                      ? "badge-danger"
                      : selectedVuln.severity === "medium"
                      ? "badge-warning"
                      : "badge-info"
                  }`}
                  style={{
                    textTransform: "uppercase",
                    fontSize: "var(--font-size-sm)",
                  }}
                >
                  {selectedVuln.severity}
                </span>
              </div>

              <div>
                <label
                  style={{
                    fontSize: "var(--font-size-sm)",
                    fontWeight: "600",
                    color: "var(--color-text-secondary)",
                    display: "block",
                    marginBottom: "var(--spacing-1)",
                  }}
                >
                  Affected URL
                </label>
                <p
                  style={{
                    fontSize: "var(--font-size-sm)",
                    color: "var(--color-text-primary)",
                    margin: 0,
                    wordBreak: "break-all",
                    fontFamily: "monospace",
                    backgroundColor: "var(--color-bg-secondary)",
                    padding: "var(--spacing-2)",
                    borderRadius: "var(--radius-md)",
                  }}
                >
                  {selectedVuln.url}
                </p>
              </div>

              {selectedVuln.parameter && (
                <div>
                  <label
                    style={{
                      fontSize: "var(--font-size-sm)",
                      fontWeight: "600",
                      color: "var(--color-text-secondary)",
                      display: "block",
                      marginBottom: "var(--spacing-1)",
                    }}
                  >
                    Parameter
                  </label>
                  <p
                    style={{
                      fontSize: "var(--font-size-sm)",
                      color: "var(--color-text-primary)",
                      margin: 0,
                      fontFamily: "monospace",
                      backgroundColor: "var(--color-bg-secondary)",
                      padding: "var(--spacing-2)",
                      borderRadius: "var(--radius-md)",
                    }}
                  >
                    {selectedVuln.parameter}
                  </p>
                </div>
              )}

              {selectedVuln.discovered_at && (
                <div>
                  <label
                    style={{
                      fontSize: "var(--font-size-sm)",
                      fontWeight: "600",
                      color: "var(--color-text-secondary)",
                      display: "block",
                      marginBottom: "var(--spacing-1)",
                    }}
                  >
                    Discovered At
                  </label>
                  <p
                    style={{
                      fontSize: "var(--font-size-sm)",
                      color: "var(--color-text-primary)",
                      margin: 0,
                    }}
                  >
                    {selectedVuln.discovered_at}
                  </p>
                </div>
              )}

              <div>
                <label
                  style={{
                    fontSize: "var(--font-size-sm)",
                    fontWeight: "600",
                    color: "var(--color-text-secondary)",
                    display: "block",
                    marginBottom: "var(--spacing-1)",
                  }}
                >
                  Description
                </label>
                <p
                  style={{
                    fontSize: "var(--font-size-sm)",
                    color: "var(--color-text-primary)",
                    margin: 0,
                    lineHeight: 1.6,
                  }}
                >
                  {selectedVuln.description}
                </p>
              </div>
            </div>

            <button
              className="btn btn-primary"
              onClick={() => setSelectedVuln(null)}
              style={{
                marginTop: "var(--spacing-5)",
                width: "100%",
              }}
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default OWASPScanner;
