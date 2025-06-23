// src/pages/Remediation.js
import React, { useEffect, useState, useMemo } from "react";
import { useLocation } from "react-router-dom";
import axios from "axios";
import SeverityBadge from "../components/SeverityBadge";

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
        severity: vuln.severity !== undefined && vuln.severity !== null
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
      fixable: 0
    };

    remediationSteps.forEach(step => {
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
          `#${i + 1} ${r.id}\nSeverity: ${r.severity}\nRisk Level: ${r.risk_level}\nFixable: ${
            r.fixable ? "Yes" : "No"
          }\nRemediation: ${r.fix_command || "Manual review required."}\n\n`
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
        severity: vuln.severity !== undefined && vuln.severity !== null
          ? parseFloat(vuln.severity)
          : 0.0,
      }));

      const response = await axios.post(
        "http://localhost:8000/api/remediate/export",
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
    <div className="max-w-7xl mx-auto">
      <h2 className="section-title">Remediation Plan</h2>

      {/* Summary Cards */}
      {remediationSteps.length > 0 && (
        <div className="mb-6 grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="card bg-purple-50 border border-purple-200">
            <h3 className="text-lg font-bold text-purple-800">Total Issues</h3>
            <p className="text-3xl font-bold">{remediationSummary.total}</p>
            <p className="text-sm text-purple-700">Vulnerabilities to fix</p>
          </div>
          
          <div className="card bg-green-50 border border-green-200">
            <h3 className="text-lg font-bold text-green-800">Fixable</h3>
            <p className="text-3xl font-bold">{remediationSummary.fixable}</p>
            <p className="text-sm text-green-700">Can be automatically fixed</p>
          </div>
          
          <div className="card bg-blue-50 border border-blue-200">
            <h3 className="text-lg font-bold text-blue-800">Requires Manual Fix</h3>
            <p className="text-3xl font-bold">{remediationSummary.total - remediationSummary.fixable}</p>
            <p className="text-sm text-blue-700">Need manual intervention</p>
          </div>
        </div>
      )}

      {/* Action Buttons at the Top */}
      {remediationSteps.length > 0 && !loading && !error && (
        <div className="flex flex-wrap gap-4 mb-6">
          <button
            onClick={handleExportText}
            className="btn bg-gradient-to-r from-purple-600 to-green-500 text-white"
          >
            Export Remediation Plan (.txt)
          </button>

          <button
            onClick={handleExportShell}
            className="btn bg-gradient-to-r from-green-500 to-purple-600 text-white"
          >
            Download Fix Script (.sh)
          </button>
        </div>
      )}

      {/* Status / Results */}
      {loading ? (
        <div className="card text-center py-12">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-green-500 mx-auto mb-4"></div>
          <p className="text-gray-600">Generating remediation steps...</p>
        </div>
      ) : error ? (
        <div className="card bg-red-50 border-l-4 border-red-500 p-4">
          <p className="text-red-700">{error}</p>
        </div>
      ) : remediationSteps.length === 0 ? (
        <div className="card text-center py-12">
          <div className="text-gray-400 mb-4">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-16 w-16 mx-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <p className="text-gray-600">
            {scannedData.length 
              ? "No remediation steps generated" 
              : "No scanned vulnerabilities were passed to this page"}
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {remediationSteps.map((step, index) => (
            <div
              key={index}
              className="card"
            >
              <div className="flex justify-between items-start mb-3">
                <div>
                  <h3 className="font-semibold text-lg text-gray-800">
                    {step.id}
                  </h3>
                  <p className="text-sm text-gray-600">{step.package} ({step.ecosystem})</p>
                </div>
                <SeverityBadge severity={step.severity} />
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3">
                <div>
                  <p className="text-sm text-gray-700 mb-1">
                    <span className="font-medium">Risk Level:</span> {step.risk_level}
                  </p>
                  <p className="text-sm text-gray-700">
                    <span className="font-medium">Fixable:</span>{" "}
                    {step.fixable ? (
                      <span className="text-green-600 font-medium">Yes</span>
                    ) : (
                      <span className="text-red-600 font-medium">No</span>
                    )}
                  </p>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-700 mb-1">
                    Remediation:
                  </p>
                  <div className="bg-gray-50 p-3 rounded-lg">
                    <code className="text-sm text-gray-800 font-mono break-words">
                      {step.fix_command || "Manual review required"}
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