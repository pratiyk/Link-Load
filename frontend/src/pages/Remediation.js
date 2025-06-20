import React, { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import axios from "axios";

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
    <div className="p-6 max-w-4xl mx-auto">
      <h2 className="text-2xl font-bold mb-4">Remediation Plan</h2>

      {/* Action Buttons at the Top */}
      {remediationSteps.length > 0 && !loading && !error && (
        <div className="flex gap-4 mb-6">
          <button
            onClick={handleExportText}
            className="bg-green-700 hover:bg-green-800 text-white px-4 py-2 rounded"
          >
            Export Remediation Plan (.txt)
          </button>

          <button
            onClick={handleExportShell}
            className="bg-blue-700 hover:bg-blue-800 text-white px-4 py-2 rounded"
          >
            Download Fix Script (.sh)
          </button>
        </div>
      )}

      {/* Status / Results */}
      {loading ? (
        <p className="text-gray-600">Generating remediation steps...</p>
      ) : error ? (
        <p className="text-red-600">{error}</p>
      ) : remediationSteps.length === 0 ? (
        <p className="text-gray-600">
          No scanned vulnerabilities were passed to this page.
        </p>
      ) : (
        <div className="space-y-6">
          {remediationSteps.map((step, index) => (
            <div
              key={index}
              className="border p-4 rounded bg-white shadow"
            >
              <h3 className="font-semibold text-lg text-blue-800 mb-1">
                {step.id}
              </h3>
              <p className="text-sm text-gray-700 mb-1">
                <span className="font-medium">Severity:</span> {step.severity}
              </p>
              <p className="text-sm text-gray-700 mb-1">
                <span className="font-medium">Risk Level:</span> {step.risk_level}
              </p>
              <p className="text-sm text-gray-700 mb-1">
                <span className="font-medium">Fixable:</span>{" "}
                {step.fixable ? "Yes" : "No"}
              </p>
              <p className="text-sm text-green-700 font-medium">
                ✅ Remediation: {step.fix_command || "Manual review required"}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
