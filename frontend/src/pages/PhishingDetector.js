import React, { useState } from "react";
import { scanPhishingURL } from "../services/phishingDetector";

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
    <div className="max-w-xl mx-auto">
      <h2 className="section-title">Phishing Detector</h2>
      <div className="card">
        <form onSubmit={handleSubmit} className="space-y-4">
          <input type="url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="Enter URL" className="input-field" required />
          <button type="submit" className="btn btn-primary w-full" disabled={loading}>{loading ? "Scanning..." : "Scan URL"}</button>
        </form>
      </div>
      {loading && <div className="card mt-6 text-center py-8"><p>Scanning...</p></div>}
      {error && <div className="card mt-6 bg-red-50 border-l-4 border-red-500 p-4"><p className="text-red-700">{error}</p></div>}
      {result && !loading && !error && (
        <div className="card mt-6">
          <h3 className="font-semibold text-lg mb-3">Scan Result</h3>
          <p><strong>URL:</strong> {result.url}</p>
          <p className={result.is_phishing ? "text-red-600" : "text-green-600"}><strong>Status:</strong> {result.is_phishing ? "Phishing Detected" : "Benign"}</p>
          <p><strong>Probability:</strong> {(result.probability * 100).toFixed(2)}%</p>
        </div>
      )}
    </div>
  );
}
