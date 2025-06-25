import React, { useState } from "react";
import axios from "axios";

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
    <div className="max-w-xl mx-auto">
      <h2 className="section-title">Dark Web Scanner</h2>

      <div className="card">
        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            type="email"
            className="input-field"
            placeholder="Enter your email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          <button type="submit" className="btn btn-primary w-full">
            Check for Breaches
          </button>
        </form>
      </div>

      {loading && (
        <div className="card mt-6 text-center py-8">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-purple-500 mx-auto mb-4"></div>
          <p className="text-gray-600">Searching dark web databases...</p>
        </div>
      )}

      {error && (
        <div className="card mt-6 bg-red-50 border-l-4 border-red-500 p-4">
          <p className="text-red-700">{error}</p>
        </div>
      )}

      {results.length > 0 && (
        <div className="card mt-6">
          <h3 className="font-semibold text-lg mb-3 text-gray-800">
            Leaked Credentials Found
          </h3>
          {results.map((result, index) => (
            <div key={index} className="mb-4">
              <h4 className="text-purple-700 font-semibold mb-2">
                Source: {result.source}
              </h4>
              <ul className="list-disc pl-5 space-y-2 text-sm text-gray-800">
                {Array.isArray(result.data) && result.data.length > 0 ? (
                  result.data.map((item, i) => (
                    <li key={i}>
                      {Object.entries(item).map(([key, value]) => (
                        <div key={key}>
                          <strong>{key}:</strong> {String(value)}
                        </div>
                      ))}
                    </li>
                  ))
                ) : (
                  <li>No specific leak details available.</li>
                )}
              </ul>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
