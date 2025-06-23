// src/pages/ThreatScanner.js
import React, { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { scanThreat } from "../services/threatScanner";

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
    <div className="max-w-3xl mx-auto">
      <h2 className="section-title">Threat Scanner</h2>
      
      <div className="card">
        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            type="text"
            className="input-field"
            placeholder="Enter domain or IP address"
            value={input}
            onChange={(e) => setInput(e.target.value)}
          />
          <button
            type="submit"
            className="btn btn-primary w-full"
          >
            Analyze Threat
          </button>
        </form>
      </div>

      {mutation.isLoading && (
        <div className="card mt-6 text-center py-8">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-purple-500 mx-auto mb-4"></div>
          <p className="text-gray-600">Analyzing threat level...</p>
        </div>
      )}

      {mutation.error && (
        <div className="card mt-6 bg-red-50 border-l-4 border-red-500 p-4">
          <p className="text-red-700">Error: {mutation.error.message}</p>
        </div>
      )}

      {mutation.data && (
        <>
          <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <div className="card bg-gray-50 border border-gray-200">
              <h3 className="text-lg font-bold text-gray-800">Threat Score</h3>
              <p className="text-3xl font-bold">
                {mutation.data?.threat_score || "N/A"}
              </p>
              <p className="text-sm text-gray-700">0-100 scale</p>
            </div>
            
            <div className="card bg-orange-50 border border-orange-200">
              <h3 className="text-lg font-bold text-orange-800">Malicious Indicators</h3>
              <p className="text-3xl font-bold">
                {mutation.data?.malicious_indicators?.length || 0}
              </p>
              <p className="text-sm text-orange-700">Detected threats</p>
            </div>
            
            <div className="card bg-green-50 border border-green-200">
              <h3 className="text-lg font-bold text-green-800">Reputation</h3>
              <p className="text-3xl font-bold">
                {mutation.data?.reputation || "N/A"}
              </p>
              <p className="text-sm text-green-700">Community rating</p>
            </div>
          </div>

          <div className="card">
            <h3 className="font-semibold text-lg mb-3 text-gray-800">Threat Analysis Details</h3>
            <div className="bg-gray-50 p-4 rounded-lg overflow-x-auto text-sm">
              <pre>{JSON.stringify(mutation.data, null, 2)}</pre>
            </div>
          </div>
        </>
      )}
    </div>
  );
}