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
    <div className="p-6 max-w-xl mx-auto">
      <h2 className="text-xl font-semibold mb-4">Threat Score Aggregator</h2>
      <form onSubmit={handleSubmit} className="space-y-4">
        <input
          type="text"
          className="w-full border p-2 rounded"
          placeholder="Enter domain or IP"
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />
        <button
          type="submit"
          className="bg-red-600 text-white px-4 py-2 rounded"
        >
          Analyze Threat
        </button>
      </form>

      {mutation.isLoading && <p className="text-yellow-500">Scanning...</p>}

      {mutation.error && (
        <p className="text-red-500">Error: {mutation.error.message}</p>
      )}

      {mutation.data && (
        <div className="bg-gray-100 p-4 mt-4 rounded overflow-x-auto text-sm">
          <pre>{JSON.stringify(mutation.data, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}
