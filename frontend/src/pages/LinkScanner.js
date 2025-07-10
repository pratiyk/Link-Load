import React, { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { scanLink } from "../services/linkScanner";

export default function LinkScanner() {
  const [url, setUrl] = useState("");

  const mutation = useMutation({
    mutationFn: scanLink,
  });

  const handleSubmit = (e) => {
    e.preventDefault();
    if (url.trim()) {
      mutation.mutate({ url }); // Pass as object!
    }
  };

  return (
    <div className="max-w-xl mx-auto">
      <h2 className="section-title">Link Scanner</h2>
      <div className="card">
        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            type="text"
            className="input-field"
            placeholder="https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          <button
            type="submit"
            className="btn btn-primary w-full"
            disabled={mutation.isLoading}
          >
            Scan Link
          </button>
        </form>
      </div>

      {mutation.isLoading && (
        <div className="card mt-6 text-center py-8">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-purple-500 mx-auto mb-4"></div>
          <p className="text-gray-600">Scanning link for threats...</p>
        </div>
      )}

      {mutation.error && (
        <div className="card mt-6 bg-red-50 border-l-4 border-red-500 p-4">
          <p className="text-red-700">
            Error: {mutation.error.response?.data?.detail || mutation.error.message || "Something went wrong"}
          </p>
        </div>
      )}

      {mutation.data && (
        <div className="card mt-6">
          <h3 className="font-semibold text-lg mb-3 text-gray-800">Scan Results</h3>
          <pre className="bg-gray-50 p-4 rounded-lg overflow-x-auto text-sm">
            {JSON.stringify(mutation.data, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
