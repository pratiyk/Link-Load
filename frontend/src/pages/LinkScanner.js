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
      mutation.mutate(url);
    }
  };

  return (
    <div className="p-6 max-w-xl mx-auto">
      <form onSubmit={handleSubmit} className="space-y-4">
        <input
          type="text"
          className="w-full border p-2 rounded"
          placeholder="Enter a link to scan"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <button
          type="submit"
          className="bg-blue-500 text-white px-4 py-2 rounded"
        >
          Scan Link
        </button>
      </form>

      {mutation.isLoading && <p className="text-yellow-500">Scanning...</p>}

      {mutation.error && (
        <p className="text-red-500">
          Error: {mutation.error.message || "Something went wrong"}
        </p>
      )}

      {mutation.data && (
        <pre className="bg-gray-100 p-4 mt-4 rounded overflow-x-auto text-sm">
          {JSON.stringify(mutation.data, null, 2)}
        </pre>
      )}
    </div>
  );
}
