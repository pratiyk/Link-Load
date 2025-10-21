import apiClient, { API_ENDPOINTS } from "../config/api";

export const scanPhishingURL = async (url) => {
  if (!url || typeof url !== "string") throw new Error("Invalid URL provided.");
  try {
    const res = await apiClient.post(API_ENDPOINTS.scans.phishing, { url });
    return res.data;
  } catch (err) {
    throw new Error(
      err?.response?.data?.detail ||
        err?.message ||
        "Failed to scan phishing URL."
    );
  }
};
