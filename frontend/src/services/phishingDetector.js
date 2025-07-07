import axios from "axios";
const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || "http://localhost:8000";

export const scanPhishingURL = async (url) => {
  if (!url || typeof url !== "string") throw new Error("Invalid URL provided.");
  try {
    const res = await axios.post(`${API_BASE_URL}/api/phishing/predict`, { url });
    return res.data;
  } catch (err) {
    throw new Error(
      err?.response?.data?.detail || err?.message || "Failed to scan phishing URL."
    );
  }
};
