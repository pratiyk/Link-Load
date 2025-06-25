import axios from "axios";

export const scanDarkWeb = async (email) => {
  try {
    const response = await axios.post("http://localhost:8000/api/darkweb_scan", { email });
    return response.data;
  } catch (error) {
    throw new Error(
      error?.response?.data?.detail || "Failed to scan dark web leaks."
    );
  }
};
