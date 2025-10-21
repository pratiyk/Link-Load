import apiClient, { API_ENDPOINTS } from "../config/api";

export const scanDarkWeb = async (email) => {
  try {
    const response = await apiClient.post(API_ENDPOINTS.scans.darkweb, {
      email,
    });
    return response.data;
  } catch (error) {
    throw new Error(
      error?.response?.data?.detail || "Failed to scan dark web leaks."
    );
  }
};
