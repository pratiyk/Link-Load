import apiClient, { API_ENDPOINTS } from "../config/api";

export async function scanLink({ url }) {
  const res = await apiClient.post(API_ENDPOINTS.scans.link, { url });
  return res.data;
}
