import apiClient, { API_ENDPOINTS } from "../config/api";

export async function scanThreat(input) {
  // Basic IPv4 regex check
  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(input);

  // Prepare payload depending on input type
  const payload = isIp ? { ip: input } : { domain: input };

  const res = await apiClient.post(API_ENDPOINTS.scans.threat, payload);
  return res.data;
}
