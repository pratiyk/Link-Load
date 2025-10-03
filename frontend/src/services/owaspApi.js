import axios from "axios";

const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL,
  timeout: 300000,
});

export const owaspApi = {
  startScan: (url, types, includeLow) =>
    api.post("/scan/start", { target_url: url, scan_types: types, include_low_risk: includeLow }),
  getScan: (id) =>
    api.get(`/scan/${id}`),
  getVulns: (id) =>
    api.get(`/scan/${id}/vulnerabilities`),
};
