import axios from "axios";

export async function scanThreat(input) {
  // Basic IPv4 regex check
  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(input);

  // Prepare payload depending on input type
  const payload = isIp ? { ip: input } : { domain: input };

  const res = await axios.post("http://localhost:8000/api/scan-threat", payload);
  return res.data;
}
