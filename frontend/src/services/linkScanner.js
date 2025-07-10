import axios from "axios";

export async function scanLink({ url }) {
  const res = await axios.post("http://localhost:8000/api/scan-url", { url });
  return res.data;
}
