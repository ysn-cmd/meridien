// Backend API istemcisi. Dev'de Vite proxy'si /api'yi 3000'e yönlendirir.
const BASE = "/api";

async function get(path) {
  const r = await fetch(BASE + path);
  if (!r.ok) throw new Error("API " + r.status);
  return r.json();
}

export const listScans = () => get("/scans");
export const getScan = (id) => get("/scans/" + encodeURIComponent(id));
