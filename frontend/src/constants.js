export const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export const SEV_COLOR = {
  critical: "#b91c1c",
  high: "#dc2626",
  medium: "#d97706",
  low: "#0891b2",
  info: "#6b7280",
};

export const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function fmtDate(iso) {
  if (!iso) return "-";
  try {
    return new Date(iso).toLocaleString("tr-TR");
  } catch {
    return iso;
  }
}
