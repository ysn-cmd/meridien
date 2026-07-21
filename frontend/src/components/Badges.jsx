import { SEV_COLOR } from "../constants.js";

export function SevBadge({ severity }) {
  return (
    <span className="sev" style={{ background: SEV_COLOR[severity] || "#6b7280" }}>
      {severity.toUpperCase()}
    </span>
  );
}

export function MiniBadge({ severity, count }) {
  return (
    <span className="mini" style={{ background: SEV_COLOR[severity] || "#6b7280" }}>
      {severity.toUpperCase()}:{count}
    </span>
  );
}

export function CveBadge({ cve }) {
  return <span className="cve">{cve}</span>;
}

export function CweBadge({ cwe }) {
  return <span className="cwe">{cwe}</span>;
}

export function OccBadge({ count }) {
  return <span className="occ">×{count}</span>;
}
