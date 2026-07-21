import { SEV_COLOR } from "../constants.js";
import { SevBadge, CveBadge, CweBadge, OccBadge } from "./Badges.jsx";

export default function FindingCard({ finding: f }) {
  const color = SEV_COLOR[f.severity] || "#6b7280";
  const ev = { ...(f.evidence || {}) };
  const occ = ev.occurrences;
  delete ev.occurrences;
  const evStr = Object.keys(ev).length ? JSON.stringify(ev, null, 2) : "";
  const desc =
    f.description && f.description.length > 500
      ? f.description.slice(0, 500) + "…"
      : f.description;

  return (
    <div className="finding" style={{ borderLeftColor: color }}>
      <div className="finding-head">
        <SevBadge severity={f.severity} />
        <span className="f-title">{f.title}</span>
        <span className="f-src">{f.source_tool}</span>
        {f.cve && <CveBadge cve={f.cve} />}
        {f.cwe && <CweBadge cwe={f.cwe} />}
        {occ && <OccBadge count={occ} />}
      </div>
      {desc && <div className="f-desc">{desc}</div>}
      {evStr && (
        <details className="evidence">
          <summary>Kanıt</summary>
          <pre>{evStr}</pre>
        </details>
      )}
    </div>
  );
}
