import { SEVERITIES, fmtDate } from "../constants.js";
import { MiniBadge } from "./Badges.jsx";

export default function ScanList({ scans, activeId, onSelect }) {
  if (!scans.length) {
    return <div className="empty">Henüz tarama yok.</div>;
  }
  return (
    <>
      {scans.map((s) => (
        <div
          key={s.id}
          className={"scan-item" + (s.id === activeId ? " active" : "")}
          onClick={() => onSelect(s.id)}
        >
          <div className="target">{s.target}</div>
          <div className="meta">
            {(s.plugins || []).join(", ")} · {fmtDate(s.started_at)} · {s.status}
          </div>
          <div className="mini-badges">
            {SEVERITIES.filter((sev) => s.severity_summary?.[sev]).map((sev) => (
              <MiniBadge key={sev} severity={sev} count={s.severity_summary[sev]} />
            ))}
          </div>
        </div>
      ))}
    </>
  );
}
