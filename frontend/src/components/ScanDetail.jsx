import { SEVERITIES, SEV_COLOR, SEV_RANK, fmtDate, CATEGORY_LABEL, groupByCategory } from "../constants.js";
import FindingCard from "./FindingCard.jsx";
import DiffSection from "./DiffSection.jsx";

export default function ScanDetail({ data, loading, error }) {
  if (loading) return <div className="loading">Yükleniyor…</div>;
  if (error) return <div className="empty">Tarama yüklenemedi: {error}</div>;
  if (!data) return <div className="empty">Soldan bir tarama seç.</div>;

  const { job, findings, diff } = data;
  const summary = job.severity_summary || {};
  const groups = groupByCategory(findings, SEV_RANK);

  return (
    <>
      <h2 className="detail-target">{job.target}</h2>
      <div className="detail-sub">Tarama ID: {job.id}</div>

      <dl className="meta-grid">
        <dt>Durum</dt>
        <dd>{job.status}</dd>
        <dt>Plugin'ler</dt>
        <dd>{(job.plugins || []).join(", ")}</dd>
        <dt>Başlatan</dt>
        <dd>{job.created_by || "-"}</dd>
        <dt>Başlangıç</dt>
        <dd>{fmtDate(job.started_at)}</dd>
        <dt>Bitiş</dt>
        <dd>{fmtDate(job.finished_at)}</dd>
        <dt>Toplam bulgu</dt>
        <dd>{job.findings_count ?? findings.length}</dd>
      </dl>

      <div className="badges">
        {SEVERITIES.filter((s) => summary[s]).length ? (
          SEVERITIES.filter((s) => summary[s]).map((s) => (
            <span key={s} className="badge" style={{ background: SEV_COLOR[s] }}>
              {s.toUpperCase()}: {summary[s]}
            </span>
          ))
        ) : (
          <span className="detail-sub">Bulgu yok</span>
        )}
      </div>

      <DiffSection diff={diff} />

      {groups.map(([cat, items]) => (
        <section key={cat} className="cat-group">
          <h3 className="cat-head">
            {CATEGORY_LABEL[cat] || cat}
            <span className="cat-count">{items.length}</span>
          </h3>
          {items.map((f) => (
            <FindingCard key={f.id} finding={f} />
          ))}
        </section>
      ))}
    </>
  );
}
