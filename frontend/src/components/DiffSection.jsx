import { SevBadge } from "./Badges.jsx";

function DiffLine({ f }) {
  return (
    <li>
      <SevBadge severity={f.severity} /> {f.title}{" "}
      <span className="f-src">{f.source_tool}</span>
    </li>
  );
}

export default function DiffSection({ diff }) {
  if (!diff) {
    return (
      <div className="diff-empty">
        İlk tarama — karşılaştırılacak önceki tarama yok.
      </div>
    );
  }
  const added = diff.added || [];
  const removed = diff.removed || [];
  if (!added.length && !removed.length) {
    return <div className="diff-empty">Önceki taramaya göre değişiklik yok.</div>;
  }
  return (
    <div className="diff">
      <h3>
        Değişiklikler{" "}
        <span className="diff-counts">
          +{added.length} yeni · −{removed.length} kapanan
        </span>
      </h3>
      {added.length > 0 && (
        <div className="diff-group added">
          <h4>Yeni bulgular</h4>
          <ul>
            {added.map((f) => (
              <DiffLine key={f.id} f={f} />
            ))}
          </ul>
        </div>
      )}
      {removed.length > 0 && (
        <div className="diff-group removed">
          <h4>Kapanan bulgular</h4>
          <ul>
            {removed.map((f) => (
              <DiffLine key={f.id} f={f} />
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
