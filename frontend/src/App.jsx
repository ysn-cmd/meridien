import { useState, useEffect } from "react";
import { listScans, getScan } from "./api.js";
import ScanList from "./components/ScanList.jsx";
import ScanDetail from "./components/ScanDetail.jsx";

export default function App() {
  const [scans, setScans] = useState([]);
  const [scansError, setScansError] = useState(null);
  const [activeId, setActiveId] = useState(null);

  const [detail, setDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState(null);

  // Tarama listesini yükle
  useEffect(() => {
    listScans()
      .then(setScans)
      .catch((e) => setScansError(e.message));
  }, []);

  // Seçilen taramanın detayını yükle
  function selectScan(id) {
    setActiveId(id);
    setDetail(null);
    setDetailError(null);
    setDetailLoading(true);
    getScan(id)
      .then((d) => setDetail(d))
      .catch((e) => setDetailError(e.message))
      .finally(() => setDetailLoading(false));
  }

  return (
    <>
      <header>
        <h1>Meridien</h1>
        <span className="tag">Güvenlik Tarama Dashboard</span>
      </header>

      <div className="layout">
        <div className="sidebar">
          {scansError ? (
            <div className="empty">API'ye ulaşılamadı: {scansError}</div>
          ) : (
            <ScanList scans={scans} activeId={activeId} onSelect={selectScan} />
          )}
        </div>
        <div className="main">
          <ScanDetail data={detail} loading={detailLoading} error={detailError} />
        </div>
      </div>
    </>
  );
}
