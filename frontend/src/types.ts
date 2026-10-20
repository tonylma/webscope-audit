import { useEffect, useMemo, useState } from 'react';
import { createScan, getHistory, getReport } from './services/api';
import type { HistoryItem, Report, ScanResult } from './types';

function App() {
  const [url, setUrl] = useState('https://example.com');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);

  const loadHistory = async () => {
    const data = await getHistory();
    setHistory(data.scans);
  };

  useEffect(() => {
    void loadHistory();
  }, []);

  const runScan = async () => {
    setLoading(true);
    try {
      const scan = await createScan(url);
      setResult(scan);
      const detailedReport = await getReport(scan.id);
      setReport(detailedReport);
      await loadHistory();
    } finally {
      setLoading(false);
    }
  };

  const riskTone = useMemo(() => {
    if (!result) return 'neutral';
    if (result.risk_score >= 70) return 'critical';
    if (result.risk_score >= 45) return 'warning';
    return 'safe';
  }, [result]);

  return (
    <div className="shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">WebScope Audit Premium</p>
          <h1>Surface d’attaque publique</h1>
        </div>
        <span className={`status-pill ${riskTone}`}>
          {result ? `Risque ${result.risk_score}` : 'Prêt'}
        </span>
      </header>

      <section className="panel hero">
        <div className="hero-copy">
          <h2>Analyse rapide et structurée</h2>
          <p>
            Validez une URL, analysez la surface exposée, repérez les sous-domaines,
            les chemins publics et les éléments vulnérables visibles.
          </p>
        </div>

        <div className="scan-box">
          <label htmlFor="target">URL cible</label>
          <div className="scan-row">
            <input id="target" value={url} onChange={(e) => setUrl(e.target.value)} />
            <button onClick={runScan} disabled={loading}>
              {loading ? 'Analyse...' : 'Lancer le scan'}
            </button>
          </div>
        </div>
      </section>

      <section className="stats-grid">
        <article className="stat-card">
          <span>URL ciblée</span>
          <strong>{result?.target_url || '—'}</strong>
        </article>
        <article className="stat-card">
          <span>Statut</span>
          <strong>{result?.status || 'Idle'}</strong>
        </article>
        <article className="stat-card">
          <span>Score</span>
          <strong>{result?.risk_score ?? 0}</strong>
        </article>
      </section>

      <section className="content-grid">
        <div className="panel">
          <h3>Résumé</h3>
          <p className="summary-text">{result?.summary || 'Aucun scan lancé pour le moment.'}</p>
        </div>

        <div className="panel">
          <h3>Découverte</h3>
          <ul className="simple-list">
            {report?.subdomains && report.subdomains.length > 0 ? (
              report.subdomains.slice(0, 6).map((sub) => <li key={sub.name}>{sub.name}</li>)
            ) : (
              <li>Aucun sous-domaine détecté.</li>
            )}
          </ul>
        </div>
      </section>

      <section className="panel">
        <h3>Signalements</h3>
        {report?.findings && report.findings.length > 0 ? (
          <div className="findings-list">
            {report.findings.map((finding, index) => (
              <div key={`${finding.title}-${index}`} className="finding-item">
                <div className="finding-head">
                  <span className={`severity ${finding.severity}`}>{finding.severity}</span>
                  <strong>{finding.title}</strong>
                </div>
                <p>{finding.description}</p>
                <small>{finding.evidence}</small>
              </div>
            ))}
          </div>
        ) : (
          <p>Aucun signalement notable.</p>
        )}
      </section>

      <section className="panel">
        <h3>URLs exposées</h3>
        <div className="url-list">
          {report?.urls && report.urls.length > 0 ? (
            report.urls.slice(0, 12).map((item) => (
              <a key={item.url} href={item.url} target="_blank" rel="noreferrer" className="url-item">
                {item.url}
              </a>
            ))
          ) : (
            <p>Aucune URL exposée détectée.</p>
          )}
        </div>
      </section>

      <section className="panel">
        <h3>Historique</h3>
        <ul className="history-list">
          {history.length === 0 ? (
            <li>Le journal de scans est vide.</li>
          ) : (
            history.map((item) => (
              <li key={item.id}>
                <span>{item.target_url}</span>
                <span className="chip">{item.status}</span>
                <span>{item.risk_score}</span>
              </li>
            ))
          )}
        </ul>
      </section>
    </div>
  );
}

export default App;
