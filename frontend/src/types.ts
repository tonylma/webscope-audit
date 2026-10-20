import { useState } from 'react';
import { createScan, getHistory } from './services/api';
import type { ScanResult, HistoryItem } from './types';

function App() {
  const [url, setUrl] = useState('https://example.com');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(false);

  const runScan = async () => {
    setLoading(true);
    try {
      const scan = await createScan(url);
      setResult(scan);
      const hist = await getHistory();
      setHistory(hist.scans);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">WebScope Audit Premium</p>
          <h1>Dashboard d’audit public</h1>
        </div>
      </header>

      <section className="panel form-panel">
        <label htmlFor="target">Cible</label>
        <div className="form-row">
          <input id="target" value={url} onChange={(e) => setUrl(e.target.value)} />
          <button onClick={runScan} disabled={loading}>{loading ? 'Analyse...' : 'Lancer le scan'}</button>
        </div>
      </section>

      <section className="stats-grid">
        <div className="stat-card">
          <span>URL ciblée</span>
          <strong>{result?.target_url || '—'}</strong>
        </div>
        <div className="stat-card">
          <span>Statut</span>
          <strong>{result?.status || 'inactif'}</strong>
        </div>
        <div className="stat-card">
          <span>Score</span>
          <strong>{result?.risk_score ?? 0}</strong>
        </div>
      </section>

      {result && (
        <section className="panel result-panel">
          <h2>Résumé</h2>
          <p>{result.summary}</p>
        </section>
      )}

      <section className="panel">
        <h2>Historique</h2>
        <ul className="history-list">
          {history.length === 0 ? (
            <li>Aucun scan pour le moment.</li>
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
