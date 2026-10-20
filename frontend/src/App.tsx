* { box-sizing: border-box; }
:root {
  font-family: Inter, 'Segoe UI', sans-serif;
  color: #e2e8f0;
  background: #07111f;
  line-height: 1.5;
  font-weight: 400;
}
body {
  margin: 0;
  min-height: 100vh;
  background:
    radial-gradient(circle at top, rgba(59,130,246,0.18), transparent 18%),
    linear-gradient(135deg, #030712 0%, #0f172a 35%, #111827 100%);
}
button, input { font: inherit; }
#root { min-height: 100vh; }
.shell { max-width: 1200px; margin: 0 auto; padding: 32px 20px 80px; }
.topbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
.eyebrow { margin: 0; color: #7dd3fc; font-size: 12px; letter-spacing: 0.18em; text-transform: uppercase; }
h1, h2, h3, p { margin-top: 0; }
h1 { margin-bottom: 0; font-size: clamp(2rem, 4vw, 3rem); }
.status-pill {
  padding: 8px 12px; border-radius: 999px; border: 1px solid rgba(148,163,184,0.3);
  background: rgba(15,23,42,0.7); font-weight: 700;
}
.status-pill.safe { color: #86efac; }
.status-pill.warning { color: #fbbf24; }
.status-pill.critical { color: #fca5a5; }
.status-pill.neutral { color: #7dd3fc; }
.panel {
  background: rgba(15,23,42,0.82); border: 1px solid rgba(148,163,184,0.18); border-radius: 20px;
  padding: 20px 22px; box-shadow: 0 12px 35px rgba(2,6,23,0.35);
}
.hero { display: grid; grid-template-columns: 1.1fr 1fr; gap: 24px; align-items: end; margin-bottom: 24px; }
.hero-copy p { color: #cbd5e1; margin-bottom: 0; }
.scan-box label { display: block; margin-bottom: 10px; color: #bfdbfe; }
.scan-row { display: flex; gap: 12px; }
.scan-row input {
  flex: 1; background: rgba(15,23,42,0.75); color: white; border: 1px solid rgba(148,163,184,0.25);
  border-radius: 12px; padding: 12px 14px;
}
button {
  border: none; border-radius: 12px; padding: 12px 18px; background: linear-gradient(135deg, #38bdf8, #2563eb);
  color: white; font-weight: 700; cursor: pointer; transition: transform 0.2s ease;
}
button:hover { transform: translateY(-1px); }
button:disabled { opacity: 0.7; cursor: wait; }
.stats-grid { display: grid; grid-template-columns: repeat(3, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
.stat-card { background: rgba(15,23,42,0.8); border: 1px solid rgba(148,163,184,0.15); border-radius: 18px; padding: 18px; }
.stat-card span { display: block; margin-bottom: 8px; color: #94a3b8; }
.stat-card strong { font-size: 1.3rem; word-break: break-word; }
.content-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 22px; margin-bottom: 22px; }
.summary-text { color: #dfe7f3; margin-bottom: 0; }
.simple-list, .history-list { list-style: none; padding: 0; margin: 0; }
.simple-list li, .history-list li { padding: 8px 0; border-bottom: 1px solid rgba(148,163,184,0.14); }
.findings-list { display: grid; gap: 16px; }
.finding-item { background: rgba(15,23,42,0.7); border: 1px solid rgba(148,163,184,0.14); border-radius: 12px; padding: 16px; }
.finding-head { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
.severity { font-size: 11px; padding: 4px 8px; border-radius: 999px; text-transform: uppercase; font-weight: 700; }
.severity.low { background: rgba(34,197,94,0.12); color: #86efac; }
.severity.medium { background: rgba(251,191,36,0.12); color: #fbbf24; }
.severity.high { background: rgba(248,113,113,0.12); color: #fca5a5; }
.finding-item p, .finding-item small { margin: 0; color: #dbeafe; }
.url-list { display: flex; flex-wrap: wrap; gap: 10px; }
.url-item { display: inline-flex; padding: 8px 12px; text-decoration: none; color: #bfdbfe; border: 1px solid rgba(96,165,250,0.25); border-radius: 999px; background: rgba(30,41,59,0.85); }
.history-list li { display: flex; justify-content: space-between; gap: 12px; align-items: center; }
.chip { padding: 4px 8px; font-size: 12px; border-radius: 999px; background: rgba(59,130,246,0.12); color: #93c5fd; }
@media (max-width: 800px) {
  .hero, .content-grid, .stats-grid { grid-template-columns: 1fr; }
  .topbar, .scan-row, .history-list li { flex-direction: column; align-items: flex-start; }
}
