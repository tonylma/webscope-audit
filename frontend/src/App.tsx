import { useEffect, useState, type FormEvent } from 'react';
import {
  analyzeUrl, createScan, createUser, evaluateFraud, getAuditStatus, getFraudCase, getFraudCases, getFraudControls,
  getHistory, getReport, getUsers, login as loginApi, resetUserPassword, revokeUserSessions, setAccessToken, triageFile,
  updateFraudCase, updateUser,
} from './services/api';
import type {
  AdminUser, FraudCaseDetail, FraudCaseSummary, FraudControl, FraudEvaluation, FraudForm, HistoryItem, Report, ScanResult,
  StaticFileResult, UrlAnalysis, UserInfo,
} from './types';

type Tab = 'surface' | 'defense' | 'fraud' | 'admin';

const initialFraud: FraudForm = {
  case_reference: '', sim_change_hours: '', beneficiary_added: false, beneficiary_age_minutes: '',
  remote_access_tool_detected: false, accessibility_abuse_detected: false,
  screen_capture_detected: false, app_integrity_warning: false, social_engineering_reported: false,
  phone_number_spoofing_suspected: false, otp_failures_15m: '0', new_device: false,
  impossible_travel: false, mobile_api_anomaly: false, transactions_10m: '0',
  amount_vs_30d_median: '1', shared_beneficiary_accounts_24h: '0', rapid_cashout: false, channel: 'unknown',
};
const roleLabels: Record<string, string> = {
  admin: 'Administrateur', security_analyst: 'Analyste sécurité', fraud_analyst: 'Analyste fraude',
  auditor: 'Auditeur', reader: 'Lecture seule',
};

function App() {
  const [user, setUser] = useState<UserInfo | null>(null);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState<Tab>('surface');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [url, setUrl] = useState('https://example.com');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [urlToCheck, setUrlToCheck] = useState('https://example.com');
  const [urlAnalysis, setUrlAnalysis] = useState<UrlAnalysis | null>(null);
  const [sample, setSample] = useState<File | null>(null);
  const [fileResult, setFileResult] = useState<StaticFileResult | null>(null);
  const [fraudForm, setFraudForm] = useState<FraudForm>(initialFraud);
  const [fraudResult, setFraudResult] = useState<FraudEvaluation | null>(null);
  const [controls, setControls] = useState<FraudControl[]>([]);
  const [auditStatus, setAuditStatus] = useState<{valid: boolean; entries_checked: number; last_hash: string} | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [newUser, setNewUser] = useState({username: '', display_name: '', email: '', password: '', role: 'reader'});

  const canSecurity = user?.role === 'security_analyst' || user?.role === 'admin';
  const canFraud = user?.role === 'fraud_analyst' || user?.role === 'admin';
  const canAudit = user?.role === 'auditor' || user?.role === 'admin';
  const isAdmin = user?.role === 'admin';

  const clearNotices = () => { setError(''); setMessage(''); };
  const fail = (cause: any) => {
    setError(cause?.response?.data?.detail || cause?.message || 'Une erreur est survenue.');
    setMessage('');
  };

  const refreshCases = async () => {
    try { const data = await getFraudCases({limit: 100}); setFraudCases(data.cases); setFraudCaseTotal(data.total); }
    catch (cause: any) { fail(cause); }
  };

  const refreshHistory = async () => {
    try {
      const data = await getHistory();
      setHistory(data.scans);
    } catch (cause: any) { fail(cause); }
  };

  const signIn = async (event: FormEvent) => {
    event.preventDefault(); clearNotices(); setBusy(true);
    try {
      const response = await loginApi(username, password);
      setUser(response.user);
      setPassword('');
      setMessage(`Connecté en tant que ${response.user.display_name || response.user.username}.`);
      setTab(response.user.role === 'fraud_analyst' ? 'fraud' : 'surface');
    } catch (cause: any) { fail(cause); }
    finally { setBusy(false); }
  };

  const signOut = () => {
    setAccessToken(null); setUser(null); setResult(null); setReport(null);
    setUrlAnalysis(null); setFileResult(null); setFraudResult(null);
    setControls([]); setUsers([]); setFraudCases([]); setSelectedCase(null); setAuditStatus(null); setMessage('Session terminée.');
  };

  useEffect(() => {
    if (!user) return;
    if (user.role !== 'reader') void refreshHistory();
    if (user.role === 'fraud_analyst' || user.role === 'auditor' || user.role === 'admin' || user.role === 'reader') {
      void getFraudControls().then(data => setControls(data.controls)).catch(fail);
      void refreshCases();
    }
    if (user.role === 'admin') void getUsers().then(data => setUsers(data.users)).catch(fail);
  }, [user]);

  const runSurfaceCheck = async () => {
    clearNotices(); setBusy(true);
    try {
      const scan = await createScan(url);
      setResult(scan);
      setReport(await getReport(scan.id));
      await refreshHistory();
      setMessage('Analyse syntaxique terminée. Aucun accès réseau à la cible n’a été effectué.');
    } catch (cause: any) { fail(cause); }
    finally { setBusy(false); }
  };

  const runUrlAnalysis = async () => {
    clearNotices(); setBusy(true);
    try {
      setUrlAnalysis(await analyzeUrl(urlToCheck));
      setMessage('Analyse locale des signaux d’URL terminée, sans ouvrir la destination.');
    } catch (cause: any) { fail(cause); }
    finally { setBusy(false); }
  };

  const runFileTriage = async () => {
    if (!sample) { setError('Sélectionne d’abord un fichier à examiner.'); return; }
    clearNotices(); setBusy(true);
    try {
      setFileResult(await triageFile(sample));
      setMessage('Triage terminé. Le fichier n’a pas été exécuté ni extrait.');
    } catch (cause: any) { fail(cause); }
    finally { setBusy(false); }
  };

  const setFraudField = <K extends keyof FraudForm>(key: K, value: FraudForm[K]) => {
    setFraudForm(current => ({ ...current, [key]: value }));
  };

  const runFraudAssessment = async (event: FormEvent) => {
    event.preventDefault(); clearNotices(); setBusy(true);
    try {
      setFraudResult(await evaluateFraud(fraudForm));
      await refreshCases();
      setMessage('Triage antifraude terminé. Le dossier est enregistré chiffré en base ; le score est une aide à la décision et non une preuve.');
    } catch (cause: any) { fail(cause); }
    finally { setBusy(false); }
  };

  const addUser = async (event: FormEvent) => {
    event.preventDefault(); clearNotices(); setBusy(true);
    try {
      await createUser({...newUser, email: newUser.email || undefined});
      setNewUser({username: '', display_name: '', email: '', password: '', role: 'reader'});
      setUsers((await getUsers()).users);
      setMessage('Compte créé.');
    } catch (cause: any) { fail(cause); }
    finally { setBusy(false); }
  };

  const revokeSessions = async (id: number) => {
    clearNotices();
    try {
      await revokeUserSessions(id);
      setUsers((await getUsers()).users);
      setMessage('Sessions de ce compte révoquées.');
    } catch (cause: any) { fail(cause); }
  };

  const openFraudCase = async (caseId: number) => {
    clearNotices();
    try {
      const detail = await getFraudCase(caseId);
      setSelectedCase(detail);
      setCaseStatus(detail.status);
      setCaseNote(detail.review_note || '');
    } catch (cause: any) { fail(cause); }
  };

  const saveFraudCase = async () => {
    if (!selectedCase || !canFraud) return;
    clearNotices(); setBusy(true);
    try {
      await updateFraudCase(selectedCase.id, {status: caseStatus, review_note: caseNote});
      await refreshCases();
      await openFraudCase(selectedCase.id);
      setMessage('Dossier antifraude mis à jour et journalisé.');
    } catch (cause: any) { fail(cause); }
    finally { setBusy(false); }
  };

  const changeUserRole = async (id: number, role: string) => {
    clearNotices();
    try {
      await updateUser(id, {role});
      setUsers((await getUsers()).users);
      setMessage('Rôle utilisateur mis à jour ; les anciens jetons ont été révoqués.');
    } catch (cause: any) { fail(cause); }
  };

  const toggleUserActive = async (item: AdminUser) => {
    clearNotices();
    try {
      await updateUser(item.id, {is_active: !item.is_active});
      setUsers((await getUsers()).users);
      setMessage(item.is_active ? 'Compte désactivé.' : 'Compte réactivé.');
    } catch (cause: any) { fail(cause); }
  };

  const submitPasswordReset = async (event: FormEvent) => {
    event.preventDefault();
    if (resetUserId === '') return;
    clearNotices();
    try {
      await resetUserPassword(resetUserId, resetPassword);
      setResetPassword('');
      setMessage('Mot de passe réinitialisé ; toutes les sessions précédentes ont été révoquées.');
    } catch (cause: any) { fail(cause); }
  };

  const checkAuditChain = async () => {
    clearNotices();
    try { setAuditStatus(await getAuditStatus()); }
    catch (cause: any) { fail(cause); }
  };

  if (!user) {
    return (
      <main className="login-wrap">
        <div className="panel stack">
          <div>
            <p className="eyebrow">WebScope Audit & Defense</p>
            <h1>Accès sécurisé</h1>
            <p className="muted">Connecte-toi avec un compte créé par l’administrateur de la plateforme.</p>
          </div>
          {error && <div className="notice error" role="alert">{error}</div>}
          {message && <div className="notice">{message}</div>}
          <form className="stack" onSubmit={signIn}>
            <div><label htmlFor="username">Identifiant</label><input id="username" autoComplete="username" required value={username} onChange={e => setUsername(e.target.value)} /></div>
            <div><label htmlFor="password">Mot de passe</label><input id="password" type="password" autoComplete="current-password" required value={password} onChange={e => setPassword(e.target.value)} /></div>
            <button disabled={busy}>{busy ? 'Connexion…' : 'Se connecter'}</button>
          </form>
          <small>Jeton d’accès conservé uniquement en mémoire navigateur. Une reconnexion sera requise après actualisation.</small>
        </div>
      </main>
    );
  }

  return (
    <main className="shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">WebScope Audit & Defense · v3</p>
          <h1>Centre de défense & contrôle antifraude</h1>
          <p className="muted">Audit autorisé · triage non-exécutant · contrôle interne Mobile Money</p>
        </div>
        <div className="row">
          <div><strong>{user.display_name || user.username}</strong><br/><span className="badge">{roleLabels[user.role] || user.role}</span></div>
          <button className="secondary" onClick={signOut}>Déconnexion</button>
        </div>
      </header>

      {error && <div className="notice error" role="alert">{error}</div>}
      {message && <div className="notice" role="status">{message}</div>}

      <nav className="tabs" aria-label="Modules">
        {(canSecurity || canAudit || user.role === 'reader') && <button className={tab === 'surface' ? 'active' : ''} onClick={() => setTab('surface')}>Audit de surface</button>}
        {(canSecurity || canAudit) && <button className={tab === 'defense' ? 'active' : ''} onClick={() => setTab('defense')}>Défense & fichiers</button>}
        {(canFraud || canAudit || user.role === 'reader') && <button className={tab === 'fraud' ? 'active' : ''} onClick={() => setTab('fraud')}>Fraude Mobile Money</button>}
        {isAdmin && <button className={tab === 'admin' ? 'active' : ''} onClick={() => setTab('admin')}>Administration</button>}
      </nav>

      {tab === 'surface' && (
        <>
          <section className="panel">
            <h2>Analyse d’URL et exposition potentielle</h2>
            <p className="muted">La version actuelle analyse la syntaxe et les signaux d’hameçonnage sans effectuer de requête vers la cible. Les scans réseau actifs restent désactivés par défaut.</p>
            {canSecurity ? <div className="row">
              <div className="grow"><label htmlFor="surface-url">URL du site public autorisé</label><input id="surface-url" value={url} onChange={e => setUrl(e.target.value)} /></div>
              <button disabled={busy} onClick={runSurfaceCheck}>{busy ? 'Analyse…' : 'Analyser'}</button>
            </div> : <p className="notice">Ton rôle autorise la consultation de l’historique, pas le lancement d’analyses.</p>}
          </section>
          {result && <section className="grid-3">
            <div className="stat"><span>Cible</span><strong>{result.target_url}</strong></div>
            <div className="stat"><span>Score heuristique</span><strong>{result.risk_score}/100</strong></div>
            <div className="stat"><span>Statut</span><strong>{result.status}</strong></div>
          </section>}
          {result && <section className="panel">
            <h3>Rapport</h3><p>{result.summary}</p>
            <div className="stack">
              {(report?.findings || []).map((item, index) => <div className="signal" key={index}>
                <div className="row"><h4>{item.title}</h4><span className={`badge ${item.severity}`}>{item.severity}</span></div>
                <p>{item.description}</p><small>{item.evidence}</small>
              </div>)}
              {(!report?.findings || report.findings.length === 0) && <p className="muted">Aucun signal heuristique identifié ; cela ne constitue pas un certificat de sécurité.</p>}
            </div>
          </section>}
          <section className="panel">
            <div className="row"><h3 className="grow">Historique des analyses</h3><button className="secondary" onClick={refreshHistory}>Actualiser</button></div>
            <div className="table-wrap"><table><thead><tr><th>ID</th><th>Cible</th><th>Statut</th><th>Score</th></tr></thead><tbody>
              {history.map(item => <tr key={item.id}><td>{item.id}</td><td>{item.target_url}</td><td>{item.status}</td><td>{item.risk_score}/100</td></tr>)}
              {history.length === 0 && <tr><td colSpan={4} className="muted">Aucun élément d’historique disponible.</td></tr>}
            </tbody></table></div>
          </section>
        </>
      )}

      {tab === 'defense' && (
        <>
          <section className="panel">
            <h2>Détection de liens suspects</h2>
            <p className="muted">Heuristiques locales : lookalike de marque, domaines punycode, raccourcisseurs, IP privées, paramètres anormaux. Le lien n’est jamais ouvert.</p>
            <div className="row">
              <div className="grow"><label htmlFor="url-sample">URL à examiner</label><input id="url-sample" value={urlToCheck} onChange={e => setUrlToCheck(e.target.value)} /></div>
              <button disabled={busy} onClick={runUrlAnalysis}>Analyser sans ouvrir</button>
            </div>
            {urlAnalysis && <div className="stack" style={{marginTop: 14}}>
              <div className="grid-3">
                <div className="stat"><span>Domaine</span><strong>{urlAnalysis.normalized_host}</strong></div>
                <div className="stat"><span>Risque</span><strong>{urlAnalysis.risk_score}/100</strong></div>
                <div className="stat"><span>Niveau</span><strong className={`badge ${urlAnalysis.risk_level}`}>{urlAnalysis.risk_level}</strong></div>
              </div>
              {urlAnalysis.signals.map(signal => <div className="signal" key={signal.code}>
                <div className="row"><h4>{signal.label}</h4><span className={`badge ${signal.severity}`}>+{signal.points}</span></div>
                <p>{signal.explanation}</p><small>{signal.code}</small>
              </div>)}
              <p className="notice">{urlAnalysis.recommendation}</p><small>{urlAnalysis.limitations}</small>
            </div>}
          </section>
          {canSecurity && <section className="panel">
            <h2>Triage statique de fichier</h2>
            <p className="muted">Limite 25 Mo. Le fichier est traité en mémoire, sans exécution, décompression ni ouverture d’URL intégrée. Un scan antivirus ClamAV interne est lancé lorsqu’il est activé.</p>
            <div className="row">
              <div className="grow"><label htmlFor="sample">Fichier suspect (APK, PDF, EXE, document…)</label><input id="sample" type="file" onChange={e => setSample(e.target.files?.[0] || null)} /></div>
              <button disabled={busy || !sample} onClick={runFileTriage}>Analyser le fichier</button>
            </div>
            {fileResult && <div className="stack" style={{marginTop: 14}}>
              <div className="grid-3">
                <div className="stat"><span>Type détecté</span><strong>{fileResult.file_type}</strong></div>
                <div className="stat"><span>Empreinte SHA-256</span><strong>{fileResult.sha256.slice(0, 20)}…</strong></div>
                <div className="stat"><span>Risque statique</span><strong>{fileResult.risk_score}/100</strong></div>
              </div>
              <p><span className={`badge ${fileResult.risk_level}`}>{fileResult.risk_level}</span> {fileResult.verdict}</p>
              <p><strong>ClamAV :</strong> <span className="badge">{fileResult.antivirus?.status || 'not_scanned'}</span> {fileResult.antivirus?.signature_response || fileResult.antivirus?.reason || ''}</p>
              {fileResult.static_indicators.map(item => <div className="signal" key={item.indicator}>{item.indicator} <small>+{item.points}</small></div>)}
              <p className="notice">Aucun fichier n’a été exécuté ni extrait. Le triage est heuristique ; un résultat « propre » ne garantit pas l’absence de menace. Disposition : {fileResult.disposition}.</p>
              <small>{fileResult.limitations}</small>
            </div>}
          </section>}
          {!canSecurity && <div className="notice">Le rôle Auditeur peut analyser des URL, mais ne peut pas téléverser de fichier.</div>}
        </>
      )}

      {tab === 'fraud' && (
        <>
          <section className="panel">
            <h2>Analyse d’un événement Mobile Money</h2>
            <p className="muted">Règles initiales de triage : SIM swap, OTP, vishing/phishing, RAT, abus d’accessibilité, prise de compte, ajout de bénéficiaire, vélocité et cash-out. Les seuils doivent être calibrés sur les données autorisées de l’établissement.</p>
            {canFraud ? <form className="stack" onSubmit={runFraudAssessment}>
              <div className="grid-3">
                <div><label>Référence de dossier (facultatif)</label><input value={fraudForm.case_reference} onChange={e => setFraudField('case_reference', e.target.value)} /></div>
                <div><label>Changement SIM (heures depuis changement)</label><input type="number" min="0" value={fraudForm.sim_change_hours} onChange={e => setFraudField('sim_change_hours', e.target.value)} /></div>
                <div><label>Âge du bénéficiaire (minutes)</label><input type="number" min="0" value={fraudForm.beneficiary_age_minutes} onChange={e => setFraudField('beneficiary_age_minutes', e.target.value)} /></div>
                <div><label>Échecs OTP (15 min)</label><input type="number" min="0" value={fraudForm.otp_failures_15m} onChange={e => setFraudField('otp_failures_15m', e.target.value)} /></div>
                <div><label>Transactions (10 min)</label><input type="number" min="0" value={fraudForm.transactions_10m} onChange={e => setFraudField('transactions_10m', e.target.value)} /></div>
                <div><label>Montant / médiane client 30 jours</label><input type="number" min="0" step="0.1" value={fraudForm.amount_vs_30d_median} onChange={e => setFraudField('amount_vs_30d_median', e.target.value)} /></div>
                <div><label>Comptes partageant le bénéficiaire (24 h)</label><input type="number" min="0" value={fraudForm.shared_beneficiary_accounts_24h} onChange={e => setFraudField('shared_beneficiary_accounts_24h', e.target.value)} /></div>
                <div><label>Canal</label><select value={fraudForm.channel} onChange={e => setFraudField('channel', e.target.value as FraudForm['channel'])}>
                  <option value="unknown">Inconnu</option><option value="wallet">Wallet</option><option value="bank_transfer">Virement bancaire</option><option value="cashout">Cash-out</option><option value="merchant">Marchand</option>
                </select></div>
              </div>
              <div className="check-grid">
                {([
                  ['beneficiary_added','Nouveau bénéficiaire ajouté'],['remote_access_tool_detected','RAT / outil de prise en main détecté'],
                  ['accessibility_abuse_detected','Abus des services d’accessibilité'],['screen_capture_detected','Capture d’écran anormale'],
                  ['app_integrity_warning','Alerte d’intégrité de l’application'],['social_engineering_reported','Phishing / smishing / vishing signalé'],
                  ['phone_number_spoofing_suspected','Usurpation possible du numéro appelant'],['new_device','Nouvel appareil'],
                  ['impossible_travel','Incohérence géographique de session'],['mobile_api_anomaly','Anomalie API mobile'],['rapid_cashout','Cash-out rapide après réception'],
                ] as [keyof FraudForm,string][]).map(([key,label]) => <label className="check" key={key}>
                  <input type="checkbox" checked={Boolean(fraudForm[key])} onChange={e => setFraudField(key, e.target.checked as any)} />{label}
                </label>)}
              </div>
              <button disabled={busy}>{busy ? 'Évaluation…' : 'Évaluer le risque antifraude'}</button>
            </form> : <p className="notice">Ton rôle permet de consulter le cadre de contrôle, mais pas d’évaluer ou de modifier un dossier de fraude.</p>}
            {fraudResult && <div className="stack" style={{marginTop: 18}}>
              <div className="grid-3">
                <div className="stat"><span>Score indicatif</span><strong>{fraudResult.risk_score}/100</strong></div>
                <div className="stat"><span>Niveau</span><strong className={`badge ${fraudResult.risk_level}`}>{fraudResult.risk_level}</strong></div>
                <div className="stat"><span>MITRE F3</span><strong>v{fraudResult.mitre_f3.version}</strong></div>
              </div>
              <h3>Signaux détectés</h3>
              {fraudResult.signals.map(signal => <div className="signal" key={signal.rule_id}>
                <div className="row"><h4>{signal.label}</h4><span className={`badge ${signal.severity}`}>+{signal.points}</span></div>
                <p>{signal.explanation}</p><small>Contrôles : {signal.recommended_controls.join(', ')}</small>
              </div>)}
              <h3>Correspondances MITRE F3 / ATT&CK</h3>
              <p className="muted">Tactiques : {fraudResult.mitre_f3.tactics.join(', ') || 'aucune correspondance déduite'}</p>
              <ul>{fraudResult.mitre_f3.techniques.map(item => <li key={item.id}>{item.id} — {item.name} ({item.tactic})</li>)}</ul>
              <h3>Actions recommandées</h3>
              <ul>{fraudResult.recommended_actions.map(action => <li key={action}>{action}</li>)}</ul>
              <p className="notice">{fraudResult.decision_note}</p>
              {fraudResult.case_id && <p className="notice">Dossier enregistré : #{fraudResult.case_id} · Statut : {fraudResult.case_status}. Les données originales et le résultat sont chiffrés au repos (AES-256-GCM).</p>}
              {fraudResult.case_token && <small>Jeton pseudonymisé : {fraudResult.case_token}</small>}
            </div>}
          </section>
          <section className="panel">
            <div className="row"><h2 className="grow">Dossiers antifraude persistés</h2><button className="secondary" onClick={refreshCases}>Actualiser ({fraudCaseTotal})</button></div>
            <div className="table-wrap"><table><thead><tr><th>Dossier</th><th>Créé</th><th>Score</th><th>Niveau</th><th>Statut</th><th>Consultation</th></tr></thead><tbody>
              {fraudCases.map(item => <tr key={item.id}>
                <td>#{item.id}<br/><small>{item.case_token.slice(0, 12)}…</small></td>
                <td>{new Date(item.created_at).toLocaleString()}</td>
                <td>{item.risk_score}/100</td>
                <td><span className={'badge ' + item.risk_level}>{item.risk_level}</span></td>
                <td>{item.status}</td>
                <td>{(canFraud || canAudit) ? <button className="secondary" onClick={() => openFraudCase(item.id)}>Ouvrir</button> : <small>Résumé uniquement</small>}</td>
              </tr>)}
              {fraudCases.length === 0 && <tr><td colSpan={6} className="muted">Aucun dossier enregistré.</td></tr>}
            </tbody></table></div>
            {selectedCase && <div className="stack" style={{marginTop: 16}}>
              <div className="row"><h3 className="grow">Dossier #{selectedCase.id}</h3><span className={'badge ' + selectedCase.risk_level}>{selectedCase.risk_level} · {selectedCase.risk_score}/100</span></div>
              <p className="muted">Référence pseudonymisée : {selectedCase.case_token} · Statut : {selectedCase.status}</p>
              <div className="signal">
                <h4>Informations du dossier déchiffrées pour l’analyste habilité</h4>
                <p>Référence source : {String(selectedCase.input?.case_reference || 'Non renseignée')}</p>
                <p>Événements : changement SIM {String(selectedCase.input?.sim_change_hours ?? 'n/a')} h · transactions/10 min {String(selectedCase.input?.transactions_10m ?? 0)} · canal {String(selectedCase.input?.channel || 'unknown')}</p>
                <p>Signaux : {selectedCase.evaluation?.signals?.map(signal => signal.label).join(' ; ') || 'Aucun signal'}</p>
                {selectedCase.review_note && <p>Dernière note de revue : {selectedCase.review_note}</p>}
              </div>
              {canFraud && <div className="stack">
                <div><label htmlFor="case-status">Nouveau statut</label><select id="case-status" value={caseStatus} onChange={e => setCaseStatus(e.target.value)}>
                  <option value="open">Ouvert</option><option value="under_review">En revue</option><option value="escalated">Escaladé</option><option value="resolved">Résolu</option><option value="false_positive">Faux positif</option>
                </select></div>
                <div><label htmlFor="case-note">Note de revue (chiffrée au repos)</label><textarea id="case-note" rows={3} value={caseNote} onChange={e => setCaseNote(e.target.value)} /></div>
                <div className="actions"><button disabled={busy} onClick={saveFraudCase}>Enregistrer le suivi</button></div>
              </div>}
            </div>}
          </section>
          <section className="panel">
            <h2>Programme de contrôle interne Mobile Money</h2>
            <p className="muted">Catalogue de contrôles pour préparer une mission d’Internal Control Officer.</p>
            <div className="stack">
              {controls.map(control => <div className="signal" key={control.id}>
                <div className="row"><h4>{control.id} · {control.title}</h4><span className="badge">{control.frequency}</span></div>
                <p><strong>Objectif :</strong> {control.objective}</p>
                <p><strong>Test :</strong> {control.test}</p>
                <small>Preuves : {control.evidence.join(' · ')} | Responsable : {control.owner}</small>
              </div>)}
            </div>
          </section>
        </>
      )}

      {tab === 'admin' && isAdmin && (
        <>
          <section className="panel">
            <h2>Créer un utilisateur</h2>
            <form className="grid-3" onSubmit={addUser}>
              <div><label>Identifiant</label><input required minLength={2} value={newUser.username} onChange={e => setNewUser({...newUser, username: e.target.value})} /></div>
              <div><label>Nom affiché</label><input required minLength={2} value={newUser.display_name} onChange={e => setNewUser({...newUser, display_name: e.target.value})} /></div>
              <div><label>E-mail (facultatif)</label><input type="email" value={newUser.email} onChange={e => setNewUser({...newUser, email: e.target.value})} /></div>
              <div><label>Mot de passe (14 caractères minimum)</label><input type="password" required minLength={14} value={newUser.password} onChange={e => setNewUser({...newUser, password: e.target.value})} /></div>
              <div><label>Rôle</label><select value={newUser.role} onChange={e => setNewUser({...newUser, role: e.target.value})}>
                <option value="security_analyst">Analyste sécurité</option><option value="fraud_analyst">Analyste fraude</option><option value="auditor">Auditeur</option><option value="reader">Lecture seule</option><option value="admin">Administrateur</option>
              </select></div>
              <div className="row" style={{alignItems:'end'}}><button disabled={busy}>Créer le compte</button></div>
            </form>
          </section>
          <section className="panel">
            <div className="row"><h2 className="grow">Comptes & rôles</h2><button className="secondary" onClick={() => getUsers().then(data => setUsers(data.users)).catch(fail)}>Actualiser</button></div>
            <div className="table-wrap"><table><thead><tr><th>Utilisateur</th><th>Rôle</th><th>État</th><th>Action</th></tr></thead><tbody>
              {users.map(item => <tr key={item.id}>
                <td>{item.display_name}<br/><small>{item.username}</small></td>
                <td><select aria-label={'Rôle de ' + item.username} value={item.role} disabled={item.id === user.id} onChange={e => changeUserRole(item.id, e.target.value)}>
                  <option value="admin">Administrateur</option><option value="security_analyst">Analyste sécurité</option><option value="fraud_analyst">Analyste fraude</option><option value="auditor">Auditeur</option><option value="reader">Lecture seule</option>
                </select></td>
                <td><span className={item.is_active ? 'success' : 'muted'}>{item.is_active ? 'Actif' : 'Désactivé'}</span></td>
                <td className="row">
                  <button className="secondary" disabled={item.id === user.id} onClick={() => toggleUserActive(item)}>{item.is_active ? 'Désactiver' : 'Réactiver'}</button>
                  <button className="secondary" disabled={item.id === user.id} onClick={() => revokeSessions(item.id)}>Révoquer sessions</button>
                </td></tr>)}
            </tbody></table></div>
          </section>
          <section className="panel">
            <h2>Réinitialiser un mot de passe</h2>
            <form className="row" onSubmit={submitPasswordReset}>
              <div className="grow"><label htmlFor="reset-user">Compte</label><select id="reset-user" required value={resetUserId} onChange={e => setResetUserId(e.target.value ? Number(e.target.value) : '')}>
                <option value="">Sélectionner un utilisateur</option>{users.map(item => <option key={item.id} value={item.id}>{item.username} ({roleLabels[item.role]})</option>)}
              </select></div>
              <div className="grow"><label htmlFor="reset-password">Nouveau mot de passe (14 caractères minimum)</label><input id="reset-password" type="password" minLength={14} required value={resetPassword} onChange={e => setResetPassword(e.target.value)} /></div>
              <button disabled={busy || resetUserId === ''}>Réinitialiser</button>
            </form>
          </section>
          <section className="panel">
            <div className="row"><h2 className="grow">Intégrité du journal d’audit</h2><button className="secondary" onClick={checkAuditChain}>Vérifier la chaîne HMAC</button></div>
            {auditStatus && <p className={auditStatus.valid ? 'success' : 'error'}>{auditStatus.valid ? 'Chaîne valide' : 'Chaîne invalide'} · {auditStatus.entries_checked} entrée(s) vérifiée(s) · {auditStatus.last_hash.slice(0, 16)}…</p>}
          </section>
        </>
      )}
      <footer className="muted" style={{marginTop: 28}}>
        <small>Outil d’aide à l’audit et au triage. Pas de décision automatisée de blocage de compte, de gel de fonds ou d’accusation de fraude. Utiliser uniquement des périmètres et jeux de données autorisés.</small>
      </footer>
    </main>
  );
}

export default App;
