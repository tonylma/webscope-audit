<!DOCTYPE html>
<html lang="fr">
  <head>
    <meta charset="utf-8" />
    <title>WebScope Audit - Rapport</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 2rem; color: #1c1c1c; }
      h1, h2, h3 { color: #0d3b66; }
      .meta { background: #eef4ff; padding: 1rem; border-radius: 8px; }
      .section { margin-top: 1.5rem; }
      table { border-collapse: collapse; width: 100%; }
      th, td { border: 1px solid #d0d7de; padding: 0.5rem; text-align: left; vertical-align: top; }
      .ok { color: #1f7a1f; font-weight: bold; }
      .warn { color: #9c5f00; font-weight: bold; }
      .error { color: #a61b1b; font-weight: bold; }
      code { background: #f6f8fa; padding: 0.1rem 0.3rem; }
    </style>
  </head>
  <body>
    <h1>WebScope Audit</h1>
    <div class="meta">
      <p><strong>Cible :</strong> {{ result.target }}</p>
      <p><strong>Date :</strong> {{ result.collected_at }}</p>
      <p><strong>Périmètre :</strong> {{ result.scope }}</p>
    </div>

    <div class="section">
      <h2>Résumé</h2>
      {% if result.errors %}
      <ul>
        {% for error in result.errors %}
        <li>{{ error }}</li>
        {% endfor %}
      </ul>
      {% else %}
      <p class="ok">Aucune erreur critique détectée dans le périmètre actuellement scanné.</p>
      {% endif %}
    </div>

    <div class="section">
      <h2>DNS</h2>
      <table>
        <tr><th>Hostname</th><td>{{ result.dns.get('hostname', '') }}</td></tr>
        <tr><th>Enregistrements</th><td><pre>{{ result.dns.get('records', {}) | tojson(indent=2) }}</pre></td></tr>
        <tr><th>Erreurs</th><td>{{ result.dns.get('errors', []) | join(', ') }}</td></tr>
      </table>
    </div>

    <div class="section">
      <h2>HTTP / HTTPS</h2>
      <table>
        <tr><th>URL</th><td>{{ result.http.get('url', '') }}</td></tr>
        <tr><th>Statut</th><td>{{ result.http.get('status') }}</td></tr>
        <tr><th>Final URL</th><td>{{ result.http.get('final_url', '') }}</td></tr>
        <tr><th>Serveur</th><td>{{ result.http.get('server', '') }}</td></tr>
        <tr><th>Temps de réponse</th><td>{{ result.http.get('response_time_ms', 0) }} ms</td></tr>
      </table>
    </div>

    <div class="section">
      <h2>TLS</h2>
      <table>
        <tr><th>Hôte</th><td>{{ result.tls.get('hostname', '') }}</td></tr>
        <tr><th>État</th><td>{{ result.tls.get('certificate', {}).get('validation_status', 'unknown') }}</td></tr>
        <tr><th>Certificat</th><td><pre>{{ result.tls.get('certificate', {}) | tojson(indent=2) }}</pre></td></tr>
      </table>
    </div>

    <div class="section">
      <h2>Technologies</h2>
      <h3>Confirmées</h3>
      <ul>
        {% for item in result.technologies.get('confirmed', []) %}
        <li>{{ item.name }} ({{ item.source }}, {{ item.confidence }})</li>
        {% endfor %}
      </ul>
      <h3>Supposées</h3>
      <ul>
        {% for item in result.technologies.get('suspected', []) %}
        <li>{{ item.name }} ({{ item.source }}, {{ item.confidence }})</li>
        {% endfor %}
      </ul>
    </div>

    <div class="section">
      <h2>Recommandations</h2>
      <ul>
        {% for item in result.recommendations %}
        <li>{{ item }}</li>
        {% endfor %}
      </ul>
    </div>

    <div class="section">
      <h2>Limites</h2>
      <pre>{{ result.limits | tojson(indent=2) }}</pre>
    </div>
  </body>
</html>
