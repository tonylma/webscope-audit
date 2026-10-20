<!DOCTYPE html>
<html lang="fr">
  <head>
    <meta charset="utf-8" />
    <title>{{ result.get('title', 'WebScope Audit V3') }}</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 2rem; color: #1f2937; }
      h1, h2, h3 { color: #0f172a; }
      .meta { background: #f8fafc; border: 1px solid #dbeafe; border-radius: 8px; padding: 1rem; }
      .panel { margin-top: 1.5rem; }
      table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
      th, td { border: 1px solid #d1d5db; padding: 0.6rem; text-align: left; vertical-align: top; }
      .ok { color: #166534; font-weight: bold; }
      .warn { color: #92400e; font-weight: bold; }
      .error { color: #991b1b; font-weight: bold; }
      pre { white-space: pre-wrap; }
      ul { margin-top: 0.5rem; }
    </style>
  </head>
  <body>
    <h1>{{ result.get('title', 'WebScope Audit V3') }}</h1>
    <div class="meta">
      <p><strong>Cible :</strong> {{ result.get('target', '') }}</p>
      <p><strong>Date :</strong> {{ result.get('collected_at', '') }}</p>
      <p><strong>Périmètre :</strong> {{ result.get('scope', '') }}</p>
    </div>

    <div class="panel">
      <h2>Résumé</h2>
      {% if result.get('errors') %}
        <ul>
          {% for error in result.get('errors', []) %}
            <li>{{ error }}</li>
          {% endfor %}
        </ul>
      {% else %}
        <p class="ok">Aucune erreur critique détectée dans le périmètre scanné.</p>
      {% endif %}
    </div>

    <div class="panel">
      <h2>DNS</h2>
      <table>
        <tr><th>Hôte</th><td>{{ result.get('dns', {}).get('hostname', '') }}</td></tr>
        <tr><th>Enregistrements</th><td><pre>{{ result.get('dns', {}).get('records', {}) | tojson(indent=2) }}</pre></td></tr>
        <tr><th>Erreurs</th><td>{{ result.get('dns', {}).get('errors', []) | join(', ') }}</td></tr>
      </table>
    </div>

    <div class="panel">
      <h2>HTTP / HTTPS</h2>
      <table>
        <tr><th>URL</th><td>{{ result.get('http', {}).get('url', '') }}</td></tr>
        <tr><th>Statut</th><td>{{ result.get('http', {}).get('status') }}</td></tr>
        <tr><th>Final URL</th><td>{{ result.get('http', {}).get('final_url', '') }}</td></tr>
        <tr><th>Serveur</th><td>{{ result.get('http', {}).get('server', '') }}</td></tr>
        <tr><th>Temps de réponse</th><td>{{ result.get('http', {}).get('response_time_ms', 0) }} ms</td></tr>
      </table>
    </div>

    <div class="panel">
      <h2>TLS</h2>
      <table>
        <tr><th>Hôte</th><td>{{ result.get('tls', {}).get('hostname', '') }}</td></tr>
        <tr><th>Validation</th><td>{{ result.get('tls', {}).get('certificate', {}).get('validation_status', 'unknown') }}</td></tr>
        <tr><th>Certificat</th><td><pre>{{ result.get('tls', {}).get('certificate', {}) | tojson(indent=2) }}</pre></td></tr>
      </table>
    </div>

    <div class="panel">
      <h2>Ports</h2>
      <pre>{{ result.get('ports', {}) | tojson(indent=2) }}</pre>
    </div>

    <div class="panel">
      <h2>Sous-domaines</h2>
      <ul>
        {% for host in result.get('subdomains', []) %}
          <li>{{ host }}</li>
        {% endfor %}
      </ul>
    </div>

    <div class="panel">
      <h2>Technologies</h2>
      <h3>Confirmées</h3>
      <ul>
        {% for item in result.get('technologies', {}).get('confirmed', []) %}
          <li>{{ item.name }} ({{ item.source }}, {{ item.confidence }})</li>
        {% endfor %}
      </ul>
      <h3>Supposées</h3>
      <ul>
        {% for item in result.get('technologies', {}).get('suspected', []) %}
          <li>{{ item.name }} ({{ item.source }}, {{ item.confidence }})</li>
        {% endfor %}
      </ul>
    </div>

    <div class="panel">
      <h2>Recommandations</h2>
      <ul>
        {% for item in result.get('recommendations', []) %}
          <li>{{ item }}</li>
        {% endfor %}
      </ul>
    </div>
  </body>
</html>
