from __future__ import annotations

F3_VERSION = "1.1"
F3_FRAMEWORK_URL = "https://ctid.mitre.org/fraud/"

F3_TECHNIQUES = {
    "F1003": {"name": "Abuse SMS verification", "tactic": "execution", "source": "f3"},
    "F1004": {"name": "Access with Stolen Session Cookie", "tactic": "initial-access", "source": "f3"},
    "F1005.003": {"name": "Account Manipulation: Add Beneficiary", "tactic": "positioning", "source": "f3"},
    "F1006": {"name": "Account Takeover", "tactic": "initial-access", "source": "f3"},
    "F1002.001": {"name": "Abuse of Public-Facing API: Mobile API Abuse", "tactic": "positioning", "source": "f3"},
    "F1031": {"name": "Impersonate Account Holder", "tactic": "initial-access", "source": "f3"},
    "F1032": {"name": "Impersonate Official", "tactic": "initial-access", "source": "f3"},
    "F1040": {"name": "Phone Number Spoofing", "tactic": "stealth", "source": "f3"},
    "T1219": {"name": "Remote Access Tools", "tactic": "positioning", "source": "attack"},
    "T1453": {"name": "Abuse Accessibility Features", "tactic": "positioning", "source": "attack"},
    "T1113": {"name": "Screen Capture", "tactic": "positioning", "source": "attack"},
    "T1566.004": {"name": "Phishing: Spearphishing Voice", "tactic": "initial-access", "source": "attack"},
}

CONTROL_CATALOG = [
    {
        "id": "MM-01", "title": "Changement SIM / numéro de téléphone",
        "objective": "Empêcher la prise de contrôle d’un portefeuille après un remplacement SIM ou une réattribution de numéro.",
        "test": "Échantillonner les changements SIM/numéro et vérifier une période de refroidissement, une preuve opérateur et une authentification indépendante avant déblocage.",
        "evidence": ["journaux de changement SIM", "horodatages", "tickets opérateur", "journaux d’authentification"],
        "frequency": "hebdomadaire", "owner": "Operations + Fraud",
    },
    {
        "id": "MM-02", "title": "Ajout de bénéficiaire et premier transfert",
        "objective": "Réduire la fraude par ajout de bénéficiaire suivi d’un cash-out rapide.",
        "test": "Vérifier les délais de refroidissement, limites graduelles, authentification renforcée et contrôle indépendant du premier transfert.",
        "evidence": ["journal des bénéficiaires", "historique des transferts", "décisions d’authentification"],
        "frequency": "hebdomadaire", "owner": "Payments Operations",
    },
    {
        "id": "MM-03", "title": "Protection OTP et anti-vishing",
        "objective": "Limiter l’abus de codes OTP, l’usurpation d’identité et l’ingénierie sociale.",
        "test": "Examiner les échecs OTP, demandes répétées, changements de canal et signalements de vishing ; vérifier les scripts de rappel sur numéro préenregistré.",
        "evidence": ["journaux OTP agrégés", "scripts d’appel", "tickets clients", "résultats de formation"],
        "frequency": "mensuelle", "owner": "Fraud + Customer Protection",
    },
    {
        "id": "MM-04", "title": "Appareil de confiance et intégrité mobile",
        "objective": "Détecter les changements d’appareil, abus d’accessibilité, overlays et outils de contrôle à distance.",
        "test": "Vérifier l’enrôlement d’appareil, l’attestation applicative, la révocation de session et le traitement des alertes EDR/MDM.",
        "evidence": ["journaux d’appareils", "alertes MDM/EDR", "événements de session", "tickets de remédiation"],
        "frequency": "mensuelle", "owner": "Mobile Security",
    },
    {
        "id": "MM-05", "title": "Vélocité et comportement transactionnel",
        "objective": "Repérer les rafales de transactions, montants atypiques et transferts en cascade.",
        "test": "Recalculer les seuils par segment, comparer les alertes aux transactions historiques et documenter les faux positifs.",
        "evidence": ["événements transactionnels", "seuils approuvés", "alertes", "résultats de revue"],
        "frequency": "quotidienne", "owner": "Fraud Monitoring",
    },
    {
        "id": "MM-06", "title": "Agents, cash-out et bénéficiaires mutualisés",
        "objective": "Identifier les réseaux de comptes mules et de points de retrait anormaux.",
        "test": "Rechercher des bénéficiaires/agents partagés, flux entrants-sortants rapides, concentration et écarts de liquidité.",
        "evidence": ["journaux agent", "graphe pseudonymisé des transferts", "rapports de liquidité", "listes d’alertes"],
        "frequency": "hebdomadaire", "owner": "Agent Network Control",
    },
    {
        "id": "MM-07", "title": "Remboursements, reversals et séparation des tâches",
        "objective": "Limiter l’abus de remboursements et les manipulations par des comptes privilégiés.",
        "test": "Revoir les annulations et remboursements, les seuils d’approbation, les doubles validations et les conflits de rôles.",
        "evidence": ["journaux de reversals", "matrice des habilitations", "approbations", "rapprochements"],
        "frequency": "mensuelle", "owner": "Internal Control",
    },
    {
        "id": "MM-08", "title": "Rapprochement indépendant des règlements",
        "objective": "Détecter les écarts entre le ledger, les opérateurs, les agrégateurs et la trésorerie.",
        "test": "Rejouer un échantillon de rapprochements et vérifier la résolution documentée des suspens et écarts.",
        "evidence": ["fichiers de règlement", "ledger", "rapprochements", "journal des suspens"],
        "frequency": "quotidienne", "owner": "Finance Control",
    },
    {
        "id": "MM-09", "title": "Accès privilégiés et réinitialisation de compte",
        "objective": "Réduire les abus internes et les prises de contrôle via le support.",
        "test": "Revoir les accès à privilèges, réinitialisations PIN, changements de limites, élévations de droits et journaux d’administration.",
        "evidence": ["revues d’accès", "journaux d’administration", "tickets support", "approbations"],
        "frequency": "mensuelle", "owner": "IAM + Internal Control",
    },
    {
        "id": "MM-10", "title": "Gestion de preuves et réponse aux incidents",
        "objective": "Préserver les éléments probants et assurer une réponse traçable et proportionnée.",
        "test": "Vérifier la chronologie, les empreintes de preuve, la conservation, l’escalade, les notifications et la clôture.",
        "evidence": ["dossier d’incident", "empreintes SHA-256", "journal d’audit", "rapport de clôture"],
        "frequency": "par incident", "owner": "Incident Response",
    },
]

def evaluate_mobile_money_event(data: dict) -> dict:
    score = 0
    signals = []
    technique_ids = set()
    f3_tactics = set()

    def add(code: str, label: str, points: int, severity: str, explanation: str, controls: list[str], techniques: tuple[str, ...] = ()) -> None:
        nonlocal score
        score += points
        signals.append({
            "rule_id": code, "label": label, "points": points, "severity": severity,
            "explanation": explanation, "recommended_controls": controls,
        })
        for technique_id in techniques:
            if technique_id in F3_TECHNIQUES:
                technique_ids.add(technique_id)
                f3_tactics.add(F3_TECHNIQUES[technique_id]["tactic"])

    sim_age = data.get("sim_change_hours")
    if sim_age is not None and sim_age <= 2:
        add("SIM-RECENT-02H", "Changement SIM très récent", 35, "critical",
            "Le changement SIM dans les deux dernières heures augmente le risque de détournement du canal OTP.",
            ["MM-01", "MM-03"], ("F1003", "F1006"))
    elif sim_age is not None and sim_age <= 72:
        add("SIM-RECENT-72H", "Changement SIM récent", 22, "high",
            "Un changement SIM récent doit déclencher une vérification indépendante avant opération sensible.",
            ["MM-01", "MM-03"], ("F1003", "F1006"))

    beneficiary_age = data.get("beneficiary_age_minutes")
    if data.get("beneficiary_added") and beneficiary_age is not None and beneficiary_age <= 60:
        add("NEW-BENEFICIARY-01H", "Bénéficiaire ajouté il y a moins d’une heure", 25, "high",
            "L’ajout récent d’un bénéficiaire suivi d’une transaction est un signal de positionnement.",
            ["MM-02", "MM-06"], ("F1005.003",))
    elif data.get("beneficiary_added") and beneficiary_age is not None and beneficiary_age <= 1440:
        add("NEW-BENEFICIARY-24H", "Bénéficiaire ajouté dans les dernières 24 heures", 16, "medium",
            "Le délai court entre enrôlement et premier transfert mérite une revue.",
            ["MM-02"], ("F1005.003",))
    elif data.get("beneficiary_added"):
        add("NEW-BENEFICIARY", "Ajout de bénéficiaire déclaré", 8, "low",
            "Confirmer que le bénéficiaire est connu du titulaire.", ["MM-02"], ("F1005.003",))

    if data.get("remote_access_tool_detected"):
        add("REMOTE-ACCESS", "Outil de contrôle à distance détecté", 35, "critical",
            "Un outil de prise en main à distance peut permettre à un fraudeur de guider ou contrôler l’appareil.",
            ["MM-04", "MM-03"], ("T1219",))
    if data.get("accessibility_abuse_detected"):
        add("ACCESSIBILITY-ABUSE", "Comportement d’accessibilité anormal", 25, "high",
            "Un service d’accessibilité abusif peut lire l’écran ou automatiser des actions sensibles.",
            ["MM-04"], ("T1453",))
    if data.get("screen_capture_detected"):
        add("SCREEN-CAPTURE", "Indice de capture d’écran inattendue", 15, "medium",
            "La capture d’écran sur un parcours sensible peut exposer des informations de session.",
            ["MM-04"], ("T1113",))
    if data.get("app_integrity_warning"):
        add("APP-INTEGRITY", "Alerte d’intégrité de l’application", 20, "high",
            "Une application modifiée, non officielle ou exécutée dans un environnement compromis exige une analyse séparée.",
            ["MM-04"], ())

    if data.get("social_engineering_reported"):
        add("SOCIAL-ENGINEERING", "Signalement de phishing, smishing ou vishing", 25, "high",
            "Un signalement social-engineering associé à une transaction impose une vérification hors bande.",
            ["MM-03", "MM-01"], ("F1031", "F1032", "T1566.004"))
    if data.get("phone_number_spoofing_suspected"):
        add("CALLER-ID-SPOOFING", "Usurpation possible du numéro appelant", 15, "medium",
            "Le numéro affiché n’est pas une preuve d’identité de l’appelant.",
            ["MM-03"], ("F1040",))
    if data.get("otp_failures_15m", 0) >= 5:
        add("OTP-FAILURES", "Échecs OTP répétés", 15, "medium",
            "Des échecs rapprochés peuvent signaler une tentative de deviner, intercepter ou détourner le second facteur.",
            ["MM-03", "MM-01"], ("F1003",))

    if data.get("new_device"):
        add("NEW-DEVICE", "Nouvel appareil", 12, "medium",
            "Un nouvel appareil doit être recoupé avec les événements de récupération et de changement SIM.",
            ["MM-04", "MM-09"], ("F1006",))
    if data.get("impossible_travel"):
        add("IMPOSSIBLE-TRAVEL", "Incohérence géographique de session", 25, "high",
            "Les emplacements successifs semblent incompatibles avec le temps écoulé ; une VPN ou une géolocalisation imprécise peut aussi l’expliquer.",
            ["MM-04", "MM-09"], ("F1004", "F1006"))
    if data.get("mobile_api_anomaly"):
        add("MOBILE-API-ANOMALY", "Anomalie d’utilisation de l’API mobile", 25, "high",
            "Le comportement API diffère du profil attendu et doit être corrélé avec les journaux de session.",
            ["MM-04", "MM-09"], ("F1002.001",))

    velocity = data.get("transactions_10m", 0)
    if velocity >= 10:
        add("VELOCITY-10", "Vélocité transactionnelle très élevée", 25, "high",
            "Dix transactions ou plus en dix minutes dépassent un seuil initial générique à calibrer.",
            ["MM-05", "MM-06"], ())
    elif velocity >= 5:
        add("VELOCITY-5", "Vélocité transactionnelle élevée", 15, "medium",
            "Cinq transactions ou plus en dix minutes méritent une revue contextualisée.",
            ["MM-05"], ())

    ratio = data.get("amount_vs_30d_median", 1.0)
    if ratio >= 10:
        add("AMOUNT-OUTLIER-10X", "Montant supérieur à dix fois la médiane client", 25, "high",
            "Comparer à l’historique du client et à son segment avant toute décision.",
            ["MM-05"], ())
    elif ratio >= 5:
        add("AMOUNT-OUTLIER-5X", "Montant supérieur à cinq fois la médiane client", 15, "medium",
            "Un montant atypique est un signal de triage, pas une preuve de fraude.",
            ["MM-05"], ())

    if data.get("shared_beneficiary_accounts_24h", 0) >= 3:
        add("SHARED-BENEFICIARY", "Bénéficiaire partagé par plusieurs comptes", 20, "high",
            "Un bénéficiaire commun à plusieurs comptes en peu de temps peut indiquer un réseau de collecte.",
            ["MM-06", "MM-05"], ())
    if data.get("rapid_cashout"):
        add("RAPID-CASHOUT", "Cash-out rapide après réception", 20, "high",
            "La conversion rapide des fonds reçus est un signal de monétisation à corréler au contexte.",
            ["MM-06", "MM-08"], ())
        f3_tactics.add("monetization")
        if data.get("channel") == "bank_transfer":
            technique_ids.add("F1025.003")

    score = min(score, 100)
    level = "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"
    actions = []
    if level in {"high", "critical"}:
        actions.extend([
            "Mettre l’opération en revue selon la politique approuvée ; ne pas conclure automatiquement à une fraude.",
            "Confirmer avec le client via un canal préenregistré indépendant de l’appel, du SMS ou du lien suspect.",
            "Suspendre/révoquer les sessions à risque et exiger une authentification résistante au phishing avant rétablissement.",
            "Conserver les journaux, références pseudonymisées et horodatages pour l’enquête.",
        ])
    elif level == "medium":
        actions.extend([
            "Effectuer une revue renforcée et comparer avec le profil historique du client.",
            "Vérifier les changements SIM, appareil et bénéficiaire avant de lever l’alerte.",
        ])
    else:
        actions.append("Surveiller les événements liés et documenter tout écart par rapport au profil habituel.")

    techniques = [
        {"id": technique_id, **F3_TECHNIQUES[technique_id]}
        for technique_id in sorted(technique_ids)
    ]
    return {
        "risk_score": score,
        "risk_level": level,
        "signals": signals,
        "recommended_actions": actions,
        "mitre_f3": {
            "version": F3_VERSION,
            "tactics": sorted(f3_tactics),
            "techniques": techniques,
            "framework_url": F3_FRAMEWORK_URL,
        },
        "decision_note": "Aide au triage uniquement. Les seuils sont initiaux, non calibrés sur les données de l’établissement. Toute décision de blocage, gel ou déclaration doit suivre les procédures, délégations et exigences réglementaires applicables.",
    }
