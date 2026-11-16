from app.services.fraud_engine import evaluate_mobile_money_event

def test_mobile_money_rules_map_to_official_f3_v12_and_controls():
    result = evaluate_mobile_money_event({
        "sim_change_hours": 1,
        "beneficiary_added": True,
        "beneficiary_age_minutes": 20,
        "remote_access_tool_detected": True,
        "social_engineering_reported": True,
        "otp_failures_15m": 5,
        "transactions_10m": 12,
        "rapid_cashout": True,
        "channel": "bank_transfer",
    })
    assert result["risk_level"] == "critical"
    assert result["risk_score"] == 100
    ids = {item["id"] for item in result["mitre_f3"]["techniques"]}
    assert {"F1005.003", "T1451", "T1219", "T1660", "F1025"} <= ids
    tactics = set(result["mitre_f3"]["tactics"])
    assert {"initial-access", "positioning", "execution", "monetization"} <= tactics
    controls = {control for signal in result["signals"] for control in signal["recommended_controls"]}
    assert {"MM-01", "MM-02", "MM-04", "MM-05", "MM-06"} <= controls
    assert result["decision_note"].startswith("Aide au triage uniquement")

def test_voice_call_center_and_mfa_events_map_to_f3():
    result = evaluate_mobile_money_event({
        "vishing_reported": True,
        "fraudulent_call_center_suspected": True,
        "caller_impersonation_suspected": True,
        "mfa_interception_suspected": True,
        "mfa_request_generation_suspected": True,
        "phone_number_spoofing_suspected": True,
    })
    ids = {item["id"] for item in result["mitre_f3"]["techniques"]}
    assert {"F1031", "F1032", "F1050", "F1056", "T1111", "T1621", "T1660", "F1040"} <= ids
    assert {"initial-access", "resource-development", "stealth"} <= set(result["mitre_f3"]["tactics"])

def test_no_indicators_produce_low_risk_and_no_false_accusation():
    result = evaluate_mobile_money_event({})
    assert result["risk_score"] == 0
    assert result["risk_level"] == "low"
    assert result["signals"] == []
