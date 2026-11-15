from app.services.fraud_engine import evaluate_mobile_money_event

def test_mobile_money_rules_map_to_f3_and_controls():
    result = evaluate_mobile_money_event({
        "sim_change_hours": 1,
        "beneficiary_added": True,
        "beneficiary_age_minutes": 20,
        "remote_access_tool_detected": True,
        "social_engineering_reported": True,
        "transactions_10m": 12,
        "rapid_cashout": True,
        "channel": "bank_transfer",
    })
    assert result["risk_level"] == "critical"
    assert result["risk_score"] == 100
    ids = {item["id"] for item in result["mitre_f3"]["techniques"]}
    assert {"F1005.003", "F1006", "T1219", "T1566.004", "F1025.003"} <= ids
    controls = {control for signal in result["signals"] for control in signal["recommended_controls"]}
    assert {"MM-01", "MM-02", "MM-04", "MM-05", "MM-06"} <= controls
    assert result["decision_note"].startswith("Aide au triage uniquement")

def test_no_indicators_produce_low_risk_and_no_false_accusation():
    result = evaluate_mobile_money_event({})
    assert result["risk_score"] == 0
    assert result["risk_level"] == "low"
    assert result["signals"] == []
