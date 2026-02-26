from typing import Any


SEVERITY_FALLBACK_WEIGHTS: dict[str, float] = {
    "low": 0.5,
    "medium": 1.0,
    "high": 2.0,
    "critical": 3.0,
}


def _count_code_lines(source_code: str) -> int:
    if not isinstance(source_code, str) or not source_code:
        return 0
    return len(source_code.splitlines())


def _finding_weight(finding: dict[str, Any]) -> float:
    explicit_weight = finding.get("weight")
    if isinstance(explicit_weight, (int, float)):
        return float(explicit_weight)

    severity = str(finding.get("severity", "")).strip().lower()
    return SEVERITY_FALLBACK_WEIGHTS.get(severity, 1.0)


def build_antlr_signal_summary(raw_report: dict[str, Any]) -> dict[str, float | int]:
    source_code = raw_report.get("original_code", "")
    static_findings = raw_report.get("static_findings", [])
    if not isinstance(static_findings, list):
        static_findings = []

    lines_total = _count_code_lines(source_code)
    findings_count = len(static_findings)
    total_weight = sum(_finding_weight(f) for f in static_findings if isinstance(f, dict))
    density = (findings_count / lines_total) if lines_total > 0 else 0.0
    weight_per_100_lines = ((total_weight / lines_total) * 100.0) if lines_total > 0 else 0.0

    return {
        "lines_total": lines_total,
        "findings_count": findings_count,
        "findings_total_weight": round(total_weight, 4),
        "findings_density": round(density, 6),
        "findings_weight_per_100_lines": round(weight_per_100_lines, 4),
    }


def refine_prediction_with_antlr(
    model_binary: int,
    raw_report: dict[str, Any],
) -> dict[str, Any]:
    """
    Hybrid decision policy:
    - Base on model binary output (0/1).
    - Adjust using ANTLR signal strength (findings count/weight vs code size).
    - No probability thresholds are used for final decision.
    """
    signals = build_antlr_signal_summary(raw_report)
    lines_total = int(signals["lines_total"])
    findings_count = int(signals["findings_count"])
    findings_density = float(signals["findings_density"])
    findings_weight_per_100_lines = float(signals["findings_weight_per_100_lines"])
    findings_total_weight = float(signals["findings_total_weight"])

    # ANTLR signal profiles
    # Example target: 1000 lines + 1 minor finding should not become malware.
    low_antlr_signal = (
        lines_total >= 300
        and findings_count <= 2
        and findings_density <= 0.01
        and findings_total_weight <= 2.5
    )

    # Example target: 10 lines + 8 findings is high risk signal.
    high_antlr_signal = (
        (findings_count >= 8 and findings_density >= 0.30)
        or (findings_count >= 5 and findings_weight_per_100_lines >= 35.0)
    )

    # Hard rule requested: if ANTLR finds nothing, do not keep suspicious/malicious.
    if findings_count == 0 or findings_total_weight <= 0.0:
        return {
            "effective_class": "BENIGN",
            "effective_label": 0,
            "decision_reason": "antlr_no_findings_force_benign",
            "decision_overridden_by_antlr": True,
            "antlr_signals": signals,
        }

    overridden = False
    # If model says malware, ANTLR must reinforce it; otherwise pull down.
    if model_binary == 1 and high_antlr_signal:
        effective_class = "MALICIOUS"
        effective_label: int | None = 1
        reason = "antlr_reinforced_malicious"
        overridden = True
    elif model_binary == 1 and low_antlr_signal:
        effective_class = "BENIGN"
        effective_label = 0
        reason = "antlr_override_false_positive_low_signal"
        overridden = True
    elif model_binary == 1:
        effective_class = "SUSPICIOUS"
        effective_label = None
        reason = "antlr_not_reinforced_pull_to_suspicious"
        overridden = True
    # If model says benign, promote only when ANTLR signal is strong.
    elif model_binary == 0 and high_antlr_signal:
        effective_class = "SUSPICIOUS"
        effective_label = None
        reason = "antlr_override_false_negative_high_signal"
        overridden = True
    else:
        effective_class = "BENIGN"
        effective_label = 0
        reason = "antlr_reinforced_benign"

    return {
        "effective_class": effective_class,
        "effective_label": effective_label,
        "decision_reason": reason,
        "decision_overridden_by_antlr": overridden,
        "antlr_signals": signals,
    }
