from __future__ import annotations

from typing import Any


class RiskScoringService:
    """
    Unified repository-level risk scoring service (SAST + DAST).

    Formula version v1.0.0:
    - unified_score = sast_score * 0.60 + dast_score * 0.40
    """

    FORMULA_VERSION = "v1.0.0"
    SAST_WEIGHT = 0.60
    DAST_WEIGHT = 0.40

    LEVEL_THRESHOLDS = {
        "LOW": (0.0, 24.99),
        "MEDIUM": (25.0, 49.99),
        "HIGH": (50.0, 74.99),
        "CRITICAL": (75.0, 100.0),
    }

    def _to_float(self, value: Any) -> float | None:
        try:
            if value is None:
                return None
            return float(value)
        except (TypeError, ValueError):
            return None

    def _clamp_0_100(self, value: float) -> float:
        return max(0.0, min(100.0, value))

    def _level_from_score(self, score: float) -> str:
        for level, (min_v, max_v) in self.LEVEL_THRESHOLDS.items():
            if min_v <= score <= max_v:
                return level
        return "CRITICAL" if score >= 75.0 else "LOW"

    def _extract_field(self, item: Any, field_name: str, default: Any = None) -> Any:
        if isinstance(item, dict):
            return item.get(field_name, default)
        return getattr(item, field_name, default)

    def _compute_sast_score(self, reports: list[Any]) -> dict[str, Any]:
        if not reports:
            return {
                "score": 0.0,
                "details": {
                    "reports_total": 0,
                    "reports_with_risk_score": 0,
                    "status_counts": {},
                    "base_avg_risk_score": 0.0,
                    "status_adjustment": 0.0,
                },
            }

        status_counts: dict[str, int] = {
            "BENIGN": 0,
            "SUSPICIOUS": 0,
            "MALICIOUS": 0,
            "SKIPPED": 0,
            "ANALYSIS_ERROR": 0,
            "POTENTIALLY_MALFORMED": 0,
            "UNKNOWN": 0,
        }
        risk_values: list[float] = []

        for item in reports:
            status = str(self._extract_field(item, "security_status", "UNKNOWN")).upper()
            if status in status_counts:
                status_counts[status] += 1
            else:
                status_counts["UNKNOWN"] += 1

            risk_score = self._to_float(self._extract_field(item, "risk_score", None))
            if risk_score is not None:
                risk_values.append(self._clamp_0_100(risk_score))

        base_avg = round(sum(risk_values) / len(risk_values), 2) if risk_values else 0.0
        decision_population = (
            status_counts["BENIGN"] + status_counts["SUSPICIOUS"] + status_counts["MALICIOUS"]
        )
        suspicious_ratio = (
            status_counts["SUSPICIOUS"] / decision_population if decision_population else 0.0
        )
        malicious_ratio = (
            status_counts["MALICIOUS"] / decision_population if decision_population else 0.0
        )
        status_adjustment = min((suspicious_ratio * 20.0) + (malicious_ratio * 35.0), 20.0)

        sast_score = round(self._clamp_0_100(base_avg + status_adjustment), 2)
        return {
            "score": sast_score,
            "details": {
                "reports_total": len(reports),
                "reports_with_risk_score": len(risk_values),
                "status_counts": status_counts,
                "base_avg_risk_score": base_avg,
                "status_adjustment": round(status_adjustment, 2),
            },
        }

    def _compute_dast_score(self, dast_result: dict[str, Any] | None) -> dict[str, Any]:
        if not isinstance(dast_result, dict):
            return {
                "score": 0.0,
                "details": {
                    "dast_status": "UNAVAILABLE",
                    "network_capture_status": "UNAVAILABLE",
                },
            }

        dast_status = str(dast_result.get("status", "UNAVAILABLE")).upper()
        network_capture = dast_result.get("network_capture", {})
        if not isinstance(network_capture, dict):
            network_capture = {}
        capture_status = str(network_capture.get("status", "UNAVAILABLE")).upper()
        metrics = network_capture.get("metrics", {})
        if not isinstance(metrics, dict):
            metrics = {}

        if dast_status in {"DISABLED", "UNAVAILABLE"}:
            score = 0.0
        elif dast_status == "FAILED":
            score = 70.0
        elif capture_status == "PARSED":
            packets_total = float(metrics.get("packets_total", 0) or 0)
            unique_destinations = float(metrics.get("unique_destinations", 0) or 0)
            unique_destination_ports = float(metrics.get("unique_destination_ports", 0) or 0)
            dns_queries_count = float(metrics.get("dns_queries_count", 0) or 0)
            tcp_syn_attempts = float(metrics.get("tcp_syn_attempts", 0) or 0)

            packets_component = min((packets_total / 200.0) * 100.0, 100.0)
            destinations_component = min((unique_destinations / 15.0) * 100.0, 100.0)
            ports_component = min((unique_destination_ports / 30.0) * 100.0, 100.0)
            dns_component = min((dns_queries_count / 20.0) * 100.0, 100.0)
            syn_component = min((tcp_syn_attempts / 20.0) * 100.0, 100.0)

            score = (
                (0.15 * packets_component)
                + (0.20 * destinations_component)
                + (0.15 * ports_component)
                + (0.15 * dns_component)
                + (0.35 * syn_component)
            )
            if int(dast_result.get("container_exit_code", 0) or 0) != 0:
                score += 15.0
        else:
            # DAST executed but capture produced no parsable network evidence.
            score = 10.0

        return {
            "score": round(self._clamp_0_100(score), 2),
            "details": {
                "dast_status": dast_status,
                "network_capture_status": capture_status,
            },
        }

    def compute_unified_risk(self, response_reports: list[Any], dast_result: dict[str, Any] | None) -> dict[str, Any]:
        sast_component = self._compute_sast_score(response_reports)
        dast_component = self._compute_dast_score(dast_result)

        sast_score = float(sast_component["score"])
        dast_score = float(dast_component["score"])

        unified_score = round(
            self._clamp_0_100((sast_score * self.SAST_WEIGHT) + (dast_score * self.DAST_WEIGHT)),
            2,
        )
        risk_level = self._level_from_score(unified_score)

        return {
            "risk_score": unified_score,
            "risk_level": risk_level,
            "formula_version": self.FORMULA_VERSION,
            "weights": {
                "sast": self.SAST_WEIGHT,
                "dast": self.DAST_WEIGHT,
            },
            "components": {
                "sast_score": sast_score,
                "dast_score": dast_score,
                "weighted_sast": round(sast_score * self.SAST_WEIGHT, 2),
                "weighted_dast": round(dast_score * self.DAST_WEIGHT, 2),
            },
            "thresholds": self.LEVEL_THRESHOLDS,
            "details": {
                "sast": sast_component["details"],
                "dast": dast_component["details"],
            },
        }

