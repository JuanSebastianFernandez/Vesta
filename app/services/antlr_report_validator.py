from __future__ import annotations

from typing import Any


class AntlrReportValidator:
    """
    Validates stored ANTLR findings and provides per-finding diagnostics.
    """

    ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def _is_int(self, value: Any) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    def _is_number(self, value: Any) -> bool:
        return isinstance(value, (int, float)) and not isinstance(value, bool)

    def validate(
        self,
        *,
        antlr_report: list[dict[str, Any]] | Any,
        amount_findings: int | None,
        antlr_features: dict[str, Any] | Any,
    ) -> dict[str, Any]:
        issues: list[str] = []
        components: list[dict[str, Any]] = []

        report_list: list[dict[str, Any]]
        if isinstance(antlr_report, list):
            report_list = [r for r in antlr_report if isinstance(r, dict)]
            if len(report_list) != len(antlr_report):
                issues.append("antlr_report contains non-object entries.")
        else:
            report_list = []
            issues.append("antlr_report is not a list.")

        expected_findings = amount_findings if isinstance(amount_findings, int) else None
        if expected_findings is None:
            issues.append("amount_findings is null or invalid.")
        elif expected_findings != len(report_list):
            issues.append(
                f"amount_findings mismatch: stored={expected_findings}, report_len={len(report_list)}."
            )

        for idx, finding in enumerate(report_list):
            finding_issues: list[str] = []
            finding_type = finding.get("finding_type")
            severity = finding.get("severity")
            line = finding.get("line")
            weight = finding.get("weight")

            if not isinstance(finding_type, str) or not finding_type.strip():
                finding_issues.append("missing_or_invalid_finding_type")
            if not isinstance(severity, str) or severity.upper() not in self.ALLOWED_SEVERITIES:
                finding_issues.append("missing_or_invalid_severity")
            if not self._is_int(line) or line < 0:
                finding_issues.append("missing_or_invalid_line")
            if weight is not None:
                if not self._is_number(weight):
                    finding_issues.append("invalid_weight_type")
                else:
                    numeric_weight = float(weight)
                    if numeric_weight < 0.0 or numeric_weight > 1.0:
                        finding_issues.append("weight_out_of_range_0_1")

            components.append(
                {
                    "index": idx,
                    "finding_type": finding_type,
                    "severity": severity,
                    "line": line,
                    "weight": weight,
                    "valid": len(finding_issues) == 0,
                    "issues": finding_issues,
                }
            )

        feature_issues: list[str] = []
        feature_signals = {}
        if isinstance(antlr_features, dict):
            feature_signals = antlr_features.get("antlr_signals", {})
            if not isinstance(feature_signals, dict):
                feature_issues.append("antlr_features.antlr_signals is not an object.")
                feature_signals = {}
        else:
            feature_issues.append("antlr_features is not an object.")
        if feature_issues:
            issues.extend(feature_issues)

        findings_from_signals = feature_signals.get("findings_count")
        if findings_from_signals is not None and isinstance(findings_from_signals, (int, float)):
            if int(findings_from_signals) != len(report_list):
                issues.append(
                    "antlr_signals.findings_count mismatch against antlr_report length."
                )

        valid_components = sum(1 for c in components if c["valid"])
        invalid_components = len(components) - valid_components

        return {
            "is_valid": len(issues) == 0 and invalid_components == 0,
            "issues": issues,
            "summary": {
                "findings_count_report": len(report_list),
                "findings_count_amount_field": amount_findings,
                "valid_components": valid_components,
                "invalid_components": invalid_components,
            },
            "components": components,
        }

