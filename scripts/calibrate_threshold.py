import argparse
import csv
import json
from dataclasses import dataclass
from pathlib import Path

from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score


@dataclass
class Metrics:
    threshold: float
    precision: float
    recall: float
    f1: float


def load_scores(csv_path: Path, y_true_col: str, y_prob_col: str) -> tuple[list[int], list[float]]:
    y_true: list[int] = []
    y_prob: list[float] = []
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get(y_true_col) is None or row.get(y_prob_col) is None:
                continue
            y_true.append(int(float(row[y_true_col])))
            y_prob.append(float(row[y_prob_col]))
    if not y_true:
        raise ValueError("No rows loaded. Verify input CSV and column names.")
    return y_true, y_prob


def evaluate_at_threshold(y_true: list[int], y_prob: list[float], threshold: float) -> Metrics:
    y_pred = [1 if p >= threshold else 0 for p in y_prob]
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    return Metrics(threshold=threshold, precision=float(precision), recall=float(recall), f1=float(f1))


def find_best_threshold(
    y_true: list[int],
    y_prob: list[float],
    min_precision: float,
    step: float,
) -> Metrics:
    best: Metrics | None = None
    threshold = 0.0
    while threshold <= 1.000001:
        m = evaluate_at_threshold(y_true, y_prob, threshold)
        if m.precision >= min_precision:
            if best is None or m.f1 > best.f1:
                best = m
        threshold += step

    if best is None:
        # If no threshold satisfies min_precision, pick best F1 globally.
        threshold = 0.0
        while threshold <= 1.000001:
            m = evaluate_at_threshold(y_true, y_prob, threshold)
            if best is None or m.f1 > best.f1:
                best = m
            threshold += step

    return best  # type: ignore[return-value]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Calibrate malware decision threshold using y_true/y_prob historical data."
    )
    parser.add_argument("--input-csv", required=True, help="CSV path with y_true and y_prob columns.")
    parser.add_argument("--y-true-col", default="y_true", help="Column name for true label (0/1).")
    parser.add_argument("--y-prob-col", default="y_prob", help="Column name for predicted probability.")
    parser.add_argument("--min-precision", type=float, default=0.70, help="Minimum precision target for malicious class.")
    parser.add_argument("--step", type=float, default=0.01, help="Threshold search step.")
    parser.add_argument(
        "--suspicious-gap",
        type=float,
        default=0.20,
        help="Gap below malicious threshold for suspicious threshold.",
    )
    parser.add_argument("--output-json", default="", help="Optional output file for calibration summary.")
    args = parser.parse_args()

    csv_path = Path(args.input_csv)
    y_true, y_prob = load_scores(csv_path, args.y_true_col, args.y_prob_col)

    best = find_best_threshold(
        y_true=y_true,
        y_prob=y_prob,
        min_precision=args.min_precision,
        step=args.step,
    )
    suspicious_threshold = max(0.0, round(best.threshold - args.suspicious_gap, 4))
    malicious_threshold = round(best.threshold, 4)

    y_pred_best = [1 if p >= malicious_threshold else 0 for p in y_prob]
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred_best, labels=[0, 1]).ravel()
    auc = roc_auc_score(y_true, y_prob)

    summary = {
        "samples": len(y_true),
        "roc_auc": round(float(auc), 6),
        "best_threshold_malicious": malicious_threshold,
        "recommended_threshold_suspicious": suspicious_threshold,
        "metrics_at_best_threshold": {
            "precision": round(best.precision, 6),
            "recall": round(best.recall, 6),
            "f1": round(best.f1, 6),
        },
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "env_suggestion": {
            "PREDICTION_THRESHOLD_SUSPICIOUS": suspicious_threshold,
            "PREDICTION_THRESHOLD_MALICIOUS": malicious_threshold,
        },
    }

    print(json.dumps(summary, indent=2))
    if args.output_json:
        output_path = Path(args.output_json)
        output_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
