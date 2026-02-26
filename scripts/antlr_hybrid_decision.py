import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Ensure project root is importable when script is executed directly.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.services.prediction_refiner import refine_prediction_with_antlr


def process_entry(
    entry: dict[str, Any],
) -> dict[str, Any]:
    model_binary = int(entry.get("model_prediction_binary", 0))
    model_probability = float(entry.get("model_prediction_probability", 0.0))
    decision = refine_prediction_with_antlr(
        model_binary=model_binary,
        raw_report=entry,
    )
    return {
        "file_path": entry.get("file_path", ""),
        "model_prediction_binary": model_binary,
        "model_prediction_probability": model_probability,
        **decision,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Apply ANTLR + ML hybrid decision policy over analysis reports."
    )
    parser.add_argument("--input-json", required=True, help="Path to JSON file with one report object or a list of report objects.")
    parser.add_argument("--output-json", default="", help="Optional output file path.")
    args = parser.parse_args()

    input_path = Path(args.input_json)
    raw_data = json.loads(input_path.read_text(encoding="utf-8"))
    reports = raw_data if isinstance(raw_data, list) else [raw_data]

    results = [
        process_entry(
            entry=entry,
        )
        for entry in reports
        if isinstance(entry, dict)
    ]

    output = {"count": len(results), "results": results}
    output_text = json.dumps(output, indent=2, ensure_ascii=False)
    print(output_text)

    if args.output_json:
        Path(args.output_json).write_text(output_text, encoding="utf-8")


if __name__ == "__main__":
    main()
