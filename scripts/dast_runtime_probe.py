from __future__ import annotations

import argparse
import json
import os
import py_compile
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


SUPPORTED_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".java": "java",
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".h": "c",
}

ENTRYPOINT_PATTERNS = {
    "python": [r"if __name__ == [\"']__main__[\"']:", r"FastAPI\(", r"Flask\("],
    "javascript": [r"express\(", r"http\.createServer", r"app\.listen", r"module\.exports"],
    "java": [r"public static void main", r"SpringApplication\.run"],
    "c": [r"int main\s*\("],
    "cpp": [r"int main\s*\("],
}

RISK_RULES = [
    ("subprocess_execution", re.compile(r"\b(subprocess|os\.system|exec\(|system\(|popen\()", re.IGNORECASE)),
    ("network_activity", re.compile(r"\b(requests\.|socket\.|urllib\.|axios|fetch\(|http\.|https\.)", re.IGNORECASE)),
    ("file_write", re.compile(r"\b(open\(.+['\"]w|writeFile|fopen\(.+['\"]w|ofstream)", re.IGNORECASE)),
    ("dangerous_eval", re.compile(r"\b(eval\(|exec\(|vm\.run|Runtime\.getRuntime\(\)\.exec)", re.IGNORECASE)),
    ("privilege_change", re.compile(r"\b(chmod\s+4777|setuid|sudo|runas|cap_set)", re.IGNORECASE)),
]


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _detect_languages(files: list[Path]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for path in files:
        language = SUPPORTED_EXTENSIONS.get(path.suffix.lower())
        if not language:
            continue
        counts[language] = counts.get(language, 0) + 1
    return counts


def _discover_entrypoints(files: list[Path]) -> list[dict[str, str]]:
    entrypoints: list[dict[str, str]] = []
    for path in files:
        language = SUPPORTED_EXTENSIONS.get(path.suffix.lower())
        if not language:
            continue
        text = _read_text(path)
        for pattern in ENTRYPOINT_PATTERNS.get(language, []):
            if re.search(pattern, text):
                entrypoints.append(
                    {
                        "language": language,
                        "file": str(path),
                        "reason": pattern,
                    }
                )
                break
    return entrypoints[:25]


def _compile_python(files: list[Path]) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    for path in files:
        if path.suffix.lower() != ".py":
            continue
        try:
            py_compile.compile(str(path), doraise=True)
            results.append({"file": str(path), "status": "compiled"})
        except Exception as exc:  # noqa: BLE001
            results.append({"file": str(path), "status": "error", "detail": str(exc)})
    return results[:100]


def _scan_risk_signals(files: list[Path]) -> tuple[list[str], list[dict[str, str]]]:
    signals: set[str] = set()
    evidence: list[dict[str, str]] = []
    for path in files:
        language = SUPPORTED_EXTENSIONS.get(path.suffix.lower())
        if not language:
            continue
        text = _read_text(path)
        if not text:
            continue
        for signal_name, pattern in RISK_RULES:
            match = pattern.search(text)
            if not match:
                continue
            signals.add(signal_name)
            evidence.append(
                {
                    "type": "risk_signal",
                    "signal": signal_name,
                    "language": language,
                    "file": str(path),
                    "detail": match.group(0)[:120],
                }
            )
    return sorted(signals), evidence[:80]


def _filesystem_observations(workspace: Path, files: list[Path]) -> dict[str, Any]:
    hidden_paths = []
    for path in workspace.rglob("*"):
        if path.name.startswith(".") and path.is_file():
            hidden_paths.append(str(path))
        if len(hidden_paths) >= 20:
            break
    return {
        "files_total": len(files),
        "hidden_files_detected": hidden_paths,
        "sensitive_paths": [
            str(path)
            for path in files
            if any(token in str(path).lower() for token in ["secret", "token", "config", ".env", "credential"])
        ][:20],
    }


def _http_request(base_url: str, request_def: dict[str, Any]) -> dict[str, Any]:
    method = str(request_def.get("method", "GET")).upper()
    name = str(request_def.get("name") or request_def.get("path") or request_def.get("url") or method)
    timeout = float(request_def.get("timeout_seconds", 3))
    path = str(request_def.get("url") or request_def.get("path") or "/")
    url = path if path.startswith("http://") or path.startswith("https://") else f"{base_url.rstrip('/')}{path}"

    payload = request_def.get("json")
    headers = {"Content-Type": "application/json"} if payload is not None else {}
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url=url, method=method, data=data, headers=headers)
    started_at = time.time()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - demo-local request
            body = response.read(600).decode("utf-8", errors="ignore")
            return {
                "name": name,
                "url": url,
                "status": int(response.status),
                "elapsed_ms": round((time.time() - started_at) * 1000, 2),
                "body_excerpt": body,
            }
    except urllib.error.HTTPError as exc:
        body = exc.read(600).decode("utf-8", errors="ignore")
        return {
            "name": name,
            "url": url,
            "status": int(exc.code),
            "elapsed_ms": round((time.time() - started_at) * 1000, 2),
            "body_excerpt": body,
            "error": str(exc),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "name": name,
            "url": url,
            "status": None,
            "elapsed_ms": round((time.time() - started_at) * 1000, 2),
            "error": str(exc),
        }


def _run_profiled_probe(workspace: Path, profile: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]], list[dict[str, Any]]]:
    command = profile.get("command")
    if not command:
        return ["profile_missing_command"], [], []

    env = os.environ.copy()
    for key, value in (profile.get("env") or {}).items():
        env[str(key)] = str(value)

    command_record = command if isinstance(command, list) else [str(command)]
    base_url = str(profile.get("base_url") or f"http://127.0.0.1:{int(profile.get('port', 8000))}")
    startup_delay = float(profile.get("startup_delay_seconds", 2))
    startup_timeout = float(profile.get("startup_timeout_seconds", 10))
    requests_def = []
    healthcheck = profile.get("healthcheck")
    if isinstance(healthcheck, dict):
        requests_def.append({"name": "healthcheck", **healthcheck})
    requests_def.extend(list(profile.get("http_requests") or []))
    requests_def.extend(list(profile.get("attacks") or []))

    proc = subprocess.Popen(
        command,
        cwd=str(workspace),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        shell=isinstance(command, str),
    )
    stdout_lines: list[str] = []
    http_results: list[dict[str, Any]] = []
    process_observations: list[dict[str, Any]] = []
    runtime_commands_attempted = [json.dumps(command_record)]

    try:
        start_wait = time.time()
        while time.time() - start_wait < startup_timeout:
            if proc.poll() is not None:
                break
            if time.time() - start_wait >= startup_delay:
                break
            time.sleep(0.2)

        for request_def in requests_def:
            http_results.append(_http_request(base_url, request_def))
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        if proc.stdout is not None:
            try:
                stdout_excerpt = proc.stdout.read(2000)
            except Exception:
                stdout_excerpt = ""
            if stdout_excerpt:
                stdout_lines.append(stdout_excerpt)
        process_observations.append(
            {
                "command": command_record,
                "pid": proc.pid,
                "running": proc.poll() is None,
                "returncode": proc.returncode,
                "stdout_excerpt": "\n".join(stdout_lines)[:1500],
            }
        )
    return runtime_commands_attempted, process_observations, http_results


def main() -> int:
    parser = argparse.ArgumentParser(description="Restricted DAST runtime probe for VESTA.")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--profile", default="")
    args = parser.parse_args()

    workspace = Path(args.workspace).resolve()
    all_files = [path for path in workspace.rglob("*") if path.is_file()]
    supported_files = [path for path in all_files if path.suffix.lower() in SUPPORTED_EXTENSIONS]
    detected_languages = _detect_languages(supported_files)
    entrypoints = _discover_entrypoints(supported_files)
    python_compile_results = _compile_python(supported_files)
    risk_signals, evidence = _scan_risk_signals(supported_files)

    probe_mode = "generic_probe"
    runtime_commands_attempted = [
        "discover_supported_files",
        "detect_entrypoints",
        "compile_python",
        "scan_risk_signals",
    ]
    process_observations: list[dict[str, Any]] = []
    http_observations: list[dict[str, Any]] = []

    if args.profile:
        profile_path = Path(args.profile)
        if profile_path.exists():
            probe_mode = "profiled_probe"
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            profile_commands, profile_process, profile_http = _run_profiled_probe(workspace, profile)
            runtime_commands_attempted.extend(profile_commands)
            process_observations.extend(profile_process)
            http_observations.extend(profile_http)

    result = {
        "probe_mode": probe_mode,
        "detected_languages": detected_languages,
        "entrypoints_detected": entrypoints,
        "runtime_commands_attempted": runtime_commands_attempted,
        "process_observations": process_observations,
        "filesystem_observations": _filesystem_observations(workspace, supported_files),
        "http_observations": http_observations,
        "evidence": evidence,
        "risk_signals": risk_signals,
        "metrics": {
            "supported_files": len(supported_files),
            "python_compile_errors": len([item for item in python_compile_results if item["status"] == "error"]),
            "python_compile_success": len([item for item in python_compile_results if item["status"] == "compiled"]),
            "http_requests_total": len(http_observations),
            "http_requests_ok": len(
                [item for item in http_observations if isinstance(item.get("status"), int) and item["status"] < 400]
            ),
        },
        "compile_observations": python_compile_results,
    }
    print(json.dumps(result, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
