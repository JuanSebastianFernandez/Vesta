from __future__ import annotations

import datetime
import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.utilities.logger import logger


class DynamicAnalysisService:
    """
    DAST service for demo and generic repository inspection.
    Runs a restricted Docker container and executes a Python probe that:
    - detects supported-language entrypoints,
    - compiles Python safely,
    - extracts risk signals and evidence,
    - optionally runs a profiled runtime flow for the smart-grid demo repo.
    """

    def __init__(self) -> None:
        self.enabled = settings.DAST_ENABLED
        self.image = settings.DAST_DOCKER_IMAGE
        self.timeout_seconds = settings.DAST_TIMEOUT_SECONDS
        self.memory_limit = settings.DAST_MEMORY_LIMIT
        self.pids_limit = settings.DAST_PIDS_LIMIT
        self.cpu_quota = settings.DAST_CPU_QUOTA
        self.network_mode = settings.DAST_NETWORK_MODE
        self.profile_relative_path = settings.DAST_PROFILE_RELATIVE_PATH
        self.tshark_enabled = settings.DAST_TSHARK_ENABLED
        self.tshark_path = settings.DAST_TSHARK_PATH
        self.tshark_interface = settings.DAST_TSHARK_INTERFACE
        self.probe_script_path = settings.BASE_DIR / "scripts" / "dast_runtime_probe.py"
        self._docker_client: Any = None

    def _get_client(self):
        if self._docker_client is not None:
            return self._docker_client
        try:
            import docker  # lazy import to keep app boot resilient
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"Docker SDK not available: {exc}") from exc

        self._docker_client = docker.from_env()
        return self._docker_client

    def _resolve_tshark_path(self) -> str | None:
        if os.path.isabs(self.tshark_path) and os.path.exists(self.tshark_path):
            return self.tshark_path
        return shutil.which(self.tshark_path)

    def _start_tshark_capture(self) -> tuple[subprocess.Popen[str] | None, str | None, str]:
        if not self.tshark_enabled:
            return None, None, "DISABLED"

        tshark_bin = self._resolve_tshark_path()
        if not tshark_bin:
            return None, None, "UNAVAILABLE"

        pcap_path = os.path.join(tempfile.gettempdir(), f"vesta_dast_{uuid.uuid4().hex}.pcapng")
        capture_duration = max(self.timeout_seconds + 5, 10)
        cmd = [tshark_bin, "-i", self.tshark_interface, "-a", f"duration:{capture_duration}", "-w", pcap_path]
        try:
            proc: subprocess.Popen[str] = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            time.sleep(0.5)
            if proc.poll() is not None:
                if os.path.exists(pcap_path):
                    try:
                        os.remove(pcap_path)
                    except Exception:
                        pass
                return None, None, "FAILED_TO_START"
            return proc, pcap_path, "STARTED"
        except Exception:
            try:
                if os.path.exists(pcap_path):
                    os.remove(pcap_path)
            except Exception:
                pass
            return None, None, "FAILED_TO_START"

    def _stop_tshark_capture(self, proc: subprocess.Popen[str] | None) -> None:
        if proc is None or proc.poll() is not None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def _run_tshark_read(self, pcap_path: str, fields: list[str], display_filter: str = "") -> list[str]:
        tshark_bin = self._resolve_tshark_path()
        if not tshark_bin:
            return []
        cmd: list[str] = [tshark_bin, "-r", pcap_path, "-T", "fields"]
        for field in fields:
            cmd.extend(["-e", field])
        if display_filter:
            cmd.extend(["-Y", display_filter])
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
            return [line.strip() for line in output.splitlines() if line.strip()]
        except Exception:
            return []

    def _parse_network_capture(self, pcap_path: str | None, capture_status: str) -> dict[str, Any]:
        result = {
            "status": capture_status,
            "pcap_path": pcap_path or "",
            "metrics": {
                "packets_total": 0,
                "unique_destinations": 0,
                "top_destinations": [],
                "unique_destination_ports": 0,
                "top_destination_ports": [],
                "dns_queries_count": 0,
                "top_dns_queries": [],
                "tcp_syn_attempts": 0,
            },
        }
        if not pcap_path or capture_status not in {"STARTED", "PARSED"}:
            return result
        if not os.path.exists(pcap_path):
            result["status"] = "NO_CAPTURE_OUTPUT"
            return result

        ip_lines = self._run_tshark_read(pcap_path, fields=["ip.dst", "ipv6.dst"], display_filter="ip.dst or ipv6.dst")
        ports_lines = self._run_tshark_read(
            pcap_path,
            fields=["tcp.dstport", "udp.dstport"],
            display_filter="tcp.dstport or udp.dstport",
        )
        dns_lines = self._run_tshark_read(pcap_path, fields=["dns.qry.name"], display_filter="dns.qry.name")
        syn_lines = self._run_tshark_read(
            pcap_path,
            fields=["tcp.flags.syn"],
            display_filter="tcp.flags.syn == 1 and tcp.flags.ack == 0",
        )

        def _top_counts(values: list[str], limit: int = 5) -> list[dict[str, Any]]:
            counts: dict[str, int] = {}
            for value in values:
                for token in [item.strip() for item in value.split("\t") if item.strip()]:
                    counts[token] = counts.get(token, 0) + 1
            return [{"value": key, "count": count} for key, count in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]]

        unique_ips = {
            token
            for line in ip_lines
            for token in [item.strip() for item in line.split("\t") if item.strip()]
        }
        unique_ports = {
            token
            for line in ports_lines
            for token in [item.strip() for item in line.split("\t") if item.strip()]
        }
        result["metrics"] = {
            "packets_total": len(ip_lines),
            "unique_destinations": len(unique_ips),
            "top_destinations": _top_counts(ip_lines),
            "unique_destination_ports": len(unique_ports),
            "top_destination_ports": _top_counts(ports_lines),
            "dns_queries_count": len(dns_lines),
            "top_dns_queries": _top_counts(dns_lines),
            "tcp_syn_attempts": len(syn_lines),
        }
        result["status"] = "PARSED"
        return result

    def _wait_for_pcap(self, pcap_path: str | None, timeout_seconds: float = 2.0) -> None:
        if not pcap_path:
            return
        end_at = time.monotonic() + timeout_seconds
        while time.monotonic() < end_at:
            if os.path.exists(pcap_path):
                return
            time.sleep(0.2)

    def _profile_path(self, repo_path: Path) -> Path:
        return repo_path / self.profile_relative_path

    def _probe_mode(self, repo_path: Path) -> str:
        return "profiled_probe" if self._profile_path(repo_path).exists() else "generic_probe"

    def _runtime_network_mode(self, repo_path: Path) -> str:
        profile_path = self._profile_path(repo_path)
        if not profile_path.exists():
            return self.network_mode
        try:
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
        except Exception:
            return self.network_mode
        return str(profile.get("network_mode") or "bridge")

    def _build_probe_command(self, repo_path: Path) -> list[str]:
        profile_path = self._profile_path(repo_path)
        command = ["python", "/probe/dast_runtime_probe.py", "--workspace", "/workspace"]
        if profile_path.exists():
            command.extend(["--profile", f"/workspace/{self.profile_relative_path.replace(os.sep, '/')}"])
        return command

    def _extract_probe_payload(self, logs_text: str) -> dict[str, Any]:
        lines = [line.strip() for line in logs_text.splitlines() if line.strip()]
        if not lines:
            return {}
        for line in reversed(lines):
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                continue
        return {}

    def _wait_for_container_exit(self, container: Any) -> tuple[int, bool]:
        """
        Poll container state instead of Docker wait streaming.
        On Windows named pipes, wait() can raise read timeouts even when the container is still running.
        Returns (exit_code, timed_out).
        """
        deadline = time.monotonic() + self.timeout_seconds
        while time.monotonic() < deadline:
            container.reload()
            state = container.attrs.get("State", {})
            status = str(state.get("Status", "")).lower()
            if status in {"exited", "dead"}:
                try:
                    return int(state.get("ExitCode", -1)), False
                except (TypeError, ValueError):
                    return -1, False
            time.sleep(0.5)
        return -1, True

    def analyze_repository(self, repo_path: Path) -> dict[str, Any]:
        started_at = datetime.datetime.utcnow()
        probe_mode = self._probe_mode(repo_path)
        runtime_network_mode = self._runtime_network_mode(repo_path)
        result: dict[str, Any] = {
            "status": "UNAVAILABLE",
            "engine": "docker",
            "probe_mode": probe_mode,
            "started_at": started_at.isoformat() + "Z",
            "finished_at": None,
            "duration_seconds": None,
            "repo_path": str(repo_path),
            "container_image": self.image,
            "container_exit_code": None,
            "timeout_seconds": self.timeout_seconds,
            "memory_limit": self.memory_limit,
            "pids_limit": self.pids_limit,
            "cpu_quota": self.cpu_quota,
            "network_mode": runtime_network_mode,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "message": "",
            "logs_excerpt": "",
            "metrics": {},
            "detected_languages": {},
            "entrypoints_detected": [],
            "runtime_commands_attempted": [],
            "process_observations": [],
            "filesystem_observations": {},
            "http_observations": [],
            "evidence": [],
            "risk_signals": [],
            "compile_observations": [],
            "network_capture": {
                "status": "DISABLED" if not self.tshark_enabled else "UNAVAILABLE",
                "pcap_path": "",
                "metrics": {},
            },
        }

        if not self.enabled:
            result["status"] = "DISABLED"
            result["message"] = "DAST is disabled by configuration."
            finished_at = datetime.datetime.utcnow()
            result["finished_at"] = finished_at.isoformat() + "Z"
            result["duration_seconds"] = round((finished_at - started_at).total_seconds(), 3)
            return result

        if not repo_path.exists() or not repo_path.is_dir():
            result["status"] = "FAILED"
            result["message"] = f"Invalid repository path: {repo_path}"
            finished_at = datetime.datetime.utcnow()
            result["finished_at"] = finished_at.isoformat() + "Z"
            result["duration_seconds"] = round((finished_at - started_at).total_seconds(), 3)
            return result

        if not self.probe_script_path.exists():
            result["status"] = "FAILED"
            result["message"] = f"Probe script not found: {self.probe_script_path}"
            finished_at = datetime.datetime.utcnow()
            result["finished_at"] = finished_at.isoformat() + "Z"
            result["duration_seconds"] = round((finished_at - started_at).total_seconds(), 3)
            return result

        container = None
        tshark_proc: subprocess.Popen[str] | None = None
        pcap_path: str | None = None
        capture_status = "DISABLED" if not self.tshark_enabled else "UNAVAILABLE"
        try:
            client = self._get_client()
            client.ping()

            tshark_proc, pcap_path, capture_status = self._start_tshark_capture()
            if capture_status == "FAILED_TO_START":
                logger.warning("[DAST] Tshark capture failed to start.")
            elif capture_status == "UNAVAILABLE":
                logger.warning("[DAST] Tshark not available; network capture skipped.")

            command = self._build_probe_command(repo_path)
            logger.info("[DAST] Launching %s for '%s'.", probe_mode, repo_path.name)
            container = client.containers.run(
                image=self.image,
                command=command,
                detach=True,
                network_mode=runtime_network_mode,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                mem_limit=self.memory_limit,
                pids_limit=self.pids_limit,
                cpu_period=100000,
                cpu_quota=self.cpu_quota,
                user="65534:65534",
                working_dir="/workspace",
                volumes={
                    str(repo_path.resolve()): {"bind": "/workspace", "mode": "ro"},
                    str(self.probe_script_path.resolve()): {"bind": "/probe/dast_runtime_probe.py", "mode": "ro"},
                },
            )

            exit_code, timed_out = self._wait_for_container_exit(container)
            if timed_out:
                result["status"] = "TIMEOUT"
                result["message"] = (
                    f"{probe_mode} exceeded the DAST timeout of {self.timeout_seconds} seconds."
                )
                logger.warning("[DAST] Probe timed out for '%s'.", repo_path.name)
                try:
                    container.kill()
                except Exception:
                    pass

            logs_text = container.logs(stdout=True, stderr=True).decode("utf-8", errors="ignore")
            probe_payload = self._extract_probe_payload(logs_text)

            result["container_exit_code"] = exit_code
            result["logs_excerpt"] = logs_text[:4000]
            result["metrics"] = dict(probe_payload.get("metrics") or {})
            result["detected_languages"] = dict(probe_payload.get("detected_languages") or {})
            result["entrypoints_detected"] = list(probe_payload.get("entrypoints_detected") or [])
            result["runtime_commands_attempted"] = list(probe_payload.get("runtime_commands_attempted") or [])
            result["process_observations"] = list(probe_payload.get("process_observations") or [])
            result["filesystem_observations"] = dict(probe_payload.get("filesystem_observations") or {})
            result["http_observations"] = list(probe_payload.get("http_observations") or [])
            result["evidence"] = list(probe_payload.get("evidence") or [])
            result["risk_signals"] = list(probe_payload.get("risk_signals") or [])
            result["compile_observations"] = list(probe_payload.get("compile_observations") or [])

            self._stop_tshark_capture(tshark_proc)
            self._wait_for_pcap(pcap_path)
            result["network_capture"] = self._parse_network_capture(pcap_path, capture_status)

            if timed_out:
                pass
            elif exit_code == 0:
                result["status"] = "SUCCESS"
                result["message"] = f"{probe_mode} executed successfully in restricted container."
            else:
                result["status"] = "FAILED"
                result["message"] = f"{probe_mode} container exited with non-zero status."
        except Exception as exc:  # noqa: BLE001
            result["status"] = "FAILED"
            result["message"] = f"DAST execution failed: {exc}"
            logger.exception(f"[DAST] Execution failed for '{repo_path.name}': {exc}")
            if container is not None:
                try:
                    container.kill()
                except Exception:
                    pass
            self._stop_tshark_capture(tshark_proc)
            result["network_capture"] = self._parse_network_capture(pcap_path, capture_status)
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
            if pcap_path and os.path.exists(pcap_path):
                try:
                    os.remove(pcap_path)
                except Exception:
                    pass
            if isinstance(result.get("network_capture"), dict):
                result["network_capture"]["pcap_path"] = ""
            finished_at = datetime.datetime.utcnow()
            result["finished_at"] = finished_at.isoformat() + "Z"
            result["duration_seconds"] = round((finished_at - started_at).total_seconds(), 3)

        return result
