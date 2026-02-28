import datetime
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
    DAST MVP service:
    - Run a short-lived Docker container with hardening flags.
    - Mount target repository read-only.
    - Collect minimal execution metadata/logs under timeout control.
    """

    def __init__(self) -> None:
        self.enabled = settings.DAST_ENABLED
        self.image = settings.DAST_DOCKER_IMAGE
        self.timeout_seconds = settings.DAST_TIMEOUT_SECONDS
        self.memory_limit = settings.DAST_MEMORY_LIMIT
        self.pids_limit = settings.DAST_PIDS_LIMIT
        self.cpu_quota = settings.DAST_CPU_QUOTA
        self.network_mode = settings.DAST_NETWORK_MODE
        self.tshark_enabled = settings.DAST_TSHARK_ENABLED
        self.tshark_path = settings.DAST_TSHARK_PATH
        self.tshark_interface = settings.DAST_TSHARK_INTERFACE
        self._docker_client: Any = None

    def _get_client(self):
        if self._docker_client is not None:
            return self._docker_client
        try:
            import docker  # lazy import to keep app boot resilient
        except Exception as e:
            raise RuntimeError(f"Docker SDK not available: {e}")

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
        cmd = [
            tshark_bin,
            "-i",
            self.tshark_interface,
            "-a",
            f"duration:{capture_duration}",
            "-w",
            pcap_path,
        ]
        try:
            proc: subprocess.Popen[str] = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            # Let tshark initialize and fail fast if interface/permissions are invalid.
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
        if proc is None:
            return
        if proc.poll() is not None:
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
        for f in fields:
            cmd.extend(["-e", f])
        if display_filter:
            cmd.extend(["-Y", display_filter])
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
            return [line.strip() for line in out.splitlines() if line.strip()]
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

        ip_lines = self._run_tshark_read(
            pcap_path,
            fields=["ip.dst", "ipv6.dst"],
            display_filter="ip.dst or ipv6.dst",
        )
        ports_lines = self._run_tshark_read(
            pcap_path,
            fields=["tcp.dstport", "udp.dstport"],
            display_filter="tcp.dstport or udp.dstport",
        )
        dns_lines = self._run_tshark_read(
            pcap_path,
            fields=["dns.qry.name"],
            display_filter="dns.qry.name",
        )
        syn_lines = self._run_tshark_read(
            pcap_path,
            fields=["tcp.flags.syn"],
            display_filter="tcp.flags.syn == 1 and tcp.flags.ack == 0",
        )

        def _top_counts(values: list[str], limit: int = 5) -> list[dict[str, Any]]:
            counts: dict[str, int] = {}
            for v in values:
                for token in [x.strip() for x in v.split("\t") if x.strip()]:
                    counts[token] = counts.get(token, 0) + 1
            ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]
            return [{"value": k, "count": v} for k, v in ranked]

        unique_ips = set()
        for line in ip_lines:
            for token in [x.strip() for x in line.split("\t") if x.strip()]:
                unique_ips.add(token)

        unique_ports = set()
        for line in ports_lines:
            for token in [x.strip() for x in line.split("\t") if x.strip()]:
                unique_ports.add(token)

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

    def analyze_repository(self, repo_path: Path) -> dict[str, Any]:
        started_at = datetime.datetime.utcnow()
        result: dict[str, Any] = {
            "status": "UNAVAILABLE",
            "engine": "docker",
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
            "network_mode": self.network_mode,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "message": "",
            "logs_excerpt": "",
            "metrics": {},
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

        container = None
        tshark_proc: subprocess.Popen[str] | None = None
        pcap_path: str | None = None
        capture_status = "DISABLED" if not self.tshark_enabled else "UNAVAILABLE"
        try:
            client = self._get_client()
            client.ping()

            command = (
                "set -eu; "
                "files=$(find /workspace -type f | wc -l); "
                "py_files=$(find /workspace -type f -name '*.py' | wc -l); "
                "js_files=$(find /workspace -type f -name '*.js' | wc -l); "
                "java_files=$(find /workspace -type f -name '*.java' | wc -l); "
                "echo files_total=$files; "
                "echo python_files=$py_files; "
                "echo javascript_files=$js_files; "
                "echo java_files=$java_files; "
                "echo dast_probe=ok"
            )

            tshark_proc, pcap_path, capture_status = self._start_tshark_capture()
            if capture_status == "FAILED_TO_START":
                logger.warning("[DAST] Tshark capture failed to start.")
            elif capture_status == "UNAVAILABLE":
                logger.warning("[DAST] Tshark not available; network capture skipped.")

            logger.info(f"[DAST] Launching restricted container for '{repo_path.name}'.")
            container = client.containers.run(
                image=self.image,
                command=["sh", "-lc", command],
                detach=True,
                network_mode=self.network_mode,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                mem_limit=self.memory_limit,
                pids_limit=self.pids_limit,
                cpu_period=100000,
                cpu_quota=self.cpu_quota,
                user="65534:65534",
                working_dir="/workspace",
                volumes={str(repo_path.resolve()): {"bind": "/workspace", "mode": "ro"}},
            )

            wait_data = container.wait(timeout=self.timeout_seconds)
            exit_code = int(wait_data.get("StatusCode", -1))
            logs_text = container.logs(stdout=True, stderr=True).decode("utf-8", errors="ignore")
            logs_excerpt = logs_text[:4000]

            metrics: dict[str, Any] = {}
            for line in logs_text.splitlines():
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()
                if value.isdigit():
                    metrics[key] = int(value)
                else:
                    metrics[key] = value

            result["container_exit_code"] = exit_code
            result["logs_excerpt"] = logs_excerpt
            result["metrics"] = metrics
            self._stop_tshark_capture(tshark_proc)
            self._wait_for_pcap(pcap_path)
            result["network_capture"] = self._parse_network_capture(pcap_path, capture_status)
            if exit_code == 0:
                result["status"] = "SUCCESS"
                result["message"] = "DAST probe executed successfully in restricted container."
            else:
                result["status"] = "FAILED"
                result["message"] = "DAST probe container exited with non-zero status."

        except Exception as e:
            result["status"] = "FAILED"
            result["message"] = f"DAST execution failed: {e}"
            logger.exception(f"[DAST] Execution failed for '{repo_path.name}': {e}")
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
