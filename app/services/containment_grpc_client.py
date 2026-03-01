from __future__ import annotations

import json
import time
from typing import Any

from app.utilities.logger import logger


class ContainmentGrpcClient:
    """
    gRPC client stub for Issue 17.
    Uses a generic unary call so the backend can integrate before
    generated protobuf classes are wired in the containment service.
    """

    METHOD_PATH = "/vesta.containment.ContainmentOrchestrator/TriggerContainment"

    def __init__(
        self,
        *,
        enabled: bool,
        target: str,
        timeout_seconds: float,
        retry_max: int,
        retry_backoff_seconds: float,
    ):
        self.enabled = enabled
        self.target = target
        self.timeout_seconds = float(timeout_seconds)
        self.retry_max = max(int(retry_max), 0)
        self.retry_backoff_seconds = max(float(retry_backoff_seconds), 0.0)

    def trigger_containment(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.enabled:
            return {
                "attempted": False,
                "status": "SKIPPED",
                "endpoint": self.target,
                "retries_used": 0,
                "message": "gRPC trigger disabled by configuration.",
                "response": None,
            }

        try:
            import grpc  # type: ignore
        except Exception as exc:  # pragma: no cover - depends on env
            return {
                "attempted": False,
                "status": "FAILED",
                "endpoint": self.target,
                "retries_used": 0,
                "message": f"grpc dependency unavailable: {exc}",
                "response": None,
            }

        request_bytes = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        attempt = 0
        last_error = ""

        while attempt <= self.retry_max:
            try:
                with grpc.insecure_channel(self.target) as channel:
                    unary_call = channel.unary_unary(
                        self.METHOD_PATH,
                        request_serializer=lambda x: x,
                        response_deserializer=lambda x: x,
                    )
                    response_bytes = unary_call(request_bytes, timeout=self.timeout_seconds)
                    parsed = self._parse_response_bytes(response_bytes)
                    return {
                        "attempted": True,
                        "status": "SENT",
                        "endpoint": self.target,
                        "retries_used": attempt,
                        "message": "Containment trigger sent successfully.",
                        "response": parsed,
                    }
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)
                logger.warning(
                    f"[Defense][gRPC] Trigger attempt={attempt + 1}/{self.retry_max + 1} failed: {last_error}"
                )
                if attempt >= self.retry_max:
                    break
                if self.retry_backoff_seconds > 0:
                    time.sleep(self.retry_backoff_seconds * (attempt + 1))
                attempt += 1
                continue

        return {
            "attempted": True,
            "status": "FAILED",
            "endpoint": self.target,
            "retries_used": self.retry_max,
            "message": f"Containment trigger failed after retries: {last_error}",
            "response": None,
        }

    @staticmethod
    def _parse_response_bytes(response_bytes: bytes | None) -> dict[str, Any]:
        if not response_bytes:
            return {}
        try:
            parsed = json.loads(response_bytes.decode("utf-8"))
            if isinstance(parsed, dict):
                return parsed
            return {"raw": parsed}
        except Exception:
            return {"raw": response_bytes.decode("utf-8", errors="ignore")}
