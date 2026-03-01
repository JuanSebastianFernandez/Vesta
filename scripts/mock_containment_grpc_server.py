from __future__ import annotations

import argparse
import json
import signal
import sys
from concurrent import futures
from datetime import datetime, timezone

import grpc


SERVICE_NAME = "vesta.containment.ContainmentOrchestrator"
METHOD_NAME = "TriggerContainment"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _trigger_containment(request_bytes: bytes, context: grpc.ServicerContext) -> bytes:
    try:
        payload = json.loads(request_bytes.decode("utf-8")) if request_bytes else {}
    except Exception:
        context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
        context.set_details("Invalid JSON payload")
        return b""

    trigger_id = str(payload.get("trigger_id", "")).strip() or "no-trigger-id"
    action = str(payload.get("action_recommended", "MANUAL_REVIEW")).strip() or "MANUAL_REVIEW"
    score = payload.get("max_alert_score", 0)
    source = payload.get("source_system", "unknown")

    print(
        f"[{_utc_now()}] gRPC trigger received "
        f"trigger_id={trigger_id} action={action} score={score} source={source}",
        flush=True,
    )

    response = {
        "accepted": True,
        "ticket_id": f"mock-{trigger_id}",
        "action": action,
        "message": "Containment request accepted by mock server.",
    }
    return json.dumps(response, ensure_ascii=True).encode("utf-8")


def run_server(host: str, port: int, max_workers: int) -> None:
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=max_workers))

    handler = grpc.unary_unary_rpc_method_handler(
        _trigger_containment,
        request_deserializer=lambda x: x,
        response_serializer=lambda x: x,
    )
    generic_handler = grpc.method_handlers_generic_handler(
        SERVICE_NAME,
        {METHOD_NAME: handler},
    )
    server.add_generic_rpc_handlers((generic_handler,))

    bind_addr = f"{host}:{port}"
    server.add_insecure_port(bind_addr)
    server.start()
    print(f"[{_utc_now()}] Mock containment gRPC server listening on {bind_addr}", flush=True)

    stop = False

    def _shutdown_handler(_sig, _frame):
        nonlocal stop
        if not stop:
            stop = True
            print(f"[{_utc_now()}] Shutting down mock containment gRPC server...", flush=True)
            server.stop(grace=2)
            sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)
    server.wait_for_termination()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mock gRPC server for containment trigger (Issue 17).")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=50051, help="Bind port (default: 50051)")
    parser.add_argument("--max-workers", type=int, default=10, help="Thread pool workers (default: 10)")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_server(host=args.host, port=args.port, max_workers=args.max_workers)
