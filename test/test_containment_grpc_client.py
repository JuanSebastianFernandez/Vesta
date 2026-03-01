import sys
import types
import unittest

from app.services.containment_grpc_client import ContainmentGrpcClient


class _FakeChannel:
    def __init__(self, outcomes):
        self.outcomes = outcomes

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def unary_unary(self, _method_path, request_serializer=None, response_deserializer=None):
        def _invoke(request_bytes, timeout=None):
            _ = timeout
            raw = request_serializer(request_bytes) if request_serializer else request_bytes
            if isinstance(raw, Exception):
                raise raw
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return response_deserializer(outcome) if response_deserializer else outcome

        return _invoke


class _FakeGrpcModule:
    def __init__(self, outcomes):
        self._outcomes = outcomes

    def insecure_channel(self, _target):
        return _FakeChannel(self._outcomes)


class TestContainmentGrpcClient(unittest.TestCase):
    def test_disabled_client_skips_trigger(self):
        client = ContainmentGrpcClient(
            enabled=False,
            target="127.0.0.1:50051",
            timeout_seconds=1.0,
            retry_max=2,
            retry_backoff_seconds=0.0,
        )
        result = client.trigger_containment({"hello": "world"})
        self.assertEqual(result["status"], "SKIPPED")
        self.assertFalse(result["attempted"])

    def test_retries_and_succeeds(self):
        fake_grpc = _FakeGrpcModule(
            outcomes=[
                RuntimeError("temporary failure"),
                b'{"accepted": true, "ticket_id": "abc-123"}',
            ]
        )
        original = sys.modules.get("grpc")
        sys.modules["grpc"] = fake_grpc  # type: ignore
        try:
            client = ContainmentGrpcClient(
                enabled=True,
                target="127.0.0.1:50051",
                timeout_seconds=1.0,
                retry_max=2,
                retry_backoff_seconds=0.0,
            )
            result = client.trigger_containment({"a": 1})
            self.assertEqual(result["status"], "SENT")
            self.assertTrue(result["attempted"])
            self.assertEqual(result["retries_used"], 1)
            self.assertEqual(result["response"]["ticket_id"], "abc-123")
        finally:
            if original is not None:
                sys.modules["grpc"] = original
            else:
                sys.modules.pop("grpc", None)

    def test_fails_after_all_retries(self):
        fake_grpc = _FakeGrpcModule(
            outcomes=[
                RuntimeError("fail-1"),
                RuntimeError("fail-2"),
                RuntimeError("fail-3"),
            ]
        )
        original = sys.modules.get("grpc")
        sys.modules["grpc"] = fake_grpc  # type: ignore
        try:
            client = ContainmentGrpcClient(
                enabled=True,
                target="127.0.0.1:50051",
                timeout_seconds=1.0,
                retry_max=2,
                retry_backoff_seconds=0.0,
            )
            result = client.trigger_containment({"a": 1})
            self.assertEqual(result["status"], "FAILED")
            self.assertTrue(result["attempted"])
            self.assertEqual(result["retries_used"], 2)
        finally:
            if original is not None:
                sys.modules["grpc"] = original
            else:
                sys.modules.pop("grpc", None)


if __name__ == "__main__":
    unittest.main()
