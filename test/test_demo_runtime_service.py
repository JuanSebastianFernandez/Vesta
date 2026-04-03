import unittest

from app.services.demo_runtime_service import DemoRuntimeService


class _FakeNetwork:
    def __init__(self, name, connect_error=None):
        self.name = name
        self.connected = []
        self.connect_error = connect_error

    def connect(self, container):
        if self.connect_error is not None:
            raise self.connect_error
        self.connected.append(container)


class _FakeNetworks:
    def __init__(self):
        self.created = []
        self._items = {}
        self.next_connect_error = None

    def list(self, names):
        return [self._items[name] for name in names if name in self._items]

    def create(self, name, driver="bridge"):
        _ = driver
        network = _FakeNetwork(name, connect_error=self.next_connect_error)
        self.next_connect_error = None
        self._items[name] = network
        self.created.append(name)
        return network


class _FakeContainer:
    def __init__(self, name="vesta-demo-honeypot", status="running", networks=None):
        self.name = name
        self.status = status
        self.short_id = "abc123"
        self.attrs = {
            "Config": {"Image": "demo-honeypot:latest"},
            "NetworkSettings": {"Networks": {network_name: {} for network_name in (networks or [])}, "Ports": {}},
        }
        self.start_called = False

    def reload(self):
        return None

    def start(self):
        self.status = "running"
        self.start_called = True


class _FakeClient:
    def __init__(self, container=None):
        self.networks = _FakeNetworks()
        self._container = container or _FakeContainer()
        self.containers = self

    def get(self, _name):
        return self._container


class TestDemoRuntimeService(unittest.TestCase):
    def test_ensure_network_creates_missing_network(self):
        service = DemoRuntimeService(session=None)
        service._docker_client = _FakeClient()

        network = service._ensure_network("vesta_demo_quarantine")

        self.assertEqual(network.name, "vesta_demo_quarantine")
        self.assertEqual(service._docker_client.networks.created, ["vesta_demo_quarantine"])

    def test_resolve_network_name_maps_demo_aliases(self):
        service = DemoRuntimeService(session=None)

        self.assertEqual(service._resolve_network_name("demo_deception", service.deception_network), service.deception_network)
        self.assertEqual(service._resolve_network_name("demo_quarantine", service.deception_network), service.quarantine_network)
        self.assertEqual(service._resolve_network_name(None, service.deception_network), service.deception_network)

    def test_deploy_honeypot_ignores_already_connected_error(self):
        container = _FakeContainer(networks=[])
        service = DemoRuntimeService(session=None)
        service._docker_client = _FakeClient(container=container)
        service._docker_client.networks.next_connect_error = RuntimeError(
            '403 Client Error: Forbidden ("endpoint with name vesta-demo-honeypot already exists in network vesta_demo_deception")'
        )

        result = service.deploy_honeypot(
            honeypot_profile="cowrie-lite",
            ttl_minutes=15,
            network_zone="demo_deception",
        )

        self.assertEqual(result["network_zone"], service.deception_network)
        self.assertEqual(result["status"], "RUNNING")


if __name__ == "__main__":
    unittest.main()
