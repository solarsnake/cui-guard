import pytest
from harness import Dirs, FakeUpstream, Gateway, launch_gateway


@pytest.fixture(scope="session")
def upstream():
    up = FakeUpstream()
    up.start()
    yield up
    up.stop()


@pytest.fixture(autouse=True)
def _reset_upstream(upstream):
    upstream.reset()
    yield
    upstream.reset()


@pytest.fixture(scope="session")
def gateways(upstream, tmp_path_factory):
    """One real gateway subprocess per trust level, started on first use."""
    started: dict[str, Gateway] = {}

    def get(trust: str) -> Gateway:
        if trust not in started:
            dirs = Dirs(tmp_path_factory.mktemp(f"gw-{trust}"))
            started[trust] = launch_gateway(dirs, upstream.url, trust)
        return started[trust]

    yield get
    for gw in started.values():
        gw.close()
