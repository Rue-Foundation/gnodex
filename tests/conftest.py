import pytest


def pytest_addoption(parser):
    parser.addoption("--num-ecdkg-nodes", action="store", default=10, type=int,
        help="number of ecdkg nodes %(default)s")


@pytest.fixture
def num_ecdkg_nodes(request):
    return request.config.getoption("--num-ecdkg-nodes")
