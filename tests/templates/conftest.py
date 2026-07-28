import sys


_STALE_MODULE_NAMES = ("db", "app_factory", "routes", "routes.notes", "routes.search", "routes.tickets")


def pytest_collectstart(collector):
    for name in _STALE_MODULE_NAMES:
        sys.modules.pop(name, None)
