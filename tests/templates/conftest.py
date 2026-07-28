import sys


# Module names to clear between test collections; resolves cache collisions between templates.
# Scoped to current templates (notes_app, tickets_app). A third template adding a NEW top-level
# module name would require extending this list, or evolving to a path-based sweep instead.
_STALE_MODULE_NAMES = ("db", "app_factory", "routes", "routes.notes", "routes.search", "routes.tickets")


def pytest_collectstart(collector):
    for name in _STALE_MODULE_NAMES:
        sys.modules.pop(name, None)
