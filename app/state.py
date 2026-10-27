"""In-memory lab state.

The project intentionally keeps data ephemeral so the vulnerable environment can be
reset quickly. Nothing here is intended for production persistence.
"""

from copy import deepcopy

_DEFAULT_USERS = {
    "member": {"password": "member-demo", "role": "member", "email": "member@example.test", "points": 120},
    "analyst": {"password": "analyst-demo", "role": "member", "email": "analyst@example.test", "points": 275},
    "admin": {"password": "admin-demo", "role": "admin", "email": "admin@example.test", "points": 400},
}

USERS = deepcopy(_DEFAULT_USERS)
REVIEWS = []


def reset_state() -> None:
    """Restore deterministic demo state for tests and demos."""
    USERS.clear()
    USERS.update(deepcopy(_DEFAULT_USERS))
    REVIEWS.clear()
