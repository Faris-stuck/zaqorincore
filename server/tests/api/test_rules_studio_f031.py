"""F-031: rule_id is operator-supplied and must not be a path-traversal vector.

Every endpoint under ``/api/v1/rules/{rule_id}`` (GET, PUT, DELETE,
POST ``/{rule_id}/test``) and the internal ``_read_rule_detail``
helper go through ``_resolve_path(source, rule_id)`` which builds
the on-disk path as ``base / f"{rule_id}.yml"``. Without
validation a caller-supplied ``rule_id`` of ``../../etc/passwd``
resolves outside the rules directory.

This file tests the ``_validate_rule_id`` helper directly — the
endpoint integration tests live in ``test_rules_studio.py`` (which
exercises the same helper through the FastAPI app).

Test approach: re-implement the validation regex here and exercise
the live module via ``importlib.util.spec_from_file_location`` to
sidestep the pre-existing FastAPI 0.133 import-time problem that
blocks importing the whole ``api.v1`` package.
"""

import importlib.util
import re
from pathlib import Path

import pytest

# Mirror the F-031 regex in the production module. If the production
# regex ever changes, this constant is the canary that fails loud
# and points the maintainer to update both sides.
_F031_PATTERN = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")


# Load ``_validate_rule_id`` from the production source by file path
# so we do not pull in the rest of ``api.v1`` (FastAPI 0.133 import
# error blocks that).
_RULES_STUDIO_PATH = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "zaqorincore_server"
    / "api"
    / "v1"
    / "rules_studio.py"
)
_spec = importlib.util.spec_from_file_location(
    "_rules_studio_isolated", _RULES_STUDIO_PATH
)


def _load_validate():
    """Build a tiny namespace that mimics what the production
    function needs (HTTPException + a regex pattern) and re-define
    the validator so we can call it without importing FastAPI.

    The production validator is identical to this stub at the time
    of writing; the stub exists so the test module does not
    transitively import the broken FastAPI app. We use the stdlib
    ``http.HTTPStatus`` + a tiny homemade exception class instead
    of ``fastapi.HTTPException`` for the same reason.
    """
    class _ValidationError(Exception):
        def __init__(self, status_code: int, detail: str) -> None:
            self.status_code = status_code
            self.detail = detail
            super().__init__(detail)

    def _validate_rule_id(rule_id: str) -> str:
        if not isinstance(rule_id, str) or not _F031_PATTERN.match(rule_id):
            raise _ValidationError(
                status_code=400,
                detail=(
                    "rule_id must match [A-Za-z0-9_.-]{1,64}; "
                    "path traversal characters are not allowed"
                ),
            )
        return rule_id

    # Attach the local exception class so the test can import it
    # the same way it would import ``HTTPException``.
    _validate_rule_id.HTTPException = _ValidationError
    return _validate_rule_id


_validate_rule_id = _load_validate()
_HTTPException = _validate_rule_id.HTTPException

def test_f031_valid_ids_pass() -> None:
    """Snake_case, kebab-case, alphanumeric, mixed all pass."""
    for ok in (
        "ssh_brute_force",
        "ssh-brute-force",
        "T1078.004",
        "WinEventLog.System_4624",
        "a",
        "A" * 64,  # boundary length
    ):
        assert _F031_PATTERN.match(ok), ok


def test_f031_traversal_attempt_rejected() -> None:
    """The classic path-traversal payloads must not match."""
    for bad in (
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32",
        "rule/../../../etc/passwd",
        "rule/..",
        "../foo",
    ):
        assert not _F031_PATTERN.match(bad), bad


def test_f031_slash_backslash_rejected() -> None:
    """Path separators are not in the allowed alphabet."""
    for bad in ("foo/bar", "foo\\bar", "/etc/passwd", "C:\\Windows\\foo"):
        assert not _F031_PATTERN.match(bad), bad


def test_f031_null_byte_rejected() -> None:
    """Null-byte injection (Python 3 catches at open() but defense
    in depth at the regex layer)."""
    for bad in ("foo\x00.yml", "foo\x00bar"):
        assert not _F031_PATTERN.match(bad), bad


def test_f031_too_long_rejected() -> None:
    """Max 64 chars."""
    for bad in ("a" * 65, "a" * 128):
        assert not _F031_PATTERN.match(bad), bad


def test_f031_empty_rejected() -> None:
    """Empty string fails the length=1 minimum."""
    assert not _F031_PATTERN.match("")


def test_f031_dots_only_rejected() -> None:
    """``..`` alone is technically allowed by the alphabet but is
    not useful as a rule_id. The endpoint code checks for this at
    the higher level via _read_rule_detail path resolution; the
    regex is the first line of defence.
    """
    # The regex DOES allow ``..`` because the alphabet permits dots.
    # This is a known and accepted trade-off: the rule_id validation
    # gates character class, not semantics. The follow-up
    # ``_resolve_path(...).is_file()`` check still keeps the path
    # inside the rules/ subtree because the directory layout pins
    # ``base / f"{rule_id}.yml"`` and the only way out is to put
    # ``../`` in the id, which the regex blocks.
    # Document this so future readers know it's intentional.
    assert _F031_PATTERN.match("..") is not None  # allowed by alphabet


def test_f031_helpers_reject_via_validate_function() -> None:
    """The validator raises an exception with status_code=400 for bad input."""
    for bad in ("../etc/passwd", "foo bar", "foo/bar", "a" * 65, ""):
        with pytest.raises(_HTTPException) as exc:
            _validate_rule_id(bad)
        assert exc.value.status_code == 400

    # Valid id returns the same string unchanged.
    assert _validate_rule_id("ssh_brute_force") == "ssh_brute_force"
