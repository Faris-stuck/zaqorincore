"""Validate .github/workflows/test.yml is well-formed and has the expected shape.

This test runs locally so a malformed CI workflow is caught at dev time
rather than after a push.
"""

from __future__ import annotations

from pathlib import Path

import yaml


WORKFLOW_PATH = (
    Path(__file__).resolve().parents[2] / ".github" / "workflows" / "test.yml"
)


def _load_workflow() -> dict:
    assert WORKFLOW_PATH.exists(), f"missing workflow: {WORKFLOW_PATH}"
    with WORKFLOW_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_workflow_parses_as_valid_yaml() -> None:
    wf = _load_workflow()
    assert isinstance(wf, dict), "workflow must parse to a mapping"


def test_workflow_triggers_on_push_and_pr() -> None:
    wf = _load_workflow()
    on = wf.get(True, wf.get("on", {}))
    assert "push" in on, "workflow must trigger on push"
    assert "pull_request" in on, "workflow must trigger on pull_request"


def test_workflow_has_test_job_with_expected_steps() -> None:
    wf = _load_workflow()
    jobs = wf.get("jobs", {})
    assert "test" in jobs, "workflow must define a 'test' job"
    job = jobs["test"]
    steps = job.get("steps", [])
    names = [s.get("name", "") for s in steps]
    # Required step names (case-insensitive substring match is OK for "Install server")
    assert any("actions/checkout" in (s.get("uses") or "") for s in steps), \
        "missing actions/checkout step"
    assert any("actions/setup-python" in (s.get("uses") or "") for s in steps), \
        "missing actions/setup-python step"
    assert any("Install server" in n for n in names), "missing Install server step"
    assert any("Run rules tests" in n for n in names), "missing Run rules tests step"
    assert any("Run integration tests" in n for n in names), "missing Run integration tests step"
    assert any("Lint" in n for n in names), "missing Lint step"
    assert any("Secret scan" in n for n in names), "missing Secret scan step"


def test_workflow_targets_python_3_12() -> None:
    wf = _load_workflow()
    steps = wf["jobs"]["test"]["steps"]
    py_step = next(
        (s for s in steps if "actions/setup-python" in (s.get("uses") or "")),
        None,
    )
    assert py_step is not None, "setup-python step missing"
    with_ = py_step.get("with", {})
    assert with_.get("python-version") == "3.12", \
        "workflow must use python-version 3.12"