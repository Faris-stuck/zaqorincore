"""SOAR backends shipped in v1.3.0 (ADR-008).

Slices 2-7 added one backend each:

  - generic_webhook (Slice 2)
  - slack          (Slice 3)
  - discord        (Slice 4)
  - pagerduty      (Slice 5)
  - thehive        (Slice 6)
  - jira           (Slice 7)

The worker imports the classes lazily in `_install_backends`
so importing this package does not import every backend
(and therefore does not require httpx or jinja2 in tests
that don't use the backends).
"""
