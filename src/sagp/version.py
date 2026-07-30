"""Single source of truth for the package version.

Imported by ``pyproject.toml`` (dynamic version) and surfaced at ``/healthz``.
Keep this module import-free so it is cheap to read at build time.
"""

__version__ = "0.0.0"
