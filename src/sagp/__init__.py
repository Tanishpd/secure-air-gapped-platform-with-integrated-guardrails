"""sagp — Secure Air-Gapped Platform with Integrated Guardrails.

Importing this package has **no side effects**: it does not read the filesystem,
touch the network, or construct any model, ORT session, spaCy pipeline or
Presidio engine (CLAUDE.md §7). Only the version is exported here.
"""

from sagp.version import __version__

__all__ = ["__version__"]
