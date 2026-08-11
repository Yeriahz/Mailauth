"""
mailauth/checks - one module per record type.

Every check takes a Resolver and a domain and returns a frozen result carrying
its own findings. No check writes to a file, prints, or reaches the network
except through the Resolver it was handed.
"""

from __future__ import annotations

from . import dkim, dmarc, extras, mx, spf

__all__ = ["dkim", "dmarc", "extras", "mx", "spf"]
