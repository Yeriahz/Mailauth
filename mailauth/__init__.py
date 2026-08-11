"""
mailauth - passive email authentication review over public DNS.

Every check in this package is a public DNS query. The one exception is the
MTA-STS policy fetch, which is gated behind an explicit opt-in flag because it
connects to a host the assessed domain operates. There is no SMTP probing, no
port scanning and no web crawling anywhere in this package, by design.
"""

from __future__ import annotations

__version__ = "1.0.0"
__author__ = "Jeriah Keith"
__email__ = "yeriahz@sscsnv.com"
__url__ = "https://github.com/Yeriahz/Mailauth"

__all__ = ["__author__", "__email__", "__url__", "__version__"]
