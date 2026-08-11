"""
mailauth/dns_client.py - the only module in the package that talks to the
network, and the only one that imports dnspython.

Responsibilities:
  - turn every dnspython failure mode into an explicit QueryStatus rather than
    an exception or an empty list, because "no record" and "the resolver timed
    out" must never be scored the same way
  - normalise rdata into plain strings so responses are JSON-serialisable and
    can be cached, replayed and diffed
  - honour record TTLs so re-running the same prospect list does not re-query
    everything
  - report whether the recursive resolver marked the answer as DNSSEC
    authenticated
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from .models import QueryStatus

try:
    import dns.exception
    import dns.flags
    import dns.rdatatype
    import dns.resolver
except ImportError:  # pragma: no cover - exercised only on a broken install
    raise SystemExit(
        "dnspython is required.  Install it with:  python -m pip install dnspython"
    ) from None


# TTL floor and ceiling for the cache. A domain publishing a five second TTL
# should not force a re-query on every row of a batch, and one publishing a
# thirty day TTL should not pin a stale answer for a month.
MIN_CACHE_TTL = 60
MAX_CACHE_TTL = 86_400

# TTL applied to answers that carry none of their own (NXDOMAIN, empty answers).
NEGATIVE_TTL = 300


@dataclass(frozen=True)
class DnsResponse:
    """One resolved query, with the reason behind an empty result preserved."""

    name: str
    rdtype: str
    status: QueryStatus
    values: list[str] = field(default_factory=list)
    ttl: int = NEGATIVE_TTL
    authenticated: bool = False
    error: str | None = None

    def __bool__(self) -> bool:
        return bool(self.values)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "rdtype": self.rdtype,
            "status": str(self.status),
            "values": list(self.values),
            "ttl": self.ttl,
            "authenticated": self.authenticated,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DnsResponse:
        return cls(
            name=str(data["name"]),
            rdtype=str(data["rdtype"]),
            status=QueryStatus(data["status"]),
            values=[str(v) for v in data.get("values", [])],
            ttl=int(data.get("ttl", NEGATIVE_TTL)),
            authenticated=bool(data.get("authenticated", False)),
            error=data.get("error"),
        )


class Resolver(Protocol):
    """The surface every check depends on.

    Checks are written against this, never against dnspython, so the entire
    suite can run offline against a dict-backed fake. The typed conveniences are
    part of the contract rather than helpers on the concrete class, because the
    checks call them and any stand-in has to provide them.
    """

    @property
    def server(self) -> str: ...

    def query(self, name: str, rdtype: str) -> DnsResponse: ...

    def txt(self, name: str) -> DnsResponse: ...

    def mx(self, name: str) -> DnsResponse: ...

    def cname(self, name: str) -> DnsResponse: ...


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def normalise(name: str) -> str:
    """Lower-case a DNS name and drop the trailing dot, for use as a cache key."""
    return name.strip().lower().rstrip(".")


def _rdata_to_string(rdata: Any, rdtype: str) -> str:
    """Render one rdata as the string form this package works with.

    TXT strings are concatenated with no separator, which is what RFC 7208 and
    RFC 7489 require: a long SPF or DMARC record split across several character
    strings must be rejoined before parsing, not space-joined.
    """
    if rdtype == "TXT":
        parts: list[bytes] = list(rdata.strings)
        return b"".join(parts).decode("utf-8", "replace")
    if rdtype == "MX":
        return f"{rdata.preference} {str(rdata.exchange).rstrip('.')}"
    if rdtype == "CNAME":
        return str(rdata.target).rstrip(".")
    if rdtype in ("A", "AAAA"):
        return str(rdata.address)
    return str(rdata.to_text())


def clamp_ttl(ttl: int) -> int:
    """Keep a published TTL inside the range the cache is willing to honour."""
    return max(MIN_CACHE_TTL, min(MAX_CACHE_TTL, ttl))


# ---------------------------------------------------------------------------
# client
# ---------------------------------------------------------------------------


class DnsClient:
    """Caching, retrying resolver wrapper.

    The cache is a plain in-memory dict guarded by a lock. It is deliberately
    not backed by a live SQLite handle: batch runs use a thread pool, and a
    connection shared across threads is a bug waiting to happen for no
    measurable gain at this scale. The store loads the cache in before a run and
    flushes it out after.
    """

    def __init__(
        self,
        nameservers: list[str] | None = None,
        timeout: float = 5.0,
        retries: int = 1,
        cache: dict[tuple[str, str], DnsResponse] | None = None,
        cache_enabled: bool = True,
        expiry: dict[tuple[str, str], float] | None = None,
    ) -> None:
        self._resolver = dns.resolver.Resolver(configure=not nameservers)
        if nameservers:
            self._resolver.nameservers = list(nameservers)
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout
        # Ask the recursive resolver to tell us whether it validated the answer.
        # Without the AD bit in the query many resolvers will not set it in the
        # response even when validation succeeded.
        self._resolver.set_flags(dns.flags.RD | dns.flags.AD)
        self._resolver.use_edns(0, dns.flags.DO, 1232)

        self._server = (nameservers or self._resolver.nameservers or ["system"])[0]
        self._retries = max(0, retries)
        self._cache: dict[tuple[str, str], DnsResponse] = dict(cache or {})
        self._expiry: dict[tuple[str, str], float] = dict(expiry or {})
        self._cache_enabled = cache_enabled
        self._lock = threading.Lock()
        self.queries_made = 0
        self.cache_hits = 0

    @property
    def server(self) -> str:
        return str(self._server)

    # -- cache plumbing ----------------------------------------------------

    def _cache_get(self, key: tuple[str, str]) -> DnsResponse | None:
        if not self._cache_enabled:
            return None
        with self._lock:
            expires = self._expiry.get(key)
            if expires is not None and expires < time.time():
                self._cache.pop(key, None)
                self._expiry.pop(key, None)
                return None
            hit = self._cache.get(key)
            if hit is not None:
                self.cache_hits += 1
            return hit

    def _cache_put(self, key: tuple[str, str], response: DnsResponse) -> None:
        with self._lock:
            self._cache[key] = response
            self._expiry[key] = time.time() + clamp_ttl(response.ttl)

    def export_cache(self) -> list[tuple[str, str, DnsResponse, float]]:
        """Snapshot the cache for persistence: (name, rdtype, response, expires_at)."""
        with self._lock:
            return [
                (name, rdtype, response, self._expiry.get((name, rdtype), 0.0))
                for (name, rdtype), response in self._cache.items()
            ]

    # -- querying ----------------------------------------------------------

    def query(self, name: str, rdtype: str) -> DnsResponse:
        """Resolve one name, returning a status rather than raising."""
        key = (normalise(name), rdtype.upper())
        cached = self._cache_get(key)
        if cached is not None:
            return cached

        response = self._resolve_with_retries(key[0], key[1])
        # Never cache a failure of our own vantage point: a timeout says nothing
        # about the domain and must not be replayed on the next run.
        if not response.status.is_our_fault:
            self._cache_put(key, response)
        return response

    def _resolve_with_retries(self, name: str, rdtype: str) -> DnsResponse:
        attempt = 0
        last = self._resolve_once(name, rdtype)
        while last.status.is_our_fault and attempt < self._retries:
            attempt += 1
            time.sleep(0.25 * attempt)
            last = self._resolve_once(name, rdtype)
        return last

    def _resolve_once(self, name: str, rdtype: str) -> DnsResponse:
        with self._lock:
            self.queries_made += 1
        try:
            answer = self._resolver.resolve(
                name, rdtype, raise_on_no_answer=False, search=False
            )
        except dns.resolver.NXDOMAIN:
            return DnsResponse(name, rdtype, QueryStatus.NXDOMAIN)
        except dns.resolver.NoNameservers as exc:
            return DnsResponse(name, rdtype, QueryStatus.SERVFAIL, error=str(exc)[:200])
        except dns.exception.Timeout as exc:
            return DnsResponse(name, rdtype, QueryStatus.TIMEOUT, error=str(exc)[:200])
        except dns.exception.DNSException as exc:
            # Covers malformed names (LabelTooLong, EmptyLabel) as well as
            # anything dnspython adds later. Everything here is our failure to
            # get an answer, never a statement about the domain.
            return DnsResponse(name, rdtype, QueryStatus.ERROR, error=str(exc)[:200])

        authenticated = bool(answer.response.flags & dns.flags.AD)
        if answer.rrset is None:
            return DnsResponse(
                name,
                rdtype,
                QueryStatus.EMPTY,
                ttl=NEGATIVE_TTL,
                authenticated=authenticated,
            )

        values = [_rdata_to_string(rdata, rdtype) for rdata in answer.rrset]
        return DnsResponse(
            name,
            rdtype,
            QueryStatus.OK,
            values=values,
            ttl=int(answer.rrset.ttl),
            authenticated=authenticated,
        )

    # -- typed conveniences ------------------------------------------------

    def txt(self, name: str) -> DnsResponse:
        return self.query(name, "TXT")

    def mx(self, name: str) -> DnsResponse:
        return self.query(name, "MX")

    def cname(self, name: str) -> DnsResponse:
        return self.query(name, "CNAME")


def prefixed(record_prefix: str, domain: str) -> str:
    """Build an underscore-prefixed name, e.g. ("_dmarc", "example.com") -> _dmarc.example.com."""
    return f"{record_prefix}.{normalise(domain)}"
