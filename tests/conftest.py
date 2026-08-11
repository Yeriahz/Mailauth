"""
tests/conftest.py - the fake resolver every test runs against.

No test in this suite touches the network. The fake is a dict keyed by
(name, rdtype), which is the same shape the real client caches, so a fixture is
just a small zone file written as Python.
"""

from __future__ import annotations

import pytest

from mailauth.dns_client import DnsResponse, normalise
from mailauth.models import QueryStatus
from mailauth.scoring import Weights, load_weights


class FakeResolver:
    """Dict-backed stand-in for DnsClient.

    Any name not in the zone returns NXDOMAIN, which is what makes a fixture
    minimal: only the records that exist need to be written down.
    """

    def __init__(
        self,
        zone: dict[tuple[str, str], list[str]] | None = None,
        server: str = "fake",
        authenticated: bool = False,
        fail: set[tuple[str, str]] | None = None,
        empty: set[tuple[str, str]] | None = None,
    ) -> None:
        self.zone = {
            (normalise(name), rdtype.upper()): values
            for (name, rdtype), values in (zone or {}).items()
        }
        self._server = server
        self.authenticated = authenticated
        self.fail = {(normalise(n), t.upper()) for n, t in (fail or set())}
        self.empty = {(normalise(n), t.upper()) for n, t in (empty or set())}
        self.queries: list[tuple[str, str]] = []

    @property
    def server(self) -> str:
        return self._server

    def query(self, name: str, rdtype: str) -> DnsResponse:
        key = (normalise(name), rdtype.upper())
        self.queries.append(key)
        if key in self.fail:
            return DnsResponse(key[0], key[1], QueryStatus.TIMEOUT)
        if key in self.empty:
            return DnsResponse(key[0], key[1], QueryStatus.EMPTY)
        if key in self.zone:
            return DnsResponse(
                key[0],
                key[1],
                QueryStatus.OK,
                values=list(self.zone[key]),
                ttl=3600,
                authenticated=self.authenticated,
            )
        return DnsResponse(key[0], key[1], QueryStatus.NXDOMAIN)

    def txt(self, name: str) -> DnsResponse:
        return self.query(name, "TXT")

    def mx(self, name: str) -> DnsResponse:
        return self.query(name, "MX")

    def cname(self, name: str) -> DnsResponse:
        return self.query(name, "CNAME")


# ---------------------------------------------------------------------------
# DKIM key material
#
# The parser under test walks DER, so the fixtures have to be structurally valid
# DER rather than a plausible-looking base64 blob. These build a real
# SubjectPublicKeyInfo of an arbitrary modulus size. The modulus is not a product
# of primes and could not verify a signature, which does not matter: nothing here
# performs crypto, it only reads the modulus length.
# ---------------------------------------------------------------------------

# 1.2.840.113549.1.1.1 rsaEncryption, followed by a NULL parameter.
_RSA_ALGORITHM_ID = bytes.fromhex("300d06092a864886f70d0101010500")


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(value)) + value


def _der_integer(value: bytes) -> bytes:
    # DER integers are signed, so a leading byte with the high bit set needs a
    # zero pad to keep the value positive.
    if value and value[0] & 0x80:
        value = b"\x00" + value
    return _der(0x02, value)


def make_rsa_spki(bits: int) -> bytes:
    """Build a DER SubjectPublicKeyInfo whose modulus is exactly `bits` long."""
    modulus = bytearray(b"\xab" * (bits // 8))
    modulus[0] |= 0x80  # force the top bit so the length is exactly `bits`
    rsa_public_key = _der(
        0x30, _der_integer(bytes(modulus)) + _der_integer(b"\x01\x00\x01")
    )
    bit_string = _der(0x03, b"\x00" + rsa_public_key)
    return _der(0x30, _RSA_ALGORITHM_ID + bit_string)


def make_dkim_p(bits: int) -> str:
    """The base64 `p=` value for a key of the given size."""
    import base64

    return base64.b64encode(make_rsa_spki(bits)).decode("ascii")


RSA_2048_P = make_dkim_p(2048)
RSA_1024_P = make_dkim_p(1024)
RSA_512_P = make_dkim_p(512)


@pytest.fixture
def weights() -> Weights:
    """The shipped weights file, default profile."""
    return load_weights()


@pytest.fixture
def clean_zone() -> dict[tuple[str, str], list[str]]:
    """A domain with everything configured correctly."""
    return {
        ("locked.test", "MX"): ["1 aspmx.l.google.com", "5 alt1.aspmx.l.google.com"],
        ("aspmx.l.google.com", "A"): ["142.250.1.26"],
        ("aspmx.l.google.com", "AAAA"): ["2607:f8b0:4004:c07::1a"],
        ("alt1.aspmx.l.google.com", "A"): ["142.250.1.27"],
        ("alt1.aspmx.l.google.com", "AAAA"): ["2607:f8b0:4004:c07::1b"],
        ("locked.test", "TXT"): ["v=spf1 include:_spf.google.com -all"],
        ("_spf.google.com", "TXT"): ["v=spf1 ip4:35.190.247.0/24 -all"],
        ("_dmarc.locked.test", "TXT"): [
            "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@locked.test; fo=1;"
        ],
        ("google._domainkey.locked.test", "TXT"): [f"v=DKIM1; k=rsa; p={RSA_2048_P}"],
        ("_smtp._tls.locked.test", "TXT"): ["v=TLSRPTv1; rua=mailto:tlsrpt@locked.test"],
        ("_mta-sts.locked.test", "TXT"): ["v=STSv1; id=20260101000000Z"],
        ("locked.test", "SOA"): ["ns1.locked.test. hostmaster.locked.test. 1 2 3 4 5"],
    }


@pytest.fixture
def wideopen_zone() -> dict[tuple[str, str], list[str]]:
    """A live mail-receiving domain with nothing published."""
    return {
        ("wideopen.test", "MX"): ["10 mail.secureserver.net"],
        ("mail.secureserver.net", "A"): ["97.74.1.1"],
        ("wideopen.test", "TXT"): ["google-site-verification=abc123"],
        ("wideopen.test", "SOA"): ["ns1.wideopen.test. host.wideopen.test. 1 2 3 4 5"],
    }


@pytest.fixture
def halfway_zone() -> dict[tuple[str, str], list[str]]:
    """Microsoft 365, SPF present, DMARC at p=none with no reporting."""
    return {
        ("halfway.test", "MX"): ["0 halfway-test.mail.protection.outlook.com"],
        ("halfway-test.mail.protection.outlook.com", "A"): ["104.47.1.1"],
        ("halfway.test", "TXT"): ["v=spf1 include:spf.protection.outlook.com -all"],
        ("spf.protection.outlook.com", "TXT"): ["v=spf1 ip4:40.92.0.0/15 -all"],
        ("_dmarc.halfway.test", "TXT"): ["v=DMARC1; p=none"],
        ("halfway.test", "SOA"): ["ns1.halfway.test. host.halfway.test. 1 2 3 4 5"],
    }
