"""
tests/test_dns_client.py - the rdata translation layer.

`_rdata_to_string` is the single most load-bearing translation in the tool:
every check reads its output and nothing downstream can recover what it got
wrong. It had no coverage at all, and the test that claimed to cover the TXT
joining handed an already-joined string to a fake resolver, so it could not have
failed for the reason it existed.

These tests build real dnspython rdata rather than fakes, so they exercise the
function as production does.
"""

from __future__ import annotations

import dns.rdata
import dns.rdataclass
import dns.rdatatype
import pytest

from mailauth.dns_client import _rdata_to_string, clamp_ttl, normalise, prefixed


def txt_rdata(*strings: bytes) -> dns.rdata.Rdata:
    """Build a real TXT rdata from explicit character-strings.

    Constructed from the wire format rather than from text, because the point of
    these tests is the multi-string case and going through text would let the
    presentation layer decide the split for us.
    """
    wire = b"".join(bytes([len(s)]) + s for s in strings)
    return dns.rdata.from_wire(dns.rdataclass.IN, dns.rdatatype.TXT, wire, 0, len(wire))


# ---------------------------------------------------------------------------
# TXT: the case the tool depends on
# ---------------------------------------------------------------------------


def test_a_single_character_string_survives_unchanged() -> None:
    rdata = txt_rdata(b"v=spf1 -all")
    assert _rdata_to_string(rdata, "TXT") == "v=spf1 -all"


def test_multiple_character_strings_join_with_nothing_between_them() -> None:
    """RFC 7208 and RFC 7489 both require concatenation with no separator.

    A space here would break every long SPF include target and every DKIM key.
    """
    rdata = txt_rdata(b"v=spf1 include:_spf.", b"google.com -all")
    assert _rdata_to_string(rdata, "TXT") == "v=spf1 include:_spf.google.com -all"


def test_a_2048_bit_dkim_key_split_at_the_255_byte_boundary_rejoins() -> None:
    """The real shape: every 2048-bit key is published as two or more strings."""
    from tests.conftest import RSA_2048_P

    record = f"v=DKIM1; k=rsa; p={RSA_2048_P}"
    assert len(record) > 255
    first, second = record[:255].encode(), record[255:].encode()
    assert len(first) == 255

    rdata = txt_rdata(first, second)
    rejoined = _rdata_to_string(rdata, "TXT")
    assert rejoined == record
    assert '"' not in rejoined
    assert len(rejoined) == len(record)


def test_the_joined_value_differs_from_the_presentation_form() -> None:
    """to_text() would add quotes and a space. Using it would corrupt every key."""
    rdata = txt_rdata(b"a" * 255, b"bbb")
    joined = _rdata_to_string(rdata, "TXT")
    presentation = rdata.to_text()

    assert joined == "a" * 255 + "bbb"
    assert '"' in presentation and '"' not in joined
    assert len(joined) < len(presentation)


def test_quote_characters_in_the_published_data_survive_intact() -> None:
    """The quoted-key case, observed on a live domain and reproduced here.

    The domain published a key whose second character-string genuinely began
    with a quote character, because whoever entered it pasted quotes into the
    panel. Those quotes are data, not framing: they must reach the parser so it
    can report the key as unreadable rather than silently repairing it.
    """
    from mailauth.checks.dkim import parse_key_record
    from tests.conftest import RSA_2048_P

    head = f"v=DKIM1; k=rsa; p={RSA_2048_P[:200]}".encode()
    tail = b'" "' + RSA_2048_P[200:].encode()

    joined = _rdata_to_string(txt_rdata(head, tail), "TXT")
    assert '" "' in joined, "the published quotes must not be stripped"

    key = parse_key_record("default", joined)
    assert key.parse_error is not None
    assert key.bits is None


def test_an_empty_character_string_contributes_nothing() -> None:
    rdata = txt_rdata(b"v=spf1 ", b"", b"-all")
    assert _rdata_to_string(rdata, "TXT") == "v=spf1 -all"


def test_undecodable_bytes_do_not_raise() -> None:
    """A malformed record must not abort a batch run partway through a list."""
    rdata = txt_rdata(b"v=spf1 \xff\xfe -all")
    result = _rdata_to_string(rdata, "TXT")
    assert result.startswith("v=spf1 ")


# ---------------------------------------------------------------------------
# the other record types
# ---------------------------------------------------------------------------


def from_text(rdtype: str, text: str) -> dns.rdata.Rdata:
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(rdtype), text)


def test_mx_carries_preference_and_a_dot_stripped_host() -> None:
    assert _rdata_to_string(from_text("MX", "10 mail.example.com."), "MX") == (
        "10 mail.example.com"
    )


def test_cname_is_dot_stripped() -> None:
    assert _rdata_to_string(from_text("CNAME", "target.example.com."), "CNAME") == (
        "target.example.com"
    )


@pytest.mark.parametrize(
    "rdtype,text",
    [("A", "192.0.2.1"), ("AAAA", "2001:db8::1")],
)
def test_addresses_render_as_written(rdtype: str, text: str) -> None:
    assert _rdata_to_string(from_text(rdtype, text), rdtype) == text


def test_an_unhandled_type_falls_back_to_presentation_form() -> None:
    rendered = _rdata_to_string(
        from_text("SOA", "ns1.example.com. host.example.com. 1 2 3 4 5"), "SOA"
    )
    assert "ns1.example.com." in rendered


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [("Example.COM.", "example.com"), ("  x.test  ", "x.test"), ("A.B.", "a.b")],
)
def test_normalise(raw: str, expected: str) -> None:
    assert normalise(raw) == expected


def test_prefixed_builds_underscore_names() -> None:
    assert prefixed("_dmarc", "Example.COM.") == "_dmarc.example.com"


def test_ttl_clamping_bounds() -> None:
    assert clamp_ttl(0) == 60
    assert clamp_ttl(1800) == 1800
    assert clamp_ttl(10**9) == 86_400
