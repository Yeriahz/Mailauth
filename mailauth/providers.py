"""
mailauth/providers.py - mail provider fingerprinting, and the provider-specific
knowledge the DKIM prober and the report generator need.

Two honesty rules govern this file:

  1. DKIM selector lists are best-effort defaults observed in the wild. They are
     the vendor's documented default, not an enumeration. A selector that is not
     on this list is normal and common. Nothing derived from these lists may be
     phrased as proof of absence.
  2. SPF include tokens and record templates are the vendor's published values
     at time of writing. Where a vendor varies by region or plan, that is stated
     on the entry rather than guessed at.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Provider:
    """A mail provider, how to recognise it, and how to fix a domain that uses it."""

    key: str
    name: str
    # Substrings matched against MX hostnames, first match wins.
    mx_needles: tuple[str, ...] = ()
    # Vendor default DKIM selectors, tried before the generic list.
    selectors: tuple[str, ...] = ()
    # The SPF include the vendor documents, used when generating a record.
    spf_include: str | None = None
    # How DKIM is enabled, for the client-facing report.
    dkim_setup: str = ""
    # Set when selectors are per-tenant and cannot be guessed at all.
    selectors_unguessable: bool = False
    # True only where dkim_setup was checked against the vendor's live
    # documentation. Everything else is written from prior knowledge and is
    # phrased as a description rather than an instruction, because a wrong
    # menu path in a client report costs more credibility than saying nothing.
    setup_verified: bool = False
    verified_on: str = ""

    @property
    def spf_record(self) -> str | None:
        if not self.spf_include:
            return None
        return f"v=spf1 include:{self.spf_include} -all"


# Ordered most specific first: "protection.outlook.com" must be tested before a
# bare "outlook.com" would be, and GoDaddy's Microsoft-backed product resolves to
# Microsoft MX hosts, so it is recognised as Microsoft 365 and the report says so.
PROVIDERS: tuple[Provider, ...] = (
    Provider(
        key="microsoft365",
        name="Microsoft 365",
        mx_needles=("mail.protection.outlook.com", "protection.outlook.com"),
        selectors=("selector1", "selector2"),
        spf_include="spf.protection.outlook.com",
        dkim_setup=(
            "In the Defender portal at https://security.microsoft.com, go to "
            "Email & collaboration > Policies & rules > Threat policies > Email "
            "authentication settings, then the DKIM tab. The direct link is "
            "https://security.microsoft.com/authentication. Enabling DKIM "
            "publishes selector1 and selector2 as CNAMEs pointing at the tenant."
        ),
        setup_verified=True,
        verified_on="2026-08-11",
    ),
    Provider(
        key="google",
        name="Google Workspace",
        mx_needles=("aspmx.l.google.com", "googlemail.com", "google.com"),
        selectors=("google",),
        spf_include="_spf.google.com",
        dkim_setup=(
            "Google Admin console > Apps > Google Workspace > Gmail > Authenticate "
            "email. Select the domain, then Generate New Record. Publish the TXT "
            "record it shows at google._domainkey, then click Start "
            "Authentication."
        ),
        setup_verified=True,
        verified_on="2026-08-11",
    ),
    Provider(
        key="zoho",
        name="Zoho Mail",
        mx_needles=("zoho.com", "zoho.eu", "zohomail", "zoho"),
        selectors=("zoho", "zmail"),
        # Zoho's include differs by data centre (zoho.com, zoho.eu, zoho.in).
        # zoho.com is the US default; the report notes the regional variants.
        spf_include="zoho.com",
        dkim_setup=(
            "Zoho Mail Admin Console > Domains > the domain > Email Configuration "
            "tab > DKIM > Add. Zoho asks you to choose the selector name yourself "
            "and suggests zoho, so the selector this tool probes is a convention "
            "rather than a fixed default."
        ),
        setup_verified=True,
        verified_on="2026-08-11",
    ),
    Provider(
        key="fastmail",
        name="Fastmail",
        mx_needles=("messagingengine.com", "fastmail.com"),
        selectors=("fm1", "fm2", "fm3", "mesmtp"),
        spf_include="spf.messagingengine.com",
        dkim_setup=(
            "Fastmail Settings > Domains. Fastmail publishes fm1/fm2/fm3 as CNAMEs "
            "and rotates the underlying keys itself."
        ),
    ),
    Provider(
        key="proofpoint",
        name="Proofpoint",
        mx_needles=("pphosted.com", "ppe-hosted.com", "proofpoint"),
        # Proofpoint selectors are provisioned per tenant. The two below are
        # common defaults, not an enumeration, and a miss means very little here.
        selectors=("ppdkim", "selector1"),
        spf_include=None,
        dkim_setup="Proofpoint admin > Email Authentication. Selector is chosen per tenant.",
        selectors_unguessable=True,
    ),
    Provider(
        key="mimecast",
        name="Mimecast",
        mx_needles=("mimecast",),
        # Mimecast selectors embed the year of provisioning, so they cannot be
        # guessed from outside with any useful hit rate.
        selectors=(),
        spf_include="_netblocks.mimecast.com",
        dkim_setup="Mimecast Administration Console > Gateway > Policies > DNS Authentication.",
        selectors_unguessable=True,
    ),
    Provider(
        key="barracuda",
        name="Barracuda",
        mx_needles=("barracudanetworks.com", "barracuda"),
        selectors=(),
        spf_include=None,
        dkim_setup="Barracuda Email Gateway Defense > Domains > DKIM.",
        selectors_unguessable=True,
    ),
    Provider(
        key="godaddy",
        name="GoDaddy",
        mx_needles=("secureserver.net",),
        selectors=("default", "dkim"),
        spf_include="secureserver.net",
        dkim_setup=(
            "GoDaddy Email & Office dashboard. Note that GoDaddy's current "
            "Microsoft-backed plans use the Microsoft 365 admin center instead."
        ),
    ),
    Provider(
        key="namecheap",
        name="Namecheap Private Email",
        mx_needles=("privateemail.com", "registrar-servers.com"),
        selectors=("default",),
        spf_include="spf.privateemail.com",
        dkim_setup="Namecheap Private Email webmail > Settings > Mail Domains > DKIM.",
    ),
    Provider(
        key="rackspace",
        name="Rackspace Email",
        mx_needles=("emailsrvr.com",),
        selectors=("mailrelay", "default"),
        spf_include="emailsrvr.com",
        dkim_setup="Rackspace Cloud Office control panel > Domains > DKIM.",
    ),
    Provider(
        key="ionos",
        name="IONOS",
        mx_needles=("ionos", "1and1"),
        selectors=("default",),
        # Regional, like Zoho: _spf-eu covers the European platform. A US or
        # other-region IONOS tenant is issued a different include, so the
        # generated record needs checking against the tenant.
        spf_include="_spf-eu.ionos.com",
        dkim_setup="IONOS control panel > Email > the domain > DKIM.",
    ),
    Provider(
        key="protonmail",
        name="Proton Mail",
        mx_needles=("protonmail.ch", "protonmail.com", "proton.me"),
        selectors=("protonmail", "protonmail2", "protonmail3"),
        spf_include="_spf.protonmail.ch",
        dkim_setup="Proton Mail Settings > Domain names > the domain > DKIM.",
    ),
    Provider(
        key="cloudflare",
        name="Cloudflare Email Routing",
        mx_needles=("mx.cloudflare.net",),
        selectors=(),
        spf_include="_spf.mx.cloudflare.net",
        dkim_setup=(
            "Cloudflare Email Routing forwards inbound mail only and does not sign "
            "outbound mail, so DKIM belongs to whatever service actually sends."
        ),
        selectors_unguessable=True,
    ),
    Provider(
        key="yahoo_sbs",
        name="Yahoo Small Business",
        mx_needles=("yahoodns.net",),
        selectors=(),
        spf_include=None,
        selectors_unguessable=True,
    ),
    Provider(
        key="improvmx",
        name="ImprovMX",
        mx_needles=("improvmx.com",),
        selectors=(),
        spf_include="spf.improvmx.com",
        selectors_unguessable=True,
    ),
)

PROVIDERS_BY_KEY: dict[str, Provider] = {p.key: p for p in PROVIDERS}

# Tried after the provider's own selectors, and on their own when the provider is
# unknown. Drawn from the defaults of widely used mail platforms and ESPs. This
# is a guess list; a domain using a selector outside it is entirely normal.
GENERIC_SELECTORS: tuple[str, ...] = (
    "default",
    "dkim",
    "mail",
    "google",
    "selector1",
    "selector2",
    "s1",
    "s2",
    "k1",
    "k2",
    "smtp",
    "key1",
    "sig1",
    "zoho",
    "fm1",
    "mandrill",
    "sendgrid",
    "em",
    "hs1",
    "hs2",
    "ctct1",
    "everlytickey1",
    "protonmail",
)


def identify(mx_hosts: list[str]) -> Provider | None:
    """Match MX hostnames against the fingerprint table, first hit wins."""
    joined = " ".join(host.lower() for host in mx_hosts)
    if not joined:
        return None
    for provider in PROVIDERS:
        for needle in provider.mx_needles:
            if needle in joined:
                return provider
    return None


def selectors_for(provider: Provider | None, extra: list[str] | None = None) -> list[str]:
    """Build the selector probe list: the provider's defaults, then the generic list.

    Order matters only for readability of the output. Every selector in the
    returned list is recorded as tried, whether or not it produced a key.
    """
    ordered: list[str] = []
    for selector in list(extra or []) + list(provider.selectors if provider else ()):
        if selector not in ordered:
            ordered.append(selector)
    for selector in GENERIC_SELECTORS:
        if selector not in ordered:
            ordered.append(selector)
    return ordered


# Where to put records, keyed by the DNS host rather than the mail provider.
# These two are often different: a firm on Microsoft 365 frequently has its DNS
# at GoDaddy, and the records go in the GoDaddy panel.
# Where to put records, keyed by the DNS host rather than the mail provider.
# These two are often different: a firm on Microsoft 365 frequently has its DNS
# at GoDaddy, and the records go in the GoDaddy panel.
#
# Each entry carries whether it was checked against the vendor's live
# documentation. Unverified entries are rendered as descriptions rather than
# instructions - see report.dns_host_guidance_lines.
DNS_HOST_GUIDANCE: dict[str, tuple[str, bool]] = {
    "godaddy": (
        "GoDaddy: sign in to your Domain Portfolio, select the domain to open "
        "Domain Settings, select DNS, then Add New Record and choose TXT. The "
        "Name field takes the prefix only (`_dmarc`), without the domain name; "
        "enter @ for the root domain.",
        True,
    ),
    "namecheap": (
        "Namecheap: Domain List > Manage next to the domain > the Advanced DNS "
        "tab > Add new record > TXT Record. The Host field takes the prefix only "
        "(`_dmarc`) or @ for the root - Namecheap's documentation is explicit "
        "that the domain name itself must not be included, even if the service "
        "asking for the record told you to include it.",
        True,
    ),
    "cloudflare": (
        "Cloudflare: the domain > DNS > Records > Add record. Cloudflare accepts "
        "either the label or the full name and normalises it, and TXT records "
        "are never proxied.",
        False,
    ),
    "google": (
        "Google Workspace does not host your DNS. Records go wherever the "
        "domain's nameservers point, which the Admin console shows under "
        "Domains.",
        True,
    ),
    "microsoft365": (
        "Microsoft 365: if the domain is managed by Microsoft, Admin center > "
        "Settings > Domains > the domain > DNS records. If DNS is elsewhere, "
        "Microsoft shows the required values and you add them at your DNS host.",
        False,
    ),
    "generic": (
        "Add these at whichever provider hosts the domain's DNS. That is the "
        "company its nameservers point to, which is not necessarily the "
        "registrar or the mail provider.",
        True,
    ),
}


def dns_host_guidance(keys: list[str]) -> list[str]:
    """Guidance blocks for the given hosts, always including the generic one.

    Unverified entries are softened here rather than at the call site, so no
    caller can render one as a bare instruction by accident.
    """
    out: list[str] = []
    for key in [*keys, "generic"]:
        entry = DNS_HOST_GUIDANCE.get(key)
        if entry is None:
            continue
        text, verified = entry
        if not verified:
            text = (
                f"{text} This path is from prior notes rather than checked "
                f"against current documentation, so confirm the menu names in "
                f"the panel before relying on them."
            )
        if text not in out:
            out.append(text)
    return out
