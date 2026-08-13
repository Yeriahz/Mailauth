# Changelog

Notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

Finding codes (`spf.absent`, `dmarc.policy_none`, and so on) are part of the
public interface: they are the key into the weights file, the unit a diff is
computed in, and the identifier a stored run is read back by. Renaming or
removing one is a breaking change and gets an entry here.

## [1.1.0] - 2026-08-12

### Added

- **`dmarc.policy_test_mode`** — a new finding, weight 0. Reports that a record
  sets `t=y`, which asks receivers not to apply the published policy while the
  owner tests. Receivers that do not recognise the tag ignore it and apply the
  policy as written, so handling differs between receivers and cannot be
  determined from DNS. Emitted only when `p` is `quarantine` or `reject`: on
  `p=none` both receiver classes take no action and the finding's text would be
  false, and on an absent or invalid `p` there is no policy to name.
- **`DmarcResult.policy_test_mode`**, reading the `t` tag alone. The restriction
  to an enforcing policy lives at the emit site, because it is a property of what
  the finding asserts rather than of the tag.
- **Input that cannot be a domain name is rejected before the resolver sees it.**
  A CSV row or an address passed to `check` or `batch` was previously reported as
  `the domain does not resolve`, which is a claim about the outside world made on
  a query that could never have succeeded, and indistinguishable in the output
  from a domain that had lapsed. Rejections carry no score, risk band or
  severity, and issue no query.
- **A byte order mark on the first line of a `--file` target list is consumed**
  rather than becoming part of the first domain.

### Changed

- **The DMARC rollout gates both enforcing rungs on DKIM.** A domain with no
  usable key is told, on stage 2 and stage 3, not to publish until signing is in
  place, and gets a prerequisite step pointing at the DKIM section before either
  record. Previously the ladder was identical whatever the DKIM state, so a
  domain that followed it to the end earned `combo.enforcing_without_dkim` at
  severity critical — the tool's own advice produced its own worst finding. The
  gate uses the same predicate as that finding, so the two cannot disagree.
  A delegation resolving to nothing and an unobservable wildcard zone are both
  treated as no key, because mail is unsigned in every one of those cases.
- The generated records themselves are unchanged.

## [1.0.0] - 2026-08-11

First release.

### Checks

- **SPF** — an RFC 7208 tokenizer rather than string splitting, with full
  include-chain resolution. Counts DNS-querying terms against the limit of ten
  and void lookups against their separate limit of two, since both are failure
  modes and conflating them hides one. Detects include loops, duplicate
  includes, terms after `all`, multiple `all` mechanisms, the deprecated `ptr`
  mechanism, macro expansion, and a `redirect` modifier that is never reached
  because an `all` precedes it.
- **DMARC** — every tag, not only `p`. Reports a `pct` below 100 under an
  enforcing policy, a subdomain policy weaker than the parent, and strict
  alignment. Checks the RFC 7489 §7.1 authorization record when `rua` or `ruf`
  points at another domain: without it the reports are never delivered, and
  nothing anywhere signals the failure.
- **DKIM** — selectors derived from the detected mail provider before falling
  back to a generic list. Keys are decoded and inspected: algorithm, RSA modulus
  bit length, test mode, and revocation. Distinguishes four states that all look
  alike from outside — a usable key, a published key that cannot be parsed, a
  key withdrawn with an empty `p=`, and a delegation whose target holds nothing.
  A wildcard zone is detected before any selector is probed, because it makes
  every probe answer.
- **MX** — null MX (RFC 7505), targets that are CNAMEs (RFC 2181 §10.3),
  targets that do not resolve, single-host domains, and IPv6 availability.
- **Supporting records** — TLS-RPT, MTA-STS, BIMI, and whether answers are
  DNSSEC authenticated.
- **Interactions** — findings that exist only in combination, such as an
  enforcing DMARC policy on a domain whose mail carries no signature that can be
  found, or a `-all` that never applies because the record permerrors first.

### Scoring

- Every weight lives in `weights.toml` with a stated rationale. No weight is
  defined in code, and a finding code with no entry raises at load time rather
  than silently scoring zero.
- Per-vertical profiles overlay the base weights. Weights that only mean
  something relative to another weight state that relationship in their
  rationale and are derived per profile.
- **Confidence is tracked separately from weight.** A gap we are unsure of keeps
  its full weight and its low confidence, and both reach the output, so a score
  built on selector probes sorts apart from one built on a missing record.
- Areas that could not be observed cap the reported confidence, scaled by how
  much each area could have contributed, so an unreadable BIMI lookup does not
  read like an unreadable DMARC lookup.
- Codes that assert the same underlying fact are grouped and capped at their
  heaviest member, so a domain is charged once for a fact rather than once per
  way of observing it.
- Domains that receive no mail are reported on their own track with no score.
  A number there would invite comparison with sending domains, and that
  comparison means nothing.
- The uncapped total is recorded alongside the capped score, so domains that
  saturate can still be ranked against each other.

### Reliability

- A failed lookup is never treated as an absent record. Timeouts and SERVFAILs
  are distinguished from NXDOMAIN and empty answers throughout, carry no weight,
  and are reported as an absence of observation rather than as a finding about
  the domain.
- TXT records split across several character strings are rejoined with no
  separator, as RFC 7208 and RFC 7489 require. Every 2048-bit DKIM key is
  published this way.
- DKIM key inspection walks the DER by hand rather than adding a compiled
  dependency, and every malformed input produces a parse error rather than an
  exception that would abort a batch run partway through a list.

### Persistence and reporting

- Every run is stored with its tool version, weights version, profile, resolver,
  and whether the gated active check was enabled.
- The weights version carries two derived digests: one over the scoring
  configuration, one over the behaviour of the scorer itself. Neither is
  hand-maintained, so a number edited without a version bump cannot make two
  incomparable runs look comparable. `diff` names which one moved.
- `mailauth diff` reports what changed per domain, distinguishes a record that
  was removed from one that could not be read, and reports score movement that
  occurred without any record changing.
- `mailauth report` generates a client-facing one-pager containing the exact
  records to publish, with a staged DMARC rollout whose stage intervals are
  configuration rather than literals.

### Scope

- Every check is a public DNS query. The single exception is the MTA-STS policy
  fetch, which connects to a host the assessed domain operates; it is gated
  behind `--active`, off by default, and prints a notice naming the URL it is
  about to request.
- No SMTP probing, port scanning, credential testing or web crawling exists
  anywhere in the package, and none is planned.
- Output describes what is published in DNS. It does not characterise anyone as
  being in violation of anything and does not name statutes. This is enforced by
  a test that renders every finding and every report section against a
  forbidden-phrase list.
- Nothing about DKIM is ever phrased as proof of absence, because selectors
  cannot be enumerated from outside a domain.
