# mailauth

Reads a domain's public DNS and reports what it publishes for email
authentication: SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI and DNSSEC. It scores
what is missing, tracks how that changes over time, and generates the exact DNS
records that would close the gaps.

Every check is a public DNS query. It does not connect to any host the assessed
domain operates. See [Scope and ethics](#scope-and-ethics) for the one exception
and how it is gated.

```
pip install mailauth
mailauth check example.com
```

## What it does

- **SPF** — a real RFC 7208 tokenizer, full include-chain resolution, DNS lookup
  counting against the limit of 10 and void lookups against the limit of 2,
  include loops, duplicate includes, terms after `all`, deprecated `ptr`, macros,
  and `redirect` modifiers that are never reached.
- **DMARC** — every tag, not just `p`. Partial `pct`, weaker `sp`, and the
  external reporting authorization record that has to exist before a third-party
  `rua` destination receives anything.
- **DKIM** — selectors derived from the detected mail provider, then a generic
  list. Keys are decoded: algorithm, modulus bit length, test mode, revocation.
  A wildcard DNS record is detected first, because it makes every selector answer
  and would otherwise produce keys that are not there.
- **MX** — null MX, CNAME targets, unresolvable hosts, single points of failure,
  IPv6.
- **Supporting records** — TLS-RPT, MTA-STS, BIMI, and whether DNS answers are
  DNSSEC authenticated.
- **Interactions** — the findings that only exist in combination. A `p=reject`
  policy on a domain whose mail appears unsigned. A `-all` that never applies
  because the record exceeds the lookup limit and permerrors first.

## Example

A real run, live DNS, trimmed for length:

```
$ mailauth check cloudflare.com
==========================================================================
cloudflare.com   (via 1.1.1.1)
==========================================================================
  score 8/100  low  confidence 100% (high)  posture sending

[ok] SPF       SPF lookup count is within limits (7 of 10)
[ok] SPF       SPF ends in -all (hard fail)
[ok] DMARC     DMARC policy is p=reject
[ok] DMARC     Aggregate reporting is configured
[ok] DKIM      DKIM key published on 3 of the 23 selectors tried
[ i] MX        No MX target publishes an AAAA record
[ i] SPF       `exists:%{i}._spf.mta.salesforce.com` uses macro expansion, which
               is legal but makes the record hard to verify by reading it
[ i] DKIM      Selector k1 publishes a 1024-bit RSA key
               Acceptable, but 2048 bits is the current recommendation.
[ i] TLS-RPT   No TLS-RPT record is published
[ i] MTA-STS   No MTA-STS record is published
```

A domain with real gaps, from the test fixtures:

```
$ mailauth check wideopen.test
  score 100/100  high  confidence 80% (high)  posture sending

[!!] SPF       No SPF record is published
[!!] DMARC     No DMARC record is published
[!!] COMBINED  Neither SPF nor a DKIM key was found for a domain that receives mail
[! ] DKIM      No DKIM key found on the 23 selectors tried
[ i] MX        Mail is handled by GoDaddy
[ i] MX        Only one MX host is published
[ i] TLS-RPT   No TLS-RPT record is published
[ i] MTA-STS   No MTA-STS record is published
```

Add `-v` to see the raw records, the include chain, and the score broken down
line by line:

```
$ mailauth check wideopen.test -v
  score breakdown
  wideopen.test: 100/100 (high)
    +40  dmarc.absent                       [high] running total 40
    +30  spf.absent                         [high] running total 70
    +15  combo.no_authentication_at_all     [low] running total 85
    +15  dkim.none_found                    [low] running total 100
    +3   mtasts.absent                      [high] running total 100
    +2   mx.single                          [high] running total 100
    +2   tlsrpt.absent                      [high] running total 100
    +1   dnssec.unsigned                    [medium] running total 100
    capped at 100 (raw total 108)
    aggregate confidence 0.80 (high), 28% of the score is low confidence
```

## Commands

```bash
mailauth check example.com example.org     # review one or more domains
mailauth batch data/targets.example.txt          # screen a list, worst first
mailauth report latest --html              # per-domain client one-pagers
mailauth diff latest~1 latest              # what changed between two runs
mailauth runs                              # list stored runs
mailauth selftest                          # run the offline test suite
```

### batch

Takes a CSV with a `domain` column. Every other column is carried through to the
output untouched, so a prospect list keeps its firm names and notes.

```bash
mailauth batch data/targets.example.txt -o out/results.csv --profile accounting
```

Output is sorted worst first and carries `score`, `risk`, `confidence`,
`posture` and a `headline` alongside the per-record detail.

### report

Generates the artifact you hand a client: what is published in plain language,
what is missing described as an observation, and the exact records to publish,
generated for that domain and correct for its detected mail provider.

```bash
mailauth report latest --outdir out/reports --html
mailauth report latest --domain example.com
```

The DMARC rollout it generates is always staged. A domain with no DMARC gets
`p=none` with a reporting address first, then `p=quarantine`, then `p=reject`,
with the waiting period between each. Publishing `p=reject` on day one is how a
small firm loses its own mail, because there is nearly always a sending service
nobody remembered — the payroll provider, the e-signature tool, the tax software
that mails client copies. The reports are what find those.

### diff

```bash
mailauth diff latest~1 latest
```

```
comparing run 3 (2026-06-14T09:12:04+00:00, weights 2026.08.1)
     with run 7 (2026-08-09T14:02:51+00:00, weights 2026.08.1)

example.com  score 90 -> 25 (-65)
    DMARC record published (p=none)
    SPF record published
    DKIM key now found on: selector1, selector2
```

Domains present in only one of the two runs are reported as added or removed
rather than being silently dropped. If the two runs used different weights
versions, the diff says so, because score movement then reflects both the domain
and the scoring config.

## Scoring

Every weight lives in [`mailauth/weights.toml`](mailauth/weights.toml), with a
comment explaining the reasoning behind each one. Nothing in the Python code
assigns a weight. A finding code with no entry in the config raises an error
rather than silently scoring zero.

The score is the sum of the weights of the findings that apply, capped at 100.
Bands: 60+ is high, 30+ is medium.

**Confidence is tracked separately from weight**, and this is the part worth
understanding. "No DMARC record" is high confidence: absence in DNS is absence.
"No DKIM key on the selectors tried" is low confidence: selectors cannot be
enumerated from outside a domain, so a miss is evidence and never proof. Both
findings carry real weight, and the output reports the aggregate confidence plus
the share of the score that came from low-confidence findings. A 70 built mostly
from selector probes can then be sorted differently from a 70 built from a
missing DMARC record.

Override the weights, or use a different profile per vertical:

```bash
mailauth batch my-targets.csv --profile accounting
mailauth batch my-targets.csv --weights my-weights.toml
```

Shipped profiles: `default`, `accounting` (weights domain-forgery gaps up and
transit-security gaps down), and `strict` (for a domain that already has DMARC
enforced and wants to know what is left).

### Posture

A domain with no MX and no SPF is recorded as `non-sending` and scored on a
separate track. A parked domain and a live firm with no authentication publish
the same nothing, but they are completely different conversations, and letting
them compete puts parked domains at the top of the worklist. Domains that do not
resolve get `unknown`, never a zero.

## Scope and ethics

This tool reads public DNS. That is a lookup of information the domain owner
published for the world to read, which is why it is safe to run against a
prospect you have no relationship with.

**It does not, and will not:**

- connect to a mail server, open an SMTP session, or read a banner
- scan ports
- test credentials or attempt any authentication
- crawl a website
- send email to the domain
- enumerate users, mailboxes, or anything else

**The one exception**, and it is off by default: MTA-STS publishes its policy in
a file at `https://mta-sts.<domain>/.well-known/mta-sts.txt`. Fetching that file
is an HTTPS request to a web server the domain operates, and it will appear in
their logs with your source address. Reading the MTA-STS *DNS record* is passive
and always happens; fetching the *policy file* requires `--active`, which prints
a notice naming exactly what it is about to do. Use it only where you have
authorization.

**On language.** The tool describes what is published in DNS. It does not
characterise anyone as being in violation of anything and does not name statutes.
It reports that a record is absent, or that a policy is set to monitor only.
This is enforced by [`tests/test_language.py`](tests/test_language.py), which
renders every finding and every report section and asserts a forbidden-phrase
list appears nowhere — so the constraint is mechanical rather than a matter of
the author's ongoing good behaviour.

**On DKIM specifically.** Nothing this tool produces will ever say a domain has
no DKIM. Selectors are arbitrary strings that cannot be listed from outside. The
tool says how many selectors it tried, names them, and says a miss is not proof.

## Install

```bash
pipx install mailauth
```

Or from a checkout:

```bash
git clone https://github.com/Yeriahz/mailauth
cd mailauth
pipx install .
```

For development, an editable install with the dev dependencies:

```bash
python -m pip install -e ".[dev]"
```

Requires Python 3.11 or newer — `tomllib`, used for the weights file, is
standard library from 3.11. The only runtime dependency is `dnspython`.

**Windows note:** pip may report that `mailauth.exe` was installed to a
`Scripts` directory that is not on your PATH. Either add that directory to PATH,
or use `pipx install .`, which handles it.

## Development

```bash
python -m pytest              # the suite, fully offline
python -m mypy mailauth       # strict
python -m ruff check .
python -m ruff format .
```

The test suite never touches the network. Every test runs against a dict-backed
fake resolver, so it passes on a machine with no DNS at all. Tests that would hit
real DNS are marked `live` and deselected by default; run them deliberately with
`pytest -m live`.

## Repository layout

```
mailauth/         the package
  checks/         one module per record type
  weights.toml    every scoring weight, with rationale
tests/            offline test suite
data/             an example target list; real target lists are not committed
out/              run outputs, the SQLite history, generated reports (gitignored)
```

## Licence

MIT. See [LICENSE](LICENSE).
