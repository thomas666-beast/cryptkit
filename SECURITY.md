# Security Policy

## Status

cryptkit is a **learning project** and has **not been audited**. It is not
recommended for production use where confidentiality or integrity is
critical. See [THREAT_MODEL.md](THREAT_MODEL.md) for what cryptkit does
and does not defend against.

## Reporting a vulnerability

If you believe you have found a security issue, please **do not open a
public GitHub issue**. Instead:

1. Email the maintainer at the address listed on the repository's GitHub
   profile page, subject line starting with `[cryptkit security]`.
2. Include:
   - A description of the issue
   - A minimal reproduction (Go test or script)
   - The version or commit hash you tested
   - Your assessment of impact (what an attacker gains)
3. If you would like to encrypt your report, request a PGP key in your
   initial email and one will be provided.

You should receive an acknowledgment within **7 days**. If you do not,
please follow up.

## Disclosure timeline

- **Day 0** — report received
- **Day 7** — acknowledgment, initial assessment
- **Day 30** — fix or mitigation ready for review (target)
- **Day 90** — public disclosure, or earlier if a fix is released and
  users are protected

If the issue is trivial (typo, documentation, low-impact), a fix may land
sooner and disclosure may be immediate.

## Scope

**In scope:**

- Cryptographic weaknesses in the format or in how primitives are used
- Tamper-detection bypasses in ciphertext, streaming, or audit log
- Context-binding bypasses
- Key commitment bypasses
- Panics in `Decrypt` / `DecryptStream` / `audit.Verify` on attacker input
- Memory unsafety (unlikely in Go, but report if you find one)

**Out of scope:**

- Issues in `crypto/*` or `golang.org/x/crypto` (report upstream)
- Attacks requiring key compromise, host compromise, or root
- Timing side channels requiring local measurement (documented as
  out-of-scope in `THREAT_MODEL.md` §5.4)
- DoS via unbounded chunk size when the caller explicitly chose the size

## What we will do

- Credit reporters in the release notes unless anonymity is requested
- Publish a GitHub Security Advisory for confirmed issues
- Maintain a `SECURITY-FIXES` section in `CHANGELOG.md` for each fix
- Provide a patched tag and, when possible, a backport to the previous
  minor version

## What we will not do

- Pay bounties (this is a learning project)
- Sign a formal SLA
- Commit to a fix timeline for issues outside the scope listed above
