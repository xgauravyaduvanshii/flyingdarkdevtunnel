# Security Policy

This document explains how to report vulnerabilities and what to expect from our response process.

---

## Supported Versions

Security fixes are applied to the active development branch:

| Version / Branch | Supported |
|---|---|
| `master` | Yes |
| Older snapshots/tags | Best effort |

---

## Reporting a Vulnerability

Please **do not** disclose security issues in public GitHub issues.

Send a private report to:
- `xgauravyaduvanshii@gmail.com`

Please include:
- affected component(s),
- clear reproduction steps,
- expected vs actual behavior,
- impact assessment,
- proof-of-concept (if safe),
- suggested mitigations (optional).

---

## Response Targets

- Initial acknowledgement: within **72 hours**
- Triage decision: within **7 days**
- Patch/mitigation timeline: depends on severity and exploitability

We may request additional context or coordinated disclosure timing.

---

## Severity Guidance

Higher priority examples:
- auth bypass or token forgery,
- relay policy bypass (auth/IP/host mode),
- remote code execution,
- data exfiltration vectors,
- signature validation bypass in billing/certificate callbacks,
- privilege escalation in admin flows.

---

## Disclosure Policy

We support responsible coordinated disclosure:
- validate and patch first,
- notify maintainers/users with remediation guidance,
- publish security notes once fixes are available.

---

## Security Hardening Areas

If contributing security improvements, review:
- `docs/security-and-tls.md`
- `docs/certificate-lifecycle.md`
- `docs/runbooks/security-rotation.md`
- `docs/runbooks/ops-oncall.md`
