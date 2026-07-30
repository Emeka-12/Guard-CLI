# Security Policy

## Supported Versions

Security fixes are applied to the **`main` branch** and included in the next release.
Older tags do not receive backported patches unless the issue is critical and a
maintainer decides otherwise.

| Version / Branch | Supported |
|-----------------|-----------|
| `main`          | ✅ Yes     |
| Older tags      | ❌ No      |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Use one of the following channels:

1. **GitHub Private Security Advisory (preferred)**
   Navigate to the repository's **Security** tab → **Advisories** → **Report a vulnerability**.
   GitHub keeps the report private until a fix is released.

2. **Email**
   Send details to **security@soroban-guard.dev** (monitored by maintainers).
   Encrypt sensitive reports with the PGP key published at the email address above if
   you need to share exploit code or credentials.

Include as much of the following as possible:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof-of-concept
- The affected version(s) or commit hash
- Any suggested fix or mitigation

## Response Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgement | Within **48 hours** of receipt |
| Status update | Within **5 business days** |
| Patch / mitigation | Within **30 days** for critical issues; **90 days** for others |
| Public disclosure | Coordinated with the reporter after a fix is available |

We follow a **coordinated disclosure** model. We ask reporters to keep the issue
private until a fix has been released or 90 days have elapsed, whichever comes first.

## Scope

### In scope

- Vulnerabilities in the `soroban-guard` CLI binary itself (e.g. path traversal,
  arbitrary code execution when processing malicious contract source files)
- Vulnerabilities in the `soroban-guard-analyzer` or `soroban-guard-checks` crates
  that could allow a crafted input to compromise the host running the tool
- Supply-chain issues with direct dependencies declared in `Cargo.toml`

### Out of scope

- False positives or false negatives in vulnerability detectors (these are bugs,
  not security issues — please file a normal GitHub issue)
- Vulnerabilities in Soroban smart contracts that Soroban Guard *analyses* but does
  not execute
- Security issues in third-party tools or services (report those upstream)
- Issues that require physical access to the analyst's machine

## Key Rotation Procedures

When a sensitive key or token requires rotation (e.g., suspected compromise, routine expiration), follow this process:

### GitHub Actions Secrets

1. **Generate a new secret/token** in the relevant service (crates.io, GitHub, etc.)
2. **Create a new secret in GitHub** (Settings → Secrets → New secret) with a versioned name if keeping both temporarily (e.g., `CRATES_IO_TOKEN_V2`)
3. **Update CI/CD workflows** to reference the new secret
4. **Verify new workflows pass** with the new secret in place
5. **Remove the old secret** from GitHub after confirming the new one works consistently
6. **Document the rotation** in an internal log or team notes (do not commit to the repo)

### Crates.io Publishing Keys

If the publishing token to crates.io is compromised:

1. **Revoke the token immediately** in your crates.io account settings
2. **Generate a new token** with the minimum scope needed (`publish-update` only if not new crates)
3. **Update the GitHub Actions secret** (follow the steps above)
4. **Publish a new patch version** of affected crates with CI to confirm access

### Signing Keys (Release Tags)

If a GPG or SSH key used for signing releases is compromised:

1. **Revoke the old key** (if using GPG, run `gpg --send-keys <key-id>` to publish revocation)
2. **Generate a new signing key** following your authentication setup
3. **Update git config** locally and ensure team members update theirs
4. **Re-sign recent releases** if necessary, or document the key change in release notes
5. **Publish the new public key** in a way your team can verify (e.g., in the repository as `MAINTAINERS.md`)

### When in Doubt

If you suspect a key is compromised but are uncertain about the scope, **contact a maintainer privately** before proceeding. Do not commit any secrets or keys to the repository in the process.

## Credit and Acknowledgements

Reporters who responsibly disclose a valid security issue will be acknowledged in the
release notes and in a **Hall of Fame** section below, unless they prefer to remain
anonymous.

> Want to be listed? Let us know your preferred name/handle when you file the report.
