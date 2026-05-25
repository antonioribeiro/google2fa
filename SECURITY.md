# Security Policy

Google2FA is a cryptographic library used for two-factor authentication, so security reports are taken seriously and prioritized.

## Reporting a vulnerability

**Please do not open a public issue or pull request for security vulnerabilities.** Instead, report privately via GitHub Security Advisories:

[**Report a vulnerability**](https://github.com/antonioribeiro/google2fa/security/advisories/new)

This delivers the report directly to the maintainers and keeps the discussion private until a fix is ready.

If you cannot use GitHub Security Advisories, email **acr@antoniocarlosribeiro.com** with the subject prefix `[google2fa security]`.

## What to include

- A description of the vulnerability and its impact
- Steps to reproduce (proof-of-concept code is welcome)
- The affected version(s) — check `composer show pragmarx/google2fa`
- Any suggested mitigation or fix

## Response

You should expect an initial acknowledgement within a few days. After triage:

- If the report is valid, a fix is prepared on a private branch and a coordinated release is planned.
- A CVE will be requested if the issue warrants one.
- You will be credited in the release notes (unless you prefer to remain anonymous).

## Supported versions for security fixes

| Version         | Supported |
| --------------- | --------- |
| `9.x`           | ✅        |
| `8.x`           | ✅        |
| `7.x` and older | ❌        |

See the [Version Support](README.md#version-support) section in the README for the full lifecycle policy.
