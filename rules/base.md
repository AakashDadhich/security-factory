---
id: base
title: Base
applies_to: [all]
---
# OWASP Top 10:2025

Source: https://owasp.org/Top10/2025/ (checked 2026-10-29).

## A01 Broken Access Control
- Do enforce authorisation on the server for every request, deny by default.
- Do check object ownership on every read and write of a user's data.
- Don't trust client-supplied ids, roles, prices or flags.
- Don't expose directory listings, backup files or admin routes without access checks.

## A02 Security Misconfiguration
- Do ship hardened defaults: debug off, no sample accounts, no default credentials.
- Do disable unused features, ports, routes and services.
- Don't return verbose errors, stack traces or version banners.

## A03 Software Supply Chain Failures
- Do pin dependencies by lockfile and review every new dependency.
- Do pin CI actions and container images by digest or commit.
- Don't add a dependency for a few lines of code, and don't install from unverified sources.

## A04 Cryptographic Failures
- Do use vetted libraries and current algorithms (AES-GCM, ChaCha20-Poly1305, SHA-256 or better, Argon2id or bcrypt for passwords).
- Do use TLS for all network traffic.
- Don't hand-roll cryptography, use MD5 or SHA-1 for security, or hardcode keys.

## A05 Injection
- Do use parameterised queries and safe APIs that separate code from data.
- Do encode output for the context it lands in.
- Don't build SQL, shell, LDAP, XPath or template strings from user input, and don't call `eval` on it.

## A06 Insecure Design
- Do design for abuse cases: rate limits, quotas, and limits on size and depth of input.
- Do separate trust levels and keep sensitive operations behind explicit checks.
- Don't rely on client-side checks for security decisions.

## A07 Authentication Failures
- Do use a vetted library or identity provider for authentication and sessions.
- Do rate limit and lock out repeated failures, and rotate session ids on login.
- Don't store passwords reversibly, accept weak or breached passwords, or put session ids in URLs.

## A08 Software or Data Integrity Failures
- Do verify signatures or checksums of downloaded code and updates.
- Do treat deserialised data as untrusted and use safe formats such as JSON with schema validation.
- Don't deserialise untrusted data with native object serialisers.

## A09 Security Logging and Alerting Failures
- Do log authentication events, access control failures and input validation failures with enough context to investigate.
- Don't log secrets, tokens, full card numbers or personal data, and neutralise newlines in logged user input.

## A10 Mishandling of Exceptional Conditions
- Do handle every error path and fail closed: on error, deny.
- Do return a generic message to the caller and log the detail.
- Don't swallow exceptions silently, leave resources open, or continue after a failed security check.
