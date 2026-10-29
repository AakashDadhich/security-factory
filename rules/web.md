---
id: web
title: Web
applies_to: [web]
---
# Web rules

- Do send security headers on every response: `Content-Security-Policy` (no `unsafe-inline` or `unsafe-eval`, `frame-ancestors` set), `Strict-Transport-Security` (HSTS), `X-Content-Type-Options: nosniff`, and a restrictive `Referrer-Policy`.
- Do protect state-changing requests with CSRF tokens whenever authentication uses cookies.
- Do set session cookies `HttpOnly`, `Secure` and `SameSite=Lax` or `Strict`, with the `__Host-` prefix where possible.
- Do rate limit authentication, password reset and other abuse-prone endpoints.
- Don't return stack traces, internal paths or raw error objects in responses. Return a generic message and log the detail.
- Do restrict CORS to named origins, never reflect the request origin and never combine a wildcard with credentials.
- Do cap request body size and validate content types.
- Don't render untrusted data with `innerHTML`, `dangerouslySetInnerHTML` or template "raw" output.
