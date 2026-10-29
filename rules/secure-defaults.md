---
id: secure-defaults
title: Secure defaults
applies_to: [all]
---
# Secure defaults

- Do use parameterised queries only. Never concatenate or format user input into SQL, NoSQL filters, shell commands or file paths.
- Do apply context-aware output encoding (HTML body, attribute, JavaScript, URL, CSS each need their own) at the point of output.
- Do validate input against a strict allowlist (type, length, range, format) at every trust boundary, and reject rather than repair.
- Do grant the least privilege needed: database accounts, file permissions, API scopes, cloud roles and process users.
- Do use vetted libraries for authentication, sessions and cryptography. Never write your own.
- Don't put secrets in code, tests, logs, images or version control. Read them from the environment or a secret store.
- Do keep a `.env.example` with fake placeholder values only, and keep real `.env` files out of git.
- Do pin dependencies by lockfile and commit the lockfile.
