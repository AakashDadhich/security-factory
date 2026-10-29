---
id: apple
title: Apple
applies_to: [macos, ios]
---
# Apple platform rules

- Do store secrets in the Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` or stricter. Never store secrets, tokens or keys in `UserDefaults`, plists or files.
- Do keep App Transport Security on. Don't set `NSAllowsArbitraryLoads` or broad exceptions, and don't accept invalid TLS certificates in a `URLSession` delegate.
- Do request the minimum entitlements, permissions and usage-description strings.
- Do enable App Sandbox and the hardened runtime on macOS, with no disabled library validation or unneeded exceptions.
- Do include a privacy manifest (`PrivacyInfo.xcprivacy`) that declares required-reason API use and collected data.
- Do use CryptoKit for hashing and encryption. Don't use CommonCrypto MD5 or SHA-1 for anything security related.
- Do validate and encode data used in URL schemes, universal links and pasteboard input as untrusted.
- Don't log sensitive data, and mark sensitive views and fields so they are excluded from snapshots and backups.
