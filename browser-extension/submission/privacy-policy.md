# CapAuth Privacy Policy

**Last updated:** 2026-02-27

## Summary
CapAuth collects no personal data. Everything stays on your device.

## Data we store (locally)
CapAuth stores the following **only in your browser's local storage** (`chrome.storage.local`):

| Item | Purpose | Retention |
|------|---------|-----------|
| PGP fingerprint | Identify your key to the server | Until you clear settings |
| ASCII-armored private key | Sign authentication challenges | Until you clear settings |
| ASCII-armored public key | Key enrollment with new services | Until you clear settings |
| JWT access tokens | Avoid re-signing on repeat visits | Token TTL (default: 1 hour) |

## Data we do NOT collect
- We do not transmit your private key anywhere
- We do not track browsing history
- We do not use analytics or telemetry
- We do not use cookies
- We do not share data with third parties

## Network requests
CapAuth communicates **only** with:
- The CapAuth-enabled service you are logging into (`/capauth/v1/challenge`, `/capauth/v1/verify`)
- No other endpoints are contacted

## Your rights
You can delete all stored data at any time from the extension's Options page → "Clear all data".

## Contact
security@smilintux.org
