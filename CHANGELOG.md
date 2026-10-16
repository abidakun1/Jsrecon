# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/).

## [1.0.0] — Initial public release

### Detection
- postMessage analysis: origin-check classification (none/weak/custom/strict
  with taint-aware alias tracking), wildcard (`'*'`) send detection,
  dangerous-sink detection (`eval`, `innerHTML`, `document.write`, etc.) via
  event.data taint tracking.
- WebSocket/BroadcastChannel/`.onmessage` (any receiver) message handling,
  insecure `ws://` URL detection, `importScripts`, `document.domain`
  relaxation, and `window.open` missing `noopener` checks.
- Cross-file taint: follows `event.data` through `require()`/`import` into
  another scanned file's exported function, flagging it when that function's
  own body reaches a dangerous sink (scoped to one scan batch).
- Exposed source map detection/resolution, with vendor-vs-own-source
  classification.
- Recon data extraction: emails, domains, IPv4s, API paths (with HTTP method
  detection), URLs + query params, S3 buckets, social links, npm packages,
  GraphQL operations.
- Secrets detection: provider-specific key formats (AWS, GCP, Slack, Stripe,
  GitHub, GitLab, SendGrid, Mailgun, Heroku, npm, Firebase, Azure,
  DigitalOcean, Mailchimp, Twilio), JWTs, private key blocks, generic
  `key:`/`secret:`/`token:` assignments, and a Shannon-entropy fallback.
- Structural matching (brace/paren boundaries, string-literal detection) runs
  on a comment/string-safe "mask" built from a dependency-free tokenizer, so
  an unbalanced bracket inside a string/comment/regex literal can't corrupt
  handler-body or call-argument extraction.

### Workflow
- Local workspace persistence (`~/.jsrecon/workspaces/<name>/`), with
  new-vs-seen diffing across scans, persistent triage (false-positive/
  confirmed) that survives future scans of the same value, and cross-target/
  cross-workspace value correlation.
- Allowlist: per-workspace exact-value/regex list of known-safe values,
  suppressed from every future scan (`--allowlist-add/-remove/-list`).
- Retry with backoff (honoring `Retry-After`) on 429/5xx for every remote
  fetch.
- Self-contained local HTML dashboard (`--ui --serve`) with in-place triage,
  filtering, and correlation notes.

### Quality
- Pure detection functions extracted into `lib/analyzers.js` (no network,
  filesystem, or CLI/process state) with a `node:test` unit suite covering
  the true-positive/false-positive fixes and every detector.
