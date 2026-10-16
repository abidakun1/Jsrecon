# Security Policy

## Reporting a vulnerability in jsrecon itself

If you find a security issue in jsrecon's own code (e.g. something in the
local `--serve` dashboard server, a path-traversal in workspace/file
handling, an injection via a crafted scan target, etc.), please report it
privately rather than opening a public issue:

- Open a [GitHub Security Advisory](../../security/advisories/new) on this
  repository (preferred — keeps it private until a fix ships), or
- Email the maintainer directly (see the GitHub profile at
  [@abidakun1](https://github.com/abidakun1) for a contact method).

Please include:
- A description of the issue and its impact
- Steps to reproduce (a minimal repro is ideal)
- Any suggested fix, if you have one

We'll acknowledge reports within a few days and aim to ship a fix or
mitigation before any public disclosure. Please give us reasonable time to
do that before disclosing publicly.

## Scope note

jsrecon's `--serve` dashboard binds to `127.0.0.1` by default and is meant
for local, single-user use on your own machine — it is not designed or
intended to be exposed to a network or run as a shared/multi-tenant service.
Running it that way is outside this project's threat model; please don't
file "the dashboard has no auth" as a vulnerability unless you've found a
way to reach it other than exposing a local-only tool to a network yourself.

## This is not where to report bugs *found by* jsrecon

A secret, exposed source map, or postMessage vulnerability that jsrecon
*detected* in someone else's application is not a vulnerability in jsrecon —
report that to the owner of the scanned target, through whatever responsible
disclosure or bug bounty program applies to it, not here.
