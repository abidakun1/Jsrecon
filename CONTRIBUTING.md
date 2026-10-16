# Contributing to jsrecon

Thanks for considering a contribution. This project is small on purpose —
keep changes focused, tested, and dependency-light.

## Getting set up

```bash
git clone https://github.com/abidakun1/jsrecon.git
cd jsrecon
npm install
npm test
```

## Before you open a PR

- **Add a test.** `lib/analyzers.js` holds every pure detection function
  (postMessage, recon, secrets, cross-file taint) and `test/analyzers.test.js`
  exercises them directly with `node:test` — no CLI, no network, no real
  files needed. If you're fixing a false positive or false negative, write
  the smallest fixture string that reproduces it and assert on the expected
  finding (or absence of one). If you're adding a detector, do the same for
  the new case. Most of the existing suite follows exactly this pattern —
  read a few existing cases in `test/analyzers.test.js` before writing yours.
- **Run `npm test`** and make sure it's green. CI runs it on every PR across
  a couple of Node versions.
- **Keep the CLI/dashboard untouched if you can.** Detection logic lives in
  `lib/analyzers.js`, which is intentionally free of CLI/process/network
  side effects (see the comment at the top of that file). If your change can
  be made there instead of in `bin/jsrecon.js`, prefer that — it's what
  keeps the logic testable.
- **No new dependencies without discussion.** This project deliberately
  avoids a full JS parser (acorn/esprima/etc.) in favor of a lightweight,
  dependency-free tokenizer (`lib/beautify.js`) used to build a comment/
  string-safe "mask" for structural matching. If you think a case genuinely
  needs real AST analysis, open an issue first to discuss before sending a
  PR that adds a parser dependency — it's a real tradeoff (parse failures on
  malformed/exotic input need a fallback path, and it changes performance on
  large bundles), not a drop-in swap.
- **False positives > false negatives, but both matter.** A detector that's
  too loud gets ignored; one that's silent on real issues is worse. If
  you're tightening a rule, show (in the PR description or the test itself)
  a real-world example of the false positive it fixes, and confirm the
  existing true-positive tests still pass.

## If you touch `lib/beautify.js`

`lib/beautify.js` is also hand-inlined into `lib/ui.js`'s generated
dashboard `<script>` (the dashboard has to be one self-contained HTML file
with no build step). After editing it, run:

```bash
node scripts/inline-beautify.js    # re-inlines it into lib/ui.js
node scripts/check-beautify-inline.js   # verifies the two stay in sync
```

CI doesn't currently check this for you — please run it by hand before
opening the PR.

## Reporting bugs / requesting features

Open a GitHub issue. For a false positive/negative in a detector, include:
- The (minimized, non-sensitive) code snippet that triggered it
- What jsrecon reported
- What you expected instead

## Reporting a security vulnerability in jsrecon itself

Don't open a public issue — see [SECURITY.md](SECURITY.md).

## Code style

Plain, commented JavaScript — no build step, no TypeScript, no linter
config currently enforced. Match the style already in the file you're
editing (the existing code leans on explanatory comments above non-obvious
regexes/heuristics; please do the same for new ones — a regex-based security
tool is only maintainable if the next person can tell *why* a pattern exists
without reverse-engineering it).
