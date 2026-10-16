#!/usr/bin/env node
'use strict';
/**
 * lib/beautify.js is the canonical, unit-testable source for the jump-to-line
 * viewer's client-side JS beautifier. It's inlined by hand into lib/ui.js's
 * generated <script> (escaped for that file's outer template literal —
 * every backslash doubled, every backtick and `${` escaped) rather than
 * required at runtime, because ui.js's output has to be a single
 * self-contained HTML file with no build step for the person running
 * `jsrecon --ui`.
 *
 * This script is a safety net for that hand-inlining: it re-derives what the
 * inlined block *should* look like from the current lib/beautify.js and
 * diffs it against what's actually sitting inside lib/ui.js, so a future
 * edit to one file that forgets the other fails loudly instead of silently
 * drifting. Run it after touching either file:
 *
 *   node scripts/check-beautify-inline.js
 */

const fs = require('fs');
const path = require('path');

const UI_PATH = path.join(__dirname, '..', 'lib', 'ui.js');
const BEAUTIFY_PATH = path.join(__dirname, '..', 'lib', 'beautify.js');

function escapeForTemplateLiteral(s) {
  return s
    .replace(/\\/g, '\\\\')
    .replace(/`/g, '\\`')
    .replace(/\$\{/g, '\\${');
}

function expected() {
  let src = fs.readFileSync(BEAUTIFY_PATH, 'utf8');
  src = src
    .replace(/^'use strict';\n/, '')
    .replace(/\nmodule\.exports = \{[^}]*\};\n?$/, '\n');
  return escapeForTemplateLiteral(src);
}

const ui = fs.readFileSync(UI_PATH, 'utf8');
// Trailing blank lines around the inlined block are cosmetic (they come from
// whatever sits immediately after it in ui.js) and not worth failing over.
const want = expected().replace(/\n+$/, '\n');

if (!ui.includes(want)) {
  console.error('lib/ui.js\'s inlined beautifier is OUT OF SYNC with lib/beautify.js.');
  console.error('Re-run: node scripts/inline-beautify.js');
  process.exit(1);
}

console.log('OK: lib/ui.js\'s inlined beautifier matches lib/beautify.js.');
