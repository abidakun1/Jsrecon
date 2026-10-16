#!/usr/bin/env node
'use strict';
/**
 * (Re-)inlines lib/beautify.js into lib/ui.js's generated client <script>.
 * Idempotent: replaces a previously-inlined block if the markers below are
 * already present, otherwise inserts fresh right before openFileViewer.
 * Run this after editing lib/beautify.js, then verify with
 * `node scripts/check-beautify-inline.js` and re-run the dashboard test
 * suite before shipping.
 */

const fs = require('fs');
const path = require('path');

const UI_PATH = path.join(__dirname, '..', 'lib', 'ui.js');
const BEAUTIFY_PATH = path.join(__dirname, '..', 'lib', 'beautify.js');

const START_MARKER = '// --- Beautifier (lib/beautify.js, inlined) -----------------------------';
const END_MARKER = '// --- end inlined beautifier ---------------------------------------------';

function escapeForTemplateLiteral(s) {
  return s
    .replace(/\\/g, '\\\\')
    .replace(/`/g, '\\`')
    .replace(/\$\{/g, '\\${');
}

let ui = fs.readFileSync(UI_PATH, 'utf8');
let beautifySrc = fs.readFileSync(BEAUTIFY_PATH, 'utf8');

beautifySrc = beautifySrc
  .replace(/^'use strict';\n/, '')
  .replace(/\nmodule\.exports = \{[^}]*\};\n?$/, '\n');

const block =
  START_MARKER + '\n' +
  '// Dependency-free JS "unminifier" for the jump-to-line viewer below. Never\n' +
  '// rewrites token text, only whitespace between tokens, so an original\n' +
  '// offset can be mapped forward into the beautified output (mapOffset) and\n' +
  '// the flagged line/column re-highlighted correctly after reformatting.\n' +
  escapeForTemplateLiteral(beautifySrc) +
  '\n' + END_MARKER + '\n';

const startIdx = ui.indexOf(START_MARKER);
if (startIdx !== -1) {
  const endIdx = ui.indexOf(END_MARKER, startIdx);
  if (endIdx === -1) throw new Error('Found start marker without a matching end marker in lib/ui.js — resolve manually.');
  const endOfBlock = endIdx + END_MARKER.length + 1; // include trailing newline
  ui = ui.slice(0, startIdx) + block + ui.slice(endOfBlock);
  fs.writeFileSync(UI_PATH, ui);
  console.log('Replaced existing inlined beautifier block in lib/ui.js.');
} else {
  const marker = 'async function openFileViewer(f) {';
  const idx = ui.indexOf(marker);
  if (idx === -1) throw new Error('openFileViewer marker not found in lib/ui.js');
  let insertAt = ui.lastIndexOf('/**', idx);
  if (insertAt === -1 || insertAt < idx - 800) insertAt = idx;
  ui = ui.slice(0, insertAt) + block + '\n' + ui.slice(insertAt);
  fs.writeFileSync(UI_PATH, ui);
  console.log('Inserted new inlined beautifier block into lib/ui.js.');
}
