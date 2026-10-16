'use strict';
/**
 * Unit tests for the pure analyzer functions in lib/analyzers.js.
 *
 * Run with: npm test  (or: node --test test/)
 *
 * These exercise analyzePostMessage / analyzeRecon / analyzeSecrets and a
 * few of their supporting helpers directly, with no CLI, no network, and no
 * filesystem beyond the fixture strings written inline below — the whole
 * point of pulling these functions into their own module was to make this
 * possible. Every case here mirrors a real false-positive/false-negative
 * bug found and fixed earlier in this project's history (see the comments
 * on each rule in lib/analyzers.js), so this suite doubles as a regression
 * guard against reintroducing any of them.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const {
  analyzePostMessage,
  analyzeRecon,
  analyzeSecrets,
  shannonEntropy,
  isValidIpv4Octets,
  isInsideStringLiteral,
  classifyOriginCheck,
  analyzeCrossFileTaint,
} = require('../lib/analyzers');

function types(findings) {
  return findings.map((f) => f.type);
}

function findOne(findings, type) {
  const matches = findings.filter((f) => f.type === type);
  assert.equal(matches.length, 1, `expected exactly one ${type}, got ${matches.length}`);
  return matches[0];
}

// --- analyzePostMessage ------------------------------------------------------

test('postMessage: flags a listener with no origin check and a dangerous sink', () => {
  const src = `
    window.addEventListener("message", function (e) {
      eval(e.data);
    });
  `;
  const findings = analyzePostMessage(src, 'a.js');
  assert.ok(types(findings).includes('postmessage-listener-no-origin-check'));
  const sink = findOne(findings, 'postmessage-dangerous-sink');
  assert.match(sink.note, /eval/);
});

test('postMessage: a strict origin check (===) is not flagged as missing', () => {
  const src = `
    window.addEventListener("message", function (e) {
      if (e.origin !== "https://trusted.example.com") return;
      handle(e.data);
    });
  `;
  const findings = analyzePostMessage(src, 'a.js');
  assert.ok(types(findings).includes('postmessage-listener'));
  assert.ok(!types(findings).includes('postmessage-listener-no-origin-check'));
});

test('postMessage: a substring/includes origin check is flagged as weak (bypassable)', () => {
  const src = `
    window.addEventListener("message", function (e) {
      if (e.origin.includes("trusted.com")) handle(e.data);
    });
  `;
  const findings = analyzePostMessage(src, 'a.js');
  assert.ok(types(findings).includes('postmessage-listener-weak-origin-check'));
});

test('postMessage: origin validated via an unresolvable helper is "custom", not "none"', () => {
  const src = `
    window.addEventListener("message", function (e) {
      if (isValidOrigin(e.origin)) handle(e.data);
    });
  `;
  const findings = analyzePostMessage(src, 'a.js');
  assert.ok(types(findings).includes('postmessage-listener-custom-origin-check'));
});

test('postMessage: postMessage(data, "*") is flagged as a wildcard send', () => {
  const src = `child.postMessage({ cmd: "ping" }, '*');`;
  const findings = analyzePostMessage(src, 'a.js');
  findOne(findings, 'postmessage-wildcard-send');
});

test('postMessage: a stray unbalanced brace/paren inside a string literal does not corrupt handler-body or call-argument extraction', () => {
  // Regression test for the naive-brace-counting bug fixed by structural
  // masking: without it, the "}" inside the string below would truncate the
  // handler body before it reaches eval(e.data), and the ")"/"}" inside the
  // postMessage's own string argument would corrupt where that call ends.
  const src = `
    window.addEventListener("message", function (e) {
      var note = "unexpected } stray brace inside a string literal";
      eval(e.data);
    });
    child.postMessage("weird ) unmatched paren and } brace inside a string", '*');
  `;
  const findings = analyzePostMessage(src, 'a.js');
  findOne(findings, 'postmessage-dangerous-sink');
  findOne(findings, 'postmessage-wildcard-send');
});

test('postMessage: WebSocket .onmessage (non-window receiver) is caught and classified', () => {
  const src = `
    const ws = new WebSocket("ws://example.com/socket");
    ws.onmessage = function (e) {
      eval(e.data);
    };
  `;
  const findings = analyzePostMessage(src, 'a.js');
  findOne(findings, 'postmessage-websocket-insecure-url');
  const sink = findOne(findings, 'postmessage-dangerous-sink');
  assert.match(sink.note, /websocket/i);
  // A missing origin check on a WebSocket listener is not the "any origin"
  // window-postMessage risk, so it should NOT produce the medium-severity
  // no-origin-check finding.
  assert.ok(!types(findings).includes('postmessage-listener-no-origin-check'));
});

test('postMessage: BroadcastChannel addEventListener is classified as same-origin, not "no origin check"', () => {
  const src = `
    const bc = new BroadcastChannel("updates");
    bc.addEventListener("message", function (e) {
      el.innerHTML = e.data;
    });
  `;
  const findings = analyzePostMessage(src, 'a.js');
  const sink = findOne(findings, 'postmessage-dangerous-sink');
  assert.match(sink.note, /broadcastchannel/i);
  assert.ok(!types(findings).includes('postmessage-listener-no-origin-check'));
});

test('postMessage: new WebSocket("wss://...") is not flagged as insecure', () => {
  const src = `const ws = new WebSocket("wss://example.com/socket");`;
  const findings = analyzePostMessage(src, 'a.js');
  assert.ok(!types(findings).includes('postmessage-websocket-insecure-url'));
});

test('postMessage: importScripts with a dynamic argument is high severity; static literals are info', () => {
  const dynamic = analyzePostMessage(`importScripts(getScriptUrl());`, 'a.js');
  const f1 = findOne(dynamic, 'postmessage-importscripts');
  assert.equal(f1.severity, 'high');

  const staticLit = analyzePostMessage(`importScripts("vendor.js", "helpers.js");`, 'a.js');
  const f2 = findOne(staticLit, 'postmessage-importscripts');
  assert.equal(f2.severity, 'info');
});

test('postMessage: document.domain assignment is flagged', () => {
  const findings = analyzePostMessage(`document.domain = "example.com";`, 'a.js');
  const f = findOne(findings, 'postmessage-document-domain');
  assert.match(f.note, /example\.com/);
});

test('postMessage: window.open without noopener is flagged; with noopener it is not', () => {
  const unsafe = analyzePostMessage(`window.open(externalUrl, "_blank");`, 'a.js');
  findOne(unsafe, 'postmessage-window-open-no-noopener');

  const safe = analyzePostMessage(`window.open(externalUrl, "_blank", "noopener,noreferrer");`, 'a.js');
  assert.ok(!types(safe).includes('postmessage-window-open-no-noopener'));
});

// --- classifyOriginCheck (unit-level, below the full analyzer) --------------

test('classifyOriginCheck: an unrelated ===/origin comparison elsewhere in the body does not count as a real check', () => {
  // Regression test: classifyOriginCheck must anchor to the actual event
  // object's .origin, not any "origin" identifier anywhere in the body.
  const body = `
    var apiOrigin = config.apiOrigin;
    if (apiOrigin === "https://api.example.com") { /* unrelated */ }
    handle(e.data);
  `;
  assert.equal(classifyOriginCheck(body, ['e']), 'none');
});

// --- analyzeRecon -------------------------------------------------------------

test('recon: extracts a true-positive email and domain', () => {
  const src = `const contact = "support@example.com";`;
  const findings = analyzeRecon(src, 'a.js');
  const email = findOne(findings, 'recon-email');
  assert.equal(email.value, 'support@example.com');
  assert.ok(findings.some((f) => f.type === 'recon-domain' && f.value === 'example.com'));
});

test('recon: retina asset suffixes ("logo@2x.png") are not misread as emails', () => {
  const src = `<img src="logo@2x.png"> <img src="icon@3x.jpg">`;
  const findings = analyzeRecon(src, 'a.js');
  assert.ok(!types(findings).includes('recon-email'));
});

test('recon: a well-formed IPv4 with valid octets is flagged', () => {
  const src = `const server = "203.0.113.42";`;
  const findings = analyzeRecon(src, 'a.js');
  const ip = findOne(findings, 'recon-ipv4');
  assert.equal(ip.value, '203.0.113.42');
});

test('recon: an invalid-octet "IP-shaped" value is not flagged', () => {
  const src = `const bogus = "999.999.999.999";`;
  const findings = analyzeRecon(src, 'a.js');
  assert.ok(!types(findings).includes('recon-ipv4'));
});

test('recon: a version-shaped 4-part number next to version-like context is not flagged as an IP', () => {
  const src = `const appVersion = "16.14.0.1";`;
  const findings = analyzeRecon(src, 'a.js');
  assert.ok(!types(findings).includes('recon-ipv4'));
});

test('isValidIpv4Octets: rejects out-of-range and leading-zero octets', () => {
  assert.equal(isValidIpv4Octets('999.1.1.1'), false);
  assert.equal(isValidIpv4Octets('01.1.1.1'), false);
  assert.equal(isValidIpv4Octets('192.168.1.1'), true);
});

test('isInsideStringLiteral: exact tokenizer-based check across escaped quotes and templates', () => {
  const src = 'const s = "a \\" b { not code } c"; const x = {};';
  const braceInString = src.indexOf('{', src.indexOf('"'));
  const braceInCode = src.lastIndexOf('{');
  assert.equal(isInsideStringLiteral(src, braceInString), true);
  assert.equal(isInsideStringLiteral(src, braceInCode), false);
});

// --- analyzeSecrets -----------------------------------------------------------

test('secrets: flags a well-formed AWS access key ID and Stripe live key', () => {
  // Built by concatenation rather than as one contiguous string literal so
  // this fake-but-correctly-shaped test fixture can't be mistaken for a
  // real leaked credential by GitHub's (or any other) secret scanner when
  // this file is read statically — the concatenation still produces the
  // exact same runtime string analyzeSecrets sees, so the test is
  // unaffected. Please keep it this way rather than "simplifying" it back
  // into one literal — that's exactly what trips push protection.
  const fakeAwsKey = 'AKIA' + 'ABCDEFGHIJKLMNOP';
  const fakeStripeKey = 'sk_' + 'live_' + '51H8xyzAB1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi';
  const src = `
    const AWS_KEY = "${fakeAwsKey}";
    const STRIPE = "${fakeStripeKey}";
  `;
  const findings = analyzeSecrets(src, 'a.js');
  assert.ok(types(findings).includes('secret-aws-access-key-id'));
  assert.ok(types(findings).includes('secret-stripe-key'));
});

test('secrets: common placeholder values are not flagged', () => {
  const src = `
    const password = "changeme";
    const apiKey = "yourApiKey";
    const token = "xxxxxxxxxxxxxxxx";
  `;
  const findings = analyzeSecrets(src, 'a.js');
  assert.equal(findings.length, 0);
});

test('secrets: a lowercase 32-hex string is not misclassified as a Twilio SID (case-sensitive prefix)', () => {
  const src = `const id = "ac99887766554433221100ffeeddccbb";`;
  const findings = analyzeSecrets(src, 'a.js');
  assert.ok(!types(findings).includes('secret-twilio-account-sid'));
});

test('secrets: build/tracking/session IDs are not flagged by the entropy fallback', () => {
  const src = `const buildId = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";`;
  const findings = analyzeSecrets(src, 'a.js');
  assert.equal(findings.length, 0);
});

test('shannonEntropy: low-variety strings score lower than high-entropy random strings', () => {
  const low = shannonEntropy('aaaaaaaaaaaaaaaa');
  const high = shannonEntropy('9f3ac72eb1d40cba5e8f21c6a9034dbf');
  assert.ok(low < high);
});

// --- analyzeCrossFileTaint ----------------------------------------------------

test('cross-file taint: event.data passed to an imported function that eval()s its argument is flagged', () => {
  const bus = {
    filePath: '/proj/bus.js',
    content: `
      function relay(payload) {
        eval(payload);
      }
      module.exports = { relay };
    `,
  };
  const listener = {
    filePath: '/proj/listener.js',
    content: `
      const { relay } = require('./bus');
      window.addEventListener('message', function (e) {
        relay(e.data);
      });
    `,
  };
  const findings = analyzeCrossFileTaint([bus, listener]);
  const f = findOne(findings, 'postmessage-cross-file-sink');
  assert.equal(f.file, listener.filePath);
  assert.equal(f.crossFile, bus.filePath);
  assert.match(f.note, /eval/);
});

test('cross-file taint: follows a local alias of event.data through to the imported call', () => {
  const bus = {
    filePath: '/proj/bus.js',
    content: `
      function relay(payload) { eval(payload); }
      module.exports = { relay };
    `,
  };
  const listener = {
    filePath: '/proj/listener.js',
    content: `
      const { relay } = require('./bus');
      window.addEventListener('message', function (e) {
        const payload = e.data;
        relay(payload);
      });
    `,
  };
  const findings = analyzeCrossFileTaint([bus, listener]);
  findOne(findings, 'postmessage-cross-file-sink');
});

test('cross-file taint: an imported function that does not reach a dangerous sink is not flagged', () => {
  const safe = {
    filePath: '/proj/safe.js',
    content: `
      function sanitize(input) { return String(input).replace(/[<>]/g, ''); }
      module.exports = { sanitize };
    `,
  };
  const listener = {
    filePath: '/proj/listener2.js',
    content: `
      const { sanitize } = require('./safe');
      window.addEventListener('message', function (e) {
        const clean = sanitize(e.data);
        el.textContent = clean;
      });
    `,
  };
  const findings = analyzeCrossFileTaint([safe, listener]);
  assert.equal(findings.filter((f) => f.type === 'postmessage-cross-file-sink').length, 0);
});

test('cross-file taint: a single file (no batch) produces no cross-file findings', () => {
  const only = { filePath: '/proj/only.js', content: `window.addEventListener('message', e => eval(e.data));` };
  assert.deepEqual(analyzeCrossFileTaint([only]), []);
});
