/**
 * Pure, side-effect-free static analysis functions — no network, no
 * filesystem, no CLI/process state. Given the same (content, filePath)
 * input they always return the same findings, which is what makes them
 * cheap to unit test directly (see test/analyzers.test.js) without spinning
 * up the whole CLI or touching a real file/URL. analyzeSourceMaps is the
 * one analyzer that stays in bin/jsrecon.js instead of here — it does real
 * I/O (fetching remote .map files, reading local ones), so it isn't pure
 * the way these are, and that impurity is exactly why it isn't included in
 * this module.
 */
const { tokenize: tokenizeJs } = require('./beautify');

// --- Analyzers ---------------------------------------------------------------

/**
 * Naive brace/paren-depth counting over raw source text breaks the moment a
 * string, template literal, comment, or regex literal contains an
 * unbalanced '{'/'}'/'('/')' — routine in real code ("a comment {like
 * this}", a CSS-in-JS template, a regex character class, a URL string with
 * a path param placeholder). Reusing beautify.js's existing string/comment/
 * regex-aware tokenizer, every non-code span gets "masked" out to
 * same-length blank filler (newlines kept, so line numbers/positions stay
 * exact) before any structural brace/paren matching runs. The mask is only
 * ever used to find *boundaries* — the text ultimately extracted for
 * analysis always comes back from the real, unmasked source at the same
 * offsets, so recon/secret patterns (which specifically want to see inside
 * string literals) are completely unaffected.
 *
 * Single-slot cache: every analyzer processes one file's content at a time
 * and calls this repeatedly for the *same* string reference, so caching
 * just the most recent result avoids re-tokenizing the same file five times
 * per scan without needing a real cache eviction policy.
 */
let _maskCache = null; // { content, mask }

function getStructuralMask(content) {
  if (_maskCache && _maskCache.content === content) return _maskCache.mask;
  let mask;
  try {
    const tokens = tokenizeJs(content);
    const maskable = new Set(['string', 'template', 'linecomment', 'blockcomment', 'regex']);
    const chars = content.split('');
    for (const t of tokens) {
      if (!maskable.has(t.type)) continue;
      for (let i = t.start; i < t.end; i++) {
        if (chars[i] !== '\n') chars[i] = ' ';
      }
    }
    mask = chars.join('');
  } catch (e) {
    // Tokenizer is whitespace/quote-based, not a real parser — on genuinely
    // pathological input, fall back to the raw text rather than crash the
    // scan. Structural matching loses its string/comment safety in that
    // case, but that's strictly the old behavior, not a regression.
    mask = content;
  }
  _maskCache = { content, mask };
  return mask;
}

/**
 * Given the index of a '{' in content, returns the index just past its
 * matching '}' — depth-counted over the comment/string-safe mask so a
 * stray brace inside a string/comment/template can't corrupt the count,
 * while the returned offsets index straight back into the real `content`.
 */
function findMatchingBrace(content, openIdx) {
  const mask = getStructuralMask(content);
  let depth = 0;
  for (let i = openIdx; i < mask.length; i++) {
    const c = mask[i];
    if (c === '{') depth++;
    else if (c === '}') {
      depth--;
      if (depth === 0) return i + 1;
    }
  }
  return Math.min(content.length, openIdx + 3000); // unbalanced — fall back to a cap
}

/**
 * Extracts the first '{...}' block starting at/after idx, returning both the
 * text and its absolute start offset in `content` (the offset is what lets
 * a caller later point a finding at an exact spot *inside* the body, not
 * just at the handler registration). The opening brace itself is located on
 * the mask too, so a '{' sitting inside a preceding string/comment can't be
 * mistaken for the block's real start.
 */
function extractBraceBlock(content, fromIdx) {
  const mask = getStructuralMask(content);
  const braceIdx = mask.indexOf('{', fromIdx);
  if (braceIdx === -1 || braceIdx > fromIdx + 200) return null; // not an inline block nearby
  const end = findMatchingBrace(content, braceIdx);
  return { text: content.slice(braceIdx, end), start: braceIdx };
}

/**
 * Given a bare identifier used as a message handler (addEventListener('message', foo)
 * or window.onmessage = foo), finds foo's declaration anywhere in the file and
 * returns its body (text + absolute start offset), so analysis isn't limited
 * to inline handlers.
 */
function resolveNamedHandlerBody(content, name) {
  if (!name || !/^[A-Za-z_$][A-Za-z0-9_$.]*$/.test(name)) return null;
  // Search the comment/string-safe mask, not the raw text — otherwise
  // `// function onMessage(e) { eval(e.data) }` sitting in a comment (or a
  // string that happens to contain that shape) gets "resolved" as if it
  // were a real declaration. Mask text equals real text everywhere except
  // inside strings/comments/templates/regex literals, and a genuine
  // function declaration is never inside one of those, so this loses
  // nothing for real matches.
  const mask = getStructuralMask(content);
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const patterns = [
    new RegExp(`function\\s+${escaped}\\s*\\(([^)]*)\\)\\s*`, ''),
    new RegExp(`(?:const|let|var)\\s+${escaped}\\s*=\\s*(?:async\\s*)?(?:function)?\\s*\\(([^)]*)\\)\\s*(?:=>\\s*)?`, ''),
    new RegExp(`${escaped}\\s*=\\s*(?:async\\s*)?(?:function)?\\s*\\(([^)]*)\\)\\s*(?:=>\\s*)?`, ''),
  ];
  for (const re of patterns) {
    const m = re.exec(mask);
    if (m) {
      const block = extractBraceBlock(content, m.index + m[0].length - 1);
      // paramsText carries the handler's real parameter name (e.g. "ev")
      // through to the caller, which uses it to widen the event/origin
      // variable alternation beyond the fixed event/evt/e/msg/message list.
      if (block) return { ...block, paramsText: m[1] };
    }
  }
  return null;
}

/**
 * Line + 0-based column for a character offset. On minified/single-line
 * bundles "line" alone is close to useless (the whole file can be one
 * line) — column is what actually lets you jump to the spot in an editor.
 */
function lineAndColumn(content, idx) {
  const lastNewline = content.lastIndexOf('\n', idx - 1);
  const line = content.slice(0, idx).split('\n').length;
  const column = idx - lastNewline - 1;
  return { line, column };
}

/**
 * Snippet of code centered on the actual match, not the start of its line.
 * This is the fix for minified/single-line bundles: `lines[line-1]` is
 * meaningless when "line 2" is the entire 500KB bundle — this instead grabs
 * `contextChars` on either side of the real match position, clamped to the
 * enclosing line, so the returned text is always the code that was matched.
 */
function snippetAround(content, idx, matchLen = 0, contextChars = 90) {
  let lineStart = content.lastIndexOf('\n', idx - 1);
  lineStart = lineStart === -1 ? 0 : lineStart + 1;
  let lineEnd = content.indexOf('\n', idx);
  if (lineEnd === -1) lineEnd = content.length;

  const start = Math.max(lineStart, idx - contextChars);
  const end = Math.min(lineEnd, idx + matchLen + contextChars);
  let snippet = content.slice(start, end);
  if (start > lineStart) snippet = '…' + snippet;
  if (end < lineEnd) snippet = snippet + '…';
  return snippet.trim();
}

const DEFAULT_EVENT_NAMES = ['event', 'evt', 'e', 'msg', 'message'];
const DATA_VAR_RE = '(?:event|evt|e|msg|message)\\s*\\.\\s*data';
const ORIGIN_VAR_RE = '(?:event|evt|e|msg|message)\\s*\\.\\s*origin';

/**
 * The fixed event/evt/e/msg/message list catches the overwhelming majority
 * of handlers, but plenty of real code names its parameter something else
 * entirely — `ev`, `msgEvent`, `postMessageEvent`, `m` — and every one of
 * those was previously invisible to both the origin-check and dangerous-sink
 * scans (a false negative, since the handler's own event.data/.origin usage
 * would spell that custom name, not "event"). Adding the handler's actual
 * first parameter name to the alternation closes that gap without touching
 * the common cases.
 */
function eventVarPattern(extraNames) {
  const names = [...DEFAULT_EVENT_NAMES, ...(extraNames || [])];
  return [...new Set(names)]
    .filter(Boolean)
    .map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('|');
}

/** First parameter's bare name from a param list, or null if it's not a
 *  simple identifier (destructured/defaulted params aren't worth the extra
 *  complexity here — they're rare for message-event handlers) or is already
 *  one of the defaults. */
function firstParamName(paramsText) {
  if (!paramsText) return null;
  const first = paramsText.split(',')[0].trim();
  if (!first) return null;
  const nameOnly = first.split('=')[0].trim();
  if (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(nameOnly) && !DEFAULT_EVENT_NAMES.includes(nameOnly)) {
    return nameOnly;
  }
  return null;
}

/**
 * Finds local names that `event.data` (or evt/e/msg/message.data) gets
 * assigned or destructured into — `var d = e.data`, `const {data} = event`,
 * `const {data: cmd} = e` — so the sink check below isn't limited to code
 * that spells out "event.data" literally at the point of use. This is the
 * single biggest source of missed (false-negative) postmessage-dangerous-
 * sink findings: real handlers almost always pull the payload into a local
 * variable first before doing anything interesting with it.
 */
function findDataAliases(body, extraNames) {
  const varPat = eventVarPattern(extraNames);
  const dataVarRe = `(?:${varPat})\\s*\\.\\s*data`;
  const aliases = new Set();
  const assignRe = new RegExp(`(?:const|let|var)\\s+([A-Za-z_$][A-Za-z0-9_$]*)\\s*=\\s*${dataVarRe}\\b`, 'g');
  let m;
  while ((m = assignRe.exec(body)) !== null) aliases.add(m[1]);

  const destructureRe = new RegExp(`(?:const|let|var)\\s*\\{\\s*data(?:\\s*:\\s*([A-Za-z_$][A-Za-z0-9_$]*))?\\s*\\}\\s*=\\s*(?:${varPat})\\b`, 'g');
  while ((m = destructureRe.exec(body)) !== null) aliases.add(m[1] || 'data');

  return [...aliases];
}

/** Builds the "taint" alternation used by both the origin check and the sink
 *  scan: the raw event.data expression (using whatever the handler's actual
 *  parameter is named, not just the fixed event/evt/e/msg/message list), plus
 *  every local alias discovered by findDataAliases, each escaped and
 *  word-bounded so a short alias name (like "d") can't match as a substring
 *  of something unrelated. */
function dataTaintPattern(aliases, extraNames) {
  const dataVarRe = `(?:${eventVarPattern(extraNames)})\\s*\\.\\s*data`;
  const parts = [dataVarRe, ...aliases.map((a) => `\\b${a.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`)];
  return parts.join('|');
}

/** Classifies an origin check as none / custom (delegated to a helper
 *  function we can't resolve) / weak (bypassable substring match) / strict. */
function classifyOriginCheck(body, extraNames) {
  const originVarRe = `(?:${eventVarPattern(extraNames)})\\s*\\.\\s*origin`;

  // /^https:\/\/(www\.)?trusted\.com$/.test(event.origin) — an anchored
  // regex .test() is as strong as a strict equality check; an unanchored
  // one (no leading ^ / trailing $ right against the closing delimiter) has
  // the same "trusted.com.evil.com" bypass risk as .includes()/.match().
  const regexTestRe = new RegExp(`\\/([^\\n]*?)\\/[gimsuy]*\\s*\\.\\s*test\\s*\\(\\s*${originVarRe}\\s*\\)`);
  const regexTestMatch = regexTestRe.exec(body);
  const anchoredRegexTest = !!(regexTestMatch && /^\^/.test(regexTestMatch[1]) && /\$$/.test(regexTestMatch[1]));
  const unanchoredRegexTest = !!regexTestMatch && !anchoredRegexTest;

  // These two used to be generic `/\.origin\s*(===|!==).../` checks with no
  // requirement that the "origin" belonged to the event/message object at
  // all — an unrelated `apiOrigin === 'foo'` or `location.origin === x`
  // anywhere in the same handler body was enough to mark a listener
  // "strict" even when event.origin itself was never checked. That's a
  // false negative on the actual vulnerability (a real missing-origin-check
  // handler silently classified as safe), so both are now anchored to the
  // handler's own event/origin variable.
  const strict = new RegExp(`${originVarRe}\\s*(===|!==)\\s*['"\`]`).test(body) ||
    new RegExp(`${originVarRe}\\s*\\)\\s*(?:===|!==)`).test(body) ||
    // whitelist.includes(origin) / allowedSet.has(origin)
    new RegExp(`\\[[^\\]]*\\]\\s*\\.\\s*(?:includes|has)\\s*\\(\\s*${originVarRe}\\s*\\)`).test(body) ||
    new RegExp(`(?:ALLOWED|TRUSTED|WHITELIST)[A-Z_]*\\s*\\.\\s*(?:includes|has)\\s*\\(\\s*${originVarRe}\\s*\\)`, 'i').test(body) ||
    anchoredRegexTest;

  const weak = !strict && (
    new RegExp(`${originVarRe}\\s*\\.\\s*(includes|indexOf|startsWith|endsWith)\\s*\\(`).test(body) ||
    new RegExp(`${originVarRe}\\s*\\.\\s*match\\s*\\(`).test(body) ||
    new RegExp(`${originVarRe}\\s*(==|!=)\\s*['"\`]`).test(body) ||
    unanchoredRegexTest
  );

  // Not recognized as strict/weak inline, but the origin is still passed
  // into *some* function — isValidOrigin(e.origin), checkOrigin(e.origin,
  // allowlist) — that we have no way to resolve statically. Previously this
  // fell all the way through to "none" (no origin check), which reads as a
  // much more serious finding than "there's a check here, we just can't see
  // inside it" — a real false-positive-flavored overstatement for a very
  // common real-world pattern (validation factored into a helper).
  const custom = !strict && !weak &&
    new RegExp(`[A-Za-z_$][A-Za-z0-9_$]*\\s*\\([^)]*${originVarRe}[^)]*\\)`).test(body);

  if (strict) return 'strict';
  if (weak) return 'weak';
  if (custom) return 'custom';
  return 'none';
}

/**
 * Looks for event.data (or a local variable it was assigned/destructured
 * into — see findDataAliases) flowing straight into a dangerous sink inside
 * the handler body. Returns each match's position *within body* too, so the
 * caller can point the finding at the actual eval(...)/innerHTML=... call
 * instead of the addEventListener registration line.
 */
function findDangerousSinks(body, extraNames) {
  const taint = dataTaintPattern(findDataAliases(body, extraNames), extraNames);
  const sinkPatterns = [
    { name: 'eval', re: new RegExp(`eval\\s*\\([^)]*(?:${taint})`) },
    { name: 'Function-constructor', re: new RegExp(`new\\s+Function\\s*\\([^)]*(?:${taint})`) },
    { name: 'innerHTML', re: new RegExp(`\\.innerHTML\\s*=[^;]*(?:${taint})`) },
    { name: 'outerHTML', re: new RegExp(`\\.outerHTML\\s*=[^;]*(?:${taint})`) },
    { name: 'insertAdjacentHTML', re: new RegExp(`insertAdjacentHTML\\s*\\([^)]*(?:${taint})`) },
    { name: 'document.write', re: new RegExp(`document\\.write(?:ln)?\\s*\\([^)]*(?:${taint})`) },
    { name: 'jquery-html', re: new RegExp(`\\.html\\s*\\([^)]*(?:${taint})`) },
    { name: 'location-assign', re: new RegExp(`location(?:\\.href)?\\s*=[^;]*(?:${taint})`) },
    { name: 'location.assign', re: new RegExp(`location\\.(?:assign|replace)\\s*\\([^)]*(?:${taint})`) },
    { name: 'settimeout-string', re: new RegExp(`set(?:Timeout|Interval)\\s*\\([^,]*(?:${taint})`) },
    { name: 'postmessage-relay', re: new RegExp(`postMessage\\s*\\([^)]*(?:${taint})[^)]*,\\s*['"\`]\\*['"\`]`) },
  ];
  const found = [];
  for (const s of sinkPatterns) {
    const m = s.re.exec(body);
    if (m) found.push({ name: s.name, localIdx: m.index, matchLen: m[0].length });
  }
  return found;
}

function analyzePostMessage(content, filePath) {
  const findings = [];
  const lines = content.split('\n');
  const lineOf = (idx) => content.slice(0, idx).split('\n').length;
  const mask = getStructuralMask(content);

  // --- Outgoing sends: track simple string-literal variables assigned '*' so
  // postMessage(data, someVar) is still caught when someVar === '*' elsewhere.
  // Runs on the real content (not the mask) — the whole point is inspecting
  // what's *inside* the string literal, which the mask deliberately blanks.
  const wildcardVars = new Set();
  const varAssignRe = /(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*['"`]\*['"`]/g;
  let vm;
  while ((vm = varAssignRe.exec(content)) !== null) wildcardVars.add(vm[1]);

  // --- Channel tracking: WebSocket/BroadcastChannel constructions, so a
  // later `<var>.addEventListener('message', ...)` / `<var>.onmessage = ...`
  // can be classified as coming from that channel type rather than assumed
  // to be a plain window message listener. Also runs on real content (the
  // constructor name and URL literal both live inside what the mask blanks).
  const channelVarKind = new Map(); // varName -> 'websocket' | 'broadcastchannel'
  const wsCtorRe = /(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*new\s+WebSocket\s*\(\s*(['"`])([^'"`]*)\2/g;
  let wsm;
  while ((wsm = wsCtorRe.exec(content)) !== null) {
    channelVarKind.set(wsm[1], 'websocket');
    const url = wsm[3];
    if (/^ws:\/\//i.test(url)) {
      const { line, column } = lineAndColumn(content, wsm.index);
      findings.push({
        type: 'postmessage-websocket-insecure-url',
        severity: 'medium',
        file: filePath,
        line,
        column,
        snippet: snippetAround(content, wsm.index, wsm[0].length),
        note: `new WebSocket("${url}") connects over plaintext ws:// — traffic (and anything relayed into message handlers below) can be intercepted or tampered with on the network. Use wss:// instead.`,
      });
    }
  }
  const bcCtorRe = /(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*new\s+BroadcastChannel\s*\(/g;
  let bcm;
  while ((bcm = bcCtorRe.exec(content)) !== null) channelVarKind.set(bcm[1], 'broadcastchannel');

  // Naming-heuristic fallback for when the declaration is out of scan range
  // or a channel is passed around under a different name (e.g. a parameter).
  function guessChannelKind(varName) {
    if (!varName) return 'window';
    if (channelVarKind.has(varName)) return channelVarKind.get(varName);
    if (/websocket|^ws$|socket/i.test(varName)) return 'websocket';
    if (/broadcastchannel|^bc$/i.test(varName)) return 'broadcastchannel';
    return 'window';
  }

  // Matches any `<anything>.postMessage(` (bracket/computed receivers included,
  // e.g. frames[0].postMessage(...), this.win.postMessage(...)) then reads the
  // call's argument list out to its balanced closing paren. Matched against
  // the mask so a `.postMessage(` spelled out in a comment or string isn't
  // treated as a real call, and the paren/brace depth counting below walks
  // the mask too, so a stray bracket inside one of the call's own string
  // arguments (e.g. a URL literal) can't throw off where the call actually
  // ends. The final argument text is still read back from the real content.
  const sendRe = /\.postMessage\s*\(/g;
  let m;
  while ((m = sendRe.exec(mask)) !== null) {
    const openParenIdx = m.index + m[0].length - 1;
    let depth = 0, closeIdx = -1;
    for (let i = openParenIdx; i < mask.length; i++) {
      const c = mask[i];
      if ('([{'.includes(c)) depth++;
      else if (')]}'.includes(c)) { depth--; if (depth === 0) { closeIdx = i; break; } }
    }
    if (closeIdx === -1) continue;
    const argsTextReal = content.slice(openParenIdx + 1, closeIdx);
    const argsTextMasked = mask.slice(openParenIdx + 1, closeIdx);
    // crude top-level split on the last comma at depth 0 to isolate the
    // targetOrigin arg — depth-counted on the masked text, sliced from real.
    let argDepth = 0, splitAt = -1;
    for (let i = 0; i < argsTextMasked.length; i++) {
      const c = argsTextMasked[i];
      if ('([{'.includes(c)) argDepth++;
      else if (')]}'.includes(c)) argDepth--;
      else if (c === ',' && argDepth === 0) splitAt = i;
    }
    if (splitAt === -1) continue; // no explicit targetOrigin (same-origin default) — not flagged
    const targetOriginArg = argsTextReal.slice(splitAt + 1).trim();
    const isWildcardLiteral = /^['"`]\*['"`]$/.test(targetOriginArg);
    const isWildcardVar = wildcardVars.has(targetOriginArg);
    if (isWildcardLiteral || isWildcardVar) {
      const { line, column } = lineAndColumn(content, m.index);
      findings.push({
        type: 'postmessage-wildcard-send',
        severity: 'info',
        file: filePath,
        line,
        column,
        snippet: snippetAround(content, m.index, closeIdx - m.index + 1),
        context: snippetAround(content, m.index, closeIdx - m.index + 1, 500),
        note: isWildcardVar
          ? `postMessage(..., ${targetOriginArg}) sends to any origin — "${targetOriginArg}" resolves to '*'. Check if the payload is sensitive.`
          : "postMessage(..., '*') sends to any origin — check if the payload is sensitive.",
      });
    }
  }

  // --- Incoming listeners: addEventListener('message', ...) and <receiver>.onmessage = ...
  // Unlike sendRe above, this pattern's own match text includes the quoted
  // string literal 'message' — masking would blank that exact substring out
  // from under the regex, so this one has to run on the real content. (The
  // handler body it leads into is still extracted via extractBraceBlock,
  // which is comment/string-safe.)
  // The addEventListener form is already receiver-agnostic (no prefix
  // required), so `ws.addEventListener('message', fn)` / `bc.addEventListener(...)`
  // were already matched before this change. The .onmessage= form used to
  // require window|self|globalThis; it's now opened up to any identifier so
  // `ws.onmessage = ...` / `bc.onmessage = ...` are caught too, with the
  // receiver captured so the listener can be classified by channel type.
  const listenerRe = /(?:([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*)?addEventListener\s*\(\s*['"]message['"]\s*,\s*(function\s*\([^)]*\)|\([^)]*\)\s*=>|[A-Za-z_$][A-Za-z0-9_$.]*)|([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*onmessage\s*=\s*(function\s*\([^)]*\)|\([^)]*\)\s*=>|[A-Za-z_$][A-Za-z0-9_$.]*)/g;
  while ((m = listenerRe.exec(content)) !== null) {
    const startIdx = m.index;
    const isAddEventListenerForm = m[2] !== undefined;
    const receiverVar = isAddEventListenerForm ? m[1] : m[3];
    const handlerHead = isAddEventListenerForm ? m[2] : m[4];
    const channelKind = guessChannelKind(receiverVar); // 'window' | 'websocket' | 'broadcastchannel'
    const { line, column } = lineAndColumn(content, startIdx);
    const snippet = snippetAround(content, startIdx, m[0].length);

    let block;
    let paramsText = null;
    if (/^function\s*\(/.test(handlerHead) || /=>\s*$/.test(handlerHead) || /^\([^)]*\)\s*=>$/.test(handlerHead)) {
      // Inline function/arrow with a block body right after the match.
      block = extractBraceBlock(content, startIdx + m[0].length - 1);
      const pm = /\(([^)]*)\)/.exec(handlerHead);
      paramsText = pm ? pm[1] : null;
    } else {
      // Bare identifier — go find its real declaration elsewhere in the file.
      block = resolveNamedHandlerBody(content, handlerHead);
      paramsText = block ? block.paramsText : null;
    }
    const body = block ? block.text : content.slice(startIdx, startIdx + 1500);
    const bodyStart = block ? block.start : startIdx;

    // Real handlers name their event parameter all sorts of things besides
    // event/evt/e/msg/message — "ev", "msgEvent", "postMessageEvent" — so
    // the actual parameter name (when it's a plain identifier) is folded
    // into every event.data/event.origin pattern below, not just the fixed
    // default list.
    const extraNames = [firstParamName(paramsText)].filter(Boolean);

    const originCheck = classifyOriginCheck(body, extraNames);
    const dangerousSinks = findDangerousSinks(body, extraNames);

    // The 90-char match-centered `snippet` is only enough to prove a listener
    // exists — it can't show whether the origin check is real or the handler
    // body is dangerous. `context` carries the actual resolved handler source
    // (capped so a giant minified function doesn't blow up the dashboard) so
    // the finding is self-contained: no external file, browser feature, or
    // editor deep-link required just to read the code being flagged.
    const CONTEXT_CAP = 4000;
    const truncated = body.length > CONTEXT_CAP;
    const context = truncated ? body.slice(0, CONTEXT_CAP) + '\n/* …truncated, ' + (body.length - CONTEXT_CAP) + ' more chars — open the file at the line above for the rest */' : body;
    const contextLine = lineAndColumn(content, bodyStart).line;

    // BroadcastChannel messages never cross origins (the browser enforces
    // that), so a missing e.origin check there isn't the same risk as a
    // window postMessage listener accepting any origin — any page that can
    // reach the channel is already same-origin. A WebSocket MessageEvent's
    // .origin isn't a same-origin-policy gate either; the real trust boundary
    // for a socket is the server it's connected to (and the transport, see
    // the insecure-url finding above), not an in-handler origin check. Both
    // get downgraded to an info note instead of the "no origin check" medium
    // finding that's meaningful for window listeners.
    if (originCheck === 'none' && channelKind !== 'window') {
      findings.push({
        type: 'postmessage-listener',
        severity: 'info',
        file: filePath,
        line,
        column,
        snippet,
        context,
        contextLine,
        note: channelKind === 'broadcastchannel'
          ? 'BroadcastChannel message listener — delivery is same-origin only by browser design, so a missing e.origin check here is not a cross-origin risk. Any script able to reach this channel name is already trusted at the origin level; verify the channel name itself isn\'t guessable/shared unintentionally.'
          : 'WebSocket message listener — trust here comes from the server the socket is connected to, not from an e.origin check on the MessageEvent. Verify the WebSocket endpoint and connection (see any ws:// finding above) are trustworthy.',
      });
    } else if (originCheck === 'none') {
      findings.push({
        type: 'postmessage-listener-no-origin-check',
        severity: 'medium',
        file: filePath,
        line,
        column,
        snippet,
        context,
        contextLine,
        note: 'message listener has no origin check in its resolved handler body — verify manually; could accept messages from any origin.',
      });
    } else if (originCheck === 'weak') {
      findings.push({
        type: 'postmessage-listener-weak-origin-check',
        severity: 'medium',
        file: filePath,
        line,
        column,
        snippet,
        context,
        contextLine,
        note: 'origin check uses a substring/pattern match (includes/indexOf/startsWith) — often bypassable, e.g. "trusted.com" also matches "trusted.com.evil.com". Verify it anchors the full origin.',
      });
    } else if (originCheck === 'custom') {
      findings.push({
        type: 'postmessage-listener-custom-origin-check',
        severity: 'info',
        file: filePath,
        line,
        column,
        snippet,
        context,
        contextLine,
        note: 'origin is passed into a helper function this scan can\'t resolve (e.g. isValidOrigin(e.origin)) rather than being checked inline — likely fine, but verify the helper actually validates the full origin.',
      });
    } else {
      findings.push({
        type: 'postmessage-listener',
        severity: 'info',
        file: filePath,
        line,
        column,
        snippet,
        context,
        contextLine,
        note: 'message listener with a strict-looking origin check (===/!== or whitelist.includes(origin)) — verify it is correct.',
      });
    }

    dangerousSinks.forEach((sink) => {
      // Point at the actual sink call (e.g. the eval(...) itself), not the
      // addEventListener registration — that's the line worth jumping to.
      const absIdx = bodyStart + sink.localIdx;
      const { line: sinkLine, column: sinkColumn } = lineAndColumn(content, absIdx);
      findings.push({
        type: 'postmessage-dangerous-sink',
        severity: 'high',
        file: filePath,
        line: sinkLine,
        column: sinkColumn,
        snippet: snippetAround(content, absIdx, sink.matchLen),
        context,
        contextLine,
        contextMatchOffset: truncated && sink.localIdx > CONTEXT_CAP ? null : sink.localIdx,
        contextMatchLen: sink.matchLen,
        note: `event.data appears to flow into ${sink.name} inside a${channelKind !== 'window' ? ` ${channelKind}` : ''} message listener registered at line ${line}${column != null ? `:${column}` : ''} — potential DOM XSS / injection via ${channelKind === 'websocket' ? 'a WebSocket message' : channelKind === 'broadcastchannel' ? 'a BroadcastChannel message' : 'postMessage'}${originCheck === 'none' && channelKind === 'window' ? ' (and there is no origin check, so this looks reachable from any site)' : ''}. Verify manually.`,
      });
    });
  }

  // --- importScripts(...): synchronous script loading inside a Worker.
  // Structure (call + balanced parens) is found on the mask so a stray
  // bracket inside one of the arguments can't corrupt where the call ends;
  // the argument text itself is read back from real content since that's
  // what decides whether it's a static, auditable literal or dynamic input.
  const importScriptsRe = /\bimportScripts\s*\(/g;
  while ((m = importScriptsRe.exec(mask)) !== null) {
    const openParenIdx = m.index + m[0].length - 1;
    let depth = 0, closeIdx = -1;
    for (let i = openParenIdx; i < mask.length; i++) {
      const c = mask[i];
      if ('([{'.includes(c)) depth++;
      else if (')]}'.includes(c)) { depth--; if (depth === 0) { closeIdx = i; break; } }
    }
    if (closeIdx === -1) continue;
    const argsText = content.slice(openParenIdx + 1, closeIdx).trim();
    // Every top-level arg a plain string literal (comma-split on the mask so
    // commas inside a literal's own content don't split it)?
    const argsMasked = mask.slice(openParenIdx + 1, closeIdx);
    const parts = [];
    let pd = 0, last = 0;
    for (let i = 0; i < argsMasked.length; i++) {
      const c = argsMasked[i];
      if ('([{'.includes(c)) pd++;
      else if (')]}'.includes(c)) pd--;
      else if (c === ',' && pd === 0) { parts.push(argsText.slice(last, i).trim()); last = i + 1; }
    }
    parts.push(argsText.slice(last).trim());
    const allStaticLiterals = parts.every((p) => /^['"`][^'"`]*['"`]$/.test(p));
    const anchorIdx = m.index;
    const { line, column } = lineAndColumn(content, anchorIdx);
    findings.push({
      type: 'postmessage-importscripts',
      severity: allStaticLiterals ? 'info' : 'high',
      file: filePath,
      line,
      column,
      snippet: snippetAround(content, anchorIdx, closeIdx - anchorIdx + 1),
      context: snippetAround(content, anchorIdx, closeIdx - anchorIdx + 1, 500),
      note: allStaticLiterals
        ? `importScripts(${argsText}) loads worker script(s) from static, auditable path(s) — low risk, but confirm those files aren't user-writable.`
        : `importScripts(${argsText}) loads worker script(s) from a non-literal (computed) source — if any part of that value can be influenced by an attacker (URL params, postMessage input, etc.), this is remote code execution inside the worker. Verify manually.`,
    });
  }

  // --- document.domain = "...": explicitly relaxes the same-origin policy,
  // letting sibling subdomains read/write each other's DOM and (in older
  // browsers) reducing postMessage origin isolation. Runs on real content —
  // the RHS string value is exactly what needs inspecting.
  const docDomainRe = /document\s*\.\s*domain\s*=\s*['"`]([^'"`]*)['"`]/g;
  while ((m = docDomainRe.exec(content)) !== null) {
    const { line, column } = lineAndColumn(content, m.index);
    findings.push({
      type: 'postmessage-document-domain',
      severity: 'medium',
      file: filePath,
      line,
      column,
      snippet: snippetAround(content, m.index, m[0].length),
      note: `document.domain = "${m[1]}" relaxes the same-origin policy so any page on a sibling subdomain of "${m[1]}" can script this page directly (and vice versa) — a compromise of any sibling becomes a compromise of this origin. Verify this is intentional and that every subdomain is equally trusted.`,
    });
  }

  // --- window.open(url, name, features) missing 'noopener' in its features
  // string: the opened page can reach back via window.opener and navigate
  // this tab (reverse tabnabbing), especially risky when the target URL is
  // external or attacker-influenced. Structure on the mask, values from
  // real content, same pattern as the calls above.
  const winOpenRe = /window\s*\.\s*open\s*\(/g;
  while ((m = winOpenRe.exec(mask)) !== null) {
    const openParenIdx = m.index + m[0].length - 1;
    let depth = 0, closeIdx = -1;
    for (let i = openParenIdx; i < mask.length; i++) {
      const c = mask[i];
      if ('([{'.includes(c)) depth++;
      else if (')]}'.includes(c)) { depth--; if (depth === 0) { closeIdx = i; break; } }
    }
    if (closeIdx === -1) continue;
    const argsText = content.slice(openParenIdx + 1, closeIdx);
    const argsMasked = mask.slice(openParenIdx + 1, closeIdx);
    const parts = [];
    let pd = 0, last = 0;
    for (let i = 0; i < argsMasked.length; i++) {
      const c = argsMasked[i];
      if ('([{'.includes(c)) pd++;
      else if (')]}'.includes(c)) pd--;
      else if (c === ',' && pd === 0) { parts.push(argsText.slice(last, i).trim()); last = i + 1; }
    }
    parts.push(argsText.slice(last).trim());
    const featuresArg = parts[2] || '';
    const hasNoopenerLiteral = /noopener/i.test(featuresArg);
    // Only flag when there's no features string at all, or one that's a
    // literal we can actually inspect and it lacks noopener — a computed/
    // variable features string is left alone rather than guessed at.
    const featuresIsLiteralOrEmpty = featuresArg === '' || /^['"`][^'"`]*['"`]$/.test(featuresArg);
    if (featuresIsLiteralOrEmpty && !hasNoopenerLiteral) {
      const { line, column } = lineAndColumn(content, m.index);
      findings.push({
        type: 'postmessage-window-open-no-noopener',
        severity: 'low',
        file: filePath,
        line,
        column,
        snippet: snippetAround(content, m.index, closeIdx - m.index + 1),
        note: `window.open(${parts[0] ? parts[0] : ''}${parts[0] ? ', …' : ''}) doesn't include "noopener" in its features string — the opened page gets a window.opener reference back to this page and can navigate it (reverse tabnabbing), which matters most if the opened URL is external or attacker-influenced. Add "noopener" (and usually "noreferrer") to the features string.`,
      });
    }
  }

  return findings;
}


const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];

/**
 * Best-effort HTTP method for one occurrence of an API path literal, from
 * whatever calling convention it's sitting in — this is regex-over-text, not
 * a parser, so it only recognizes a handful of common shapes:
 *   axios.post('/api/x')            — method chained directly onto the call
 *   xhr.open('POST', '/api/x')      — method is the argument just before it
 *   fetch('/api/x', {method:'POST'})  or  axios({method:'POST', url:'/api/x'})
 *                                    — an explicit method: '...' key anywhere
 *                                      in the same call/object literal
 * Returns an uppercase verb, or null when nothing nearby says one (the UI
 * shows that as "Not defined" rather than guessing).
 */
function detectHttpMethodAt(content, valueIdx, valueLen) {
  const WINDOW = 150;

  let before = content.slice(Math.max(0, valueIdx - WINDOW), valueIdx);
  // Don't reach back past the start of this statement — otherwise a long
  // minified one-liner risks picking up an unrelated call several
  // statements earlier that happens to sit within the window.
  const semiBefore = before.lastIndexOf(';');
  if (semiBefore !== -1) before = before.slice(semiBefore + 1);

  let after = content.slice(valueIdx + valueLen, Math.min(content.length, valueIdx + valueLen + WINDOW));
  const semiAfter = after.indexOf(';');
  if (semiAfter !== -1) after = after.slice(0, semiAfter);

  // 1. Chained directly onto the call: axios.post('/x'), client.get(`/x`)
  // `before` ends right where the path's own characters start, i.e. just
  // *after* its opening quote/backtick — so that quote has to be allowed
  // between the "(" and the end of the window, or this never matches.
  let m = before.match(/\.(get|post|put|delete|patch|head|options)\s*\(\s*['"`]?\s*$/i);
  if (m) return m[1].toUpperCase();

  // 2. XHR-style: the method is the argument immediately before this one —
  // xhr.open('POST', '/x') — same opening-quote wrinkle as above.
  m = before.match(/\.open\s*\(\s*['"]([A-Za-z]+)['"]\s*,\s*['"`]?\s*$/i);
  if (m && HTTP_METHODS.includes(m[1].toUpperCase())) return m[1].toUpperCase();

  // 3. An explicit method: '...' key in the same call/object literal, on
  // either side of the path (key order varies: fetch(url, {method}) puts it
  // after; axios({method, url}) can put it before).
  m = before.match(/\bmethod\s*[:=]\s*['"]([A-Za-z]+)['"]/i) || after.match(/\bmethod\s*[:=]\s*['"]([A-Za-z]+)['"]/i);
  if (m && HTTP_METHODS.includes(m[1].toUpperCase())) return m[1].toUpperCase();

  return null;
}

/**
 * Scans every occurrence of `value` in the file (not just the first — the
 * same endpoint is very often called with more than one verb, e.g. GET to
 * read and POST to write) and merges whatever methods are recognized at
 * each spot. Capped so a path repeated hundreds of times in a huge bundle
 * doesn't turn into a full re-scan of the file.
 */
function detectHttpMethodsForValue(content, value) {
  const methods = new Set();
  let searchIdx = 0;
  for (let seen = 0; seen < 25; seen++) {
    const idx = content.indexOf(value, searchIdx);
    if (idx === -1) break;
    const method = detectHttpMethodAt(content, idx, value.length);
    if (method) methods.add(method);
    searchIdx = idx + value.length;
  }
  return methods.size ? [...methods].sort().join(', ') : null;
}

/**
 * Recon extraction — pattern matching over static text, covering the same
 * fields jsmon's `-recon field=<name>` exposes (apiPaths, urls/jsurls,
 * extractedDomains, ip, emails, s3Buckets, gqlQueries/Mutations/Fragments,
 * param, npmPackages, socialUrls, portUrls) plus dedup so a value that
 * appears 50 times in a minified bundle is reported once per file.
 */
/**
 * Cheap, bounded "are we inside a string literal at this offset" check —
 * not a real parser, just a quote-state scan from the nearest statement/
 * block boundary up to idx. Exists specifically to keep patterns that only
 * make sense in string form (port-url) from matching bare code, e.g. the
 * object-literal key:value pairs (`{width:1920,height:1080}`) that are
 * everywhere in minified JS and look identical to `host:port` shapes
 * once you drop the surrounding quotes.
 */
// Single-slot cache, same rationale as getStructuralMask: one file's content
// gets queried many times in a row (once per port-url candidate) before the
// next file's content ever shows up.
let _stringSpanCache = null; // { content, spans: [[start,end], ...] sorted by start }

function getStringLiteralSpans(content) {
  if (_stringSpanCache && _stringSpanCache.content === content) return _stringSpanCache.spans;
  let spans = [];
  try {
    const tokens = tokenizeJs(content);
    spans = tokens
      .filter((t) => t.type === 'string' || t.type === 'template')
      .map((t) => [t.start, t.end]);
  } catch (e) {
    spans = [];
  }
  _stringSpanCache = { content, spans };
  return spans;
}

/**
 * True when idx falls inside an actual string or template literal token —
 * built on beautify.js's tokenizer instead of a bounded quote-state scan, so
 * it's exact about escaped quotes, multi-line strings, and nested
 * `${...}` template expressions rather than a "good enough within ~3000
 * chars of the nearest statement boundary" approximation. Exists specifically
 * to keep patterns that only make sense in string form (port-url) from
 * matching bare code, e.g. the object-literal key:value pairs
 * (`{width:1920,height:1080}`) that are everywhere in minified JS and look
 * identical to `host:port` shapes once you drop the surrounding quotes.
 */
function isInsideStringLiteral(content, idx) {
  const spans = getStringLiteralSpans(content);
  let lo = 0, hi = spans.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [start, end] = spans[mid];
    if (idx < start) hi = mid - 1;
    else if (idx >= end) lo = mid + 1;
    else return true;
  }
  return false;
}

/** True for a well-formed dotted-quad where every octet is a valid 0-255
 *  byte — the previous \d{1,3} pattern happily matched garbage like
 *  "999.999.999.999" or a 4-part version/build number. */
function isValidIpv4Octets(value) {
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    if (p.length > 1 && p[0] === '0') return false; // "01" isn't a real octet either
    const n = Number(p);
    return n >= 0 && n <= 255;
  });
}

// A 4-part dotted number that's octet-valid (0-255 each part) is still
// ambiguous — "16.14.0.1" reads exactly like a real IP but is just as often
// a build/version/release number sitting next to a matching variable name.
// No regex fix disambiguates that; the variable name right next to it is
// the only signal available, same trick used for the secret-entropy fallback.
const VERSION_LIKE_CONTEXT = /version|build|release|semver|revision|schema/i;

// "logo@2x.png", "icon@3x.jpg" — the retina-asset naming convention used
// throughout bundled web app JS matches the email regex perfectly (local
// part "logo", domain "2x", "tld" "png"/"jpg"/etc.), and is one of the most
// common false positives the email field produces in practice.
const EMAIL_ASSET_SUFFIX_RE = /^[0-9]+x$/i;

function analyzeRecon(content, filePath) {
  const findings = [];
  const seen = new Set();

  const SOCIAL_HOSTS = /(?:facebook|twitter|x|linkedin|instagram|youtube|tiktok|t\.me|telegram|discord|reddit)\.com|t\.me\/|discord\.gg\//i;

  const patterns = [
    { field: 'email', re: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g },
    { field: 'ipv4', re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g },
    {
      field: 'domain',
      re: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|dev|app|co|ai|gov|edu|sh|xyz|cloud)\b/g,
    },
    {
      field: 'url',
      // Any full http(s) URL literal in the file (jsmon's extractedUrls/jsurls).
      re: /https?:\/\/[a-zA-Z0-9.\-]+(?::\d+)?(?:\/[a-zA-Z0-9\-._~%!$&'()*+,;=:@/]*)?/g,
    },
    {
      field: 'social-url',
      re: /https?:\/\/(?:www\.)?(?:facebook|twitter|x|linkedin|instagram|youtube|tiktok)\.com\/[a-zA-Z0-9_./?=&-]*/gi,
    },
    {
      field: 'api-path',
      // Quoted strings that look like an API/endpoint path: /api/..., /v1/..., /graphql, etc.
      re: /['"`](\/(?:api|v[0-9]+|graphql|internal|admin|rest|rpc|gateway|service|backend|webhook|oauth)\/[a-zA-Z0-9/_\-{}.]*)['"`]/g,
      group: 1,
    },
    {
      field: 'aws-s3-bucket',
      re: /\b[a-zA-Z0-9.\-]+\.s3(?:[.-][a-zA-Z0-9-]+)?\.amazonaws\.com\b|\bs3:\/\/[a-zA-Z0-9.\-]+\b/g,
    },
    {
      field: 'port-url',
      // host:port pairs that look like an internal service reference, e.g.
      // localhost:8080, 10.0.0.5:5432, internal-api:3000 (guards against
      // matching plain numbers/timestamps by requiring a hostname-like prefix).
      re: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9-]+)*):(\d{2,5})\b(?=["'`\s,)/])/g,
    },
    {
      field: 'gql-query',
      re: /\b(?:query|Query)\s+([A-Za-z_][A-Za-z0-9_]*)\s*[({]/g,
      group: 1,
    },
    {
      field: 'gql-mutation',
      re: /\bmutation\s+([A-Za-z_][A-Za-z0-9_]*)\s*[({]/g,
      group: 1,
    },
    {
      field: 'gql-fragment',
      re: /\bfragment\s+([A-Za-z_][A-Za-z0-9_]*)\s+on\s+[A-Za-z_][A-Za-z0-9_]*/g,
      group: 1,
    },
    {
      field: 'npm-package',
      // require('pkg') / import ... from 'pkg' — only non-relative specifiers
      re: /(?:require\(|from\s+)['"](?!\.{1,2}\/|\/)([@a-zA-Z0-9][a-zA-Z0-9_.\-/]*)['"]/g,
      group: 1,
    },
  ];

  for (const { field, re, group } of patterns) {
    let m;
    while ((m = re.exec(content)) !== null) {
      const value = group ? m[group] : m[0];
      if (!value) continue;
      const dedupeKey = `${field}:${value}`;
      if (seen.has(dedupeKey)) continue;
      // Offset the reported position to the captured group itself when the
      // pattern uses one (e.g. gql-query's function name), not the whole match.
      const valueIdx = group ? content.indexOf(value, m.index) : m.index;

      if (field === 'ipv4') {
        if (!isValidIpv4Octets(value)) continue; // e.g. "999.999.999.999"
        // Bounded to the current statement/line — an unrelated comment or
        // statement just before this one shouldn't be able to suppress it.
        let ipContext = content.slice(Math.max(0, valueIdx - 40), valueIdx);
        const ipBoundary = Math.max(ipContext.lastIndexOf(';'), ipContext.lastIndexOf('\n'));
        if (ipBoundary !== -1) ipContext = ipContext.slice(ipBoundary + 1);
        if (VERSION_LIKE_CONTEXT.test(ipContext)) continue; // e.g. buildVersion = "16.14.0.1"
      }
      if (field === 'port-url' && !isInsideStringLiteral(content, valueIdx)) continue; // e.g. {width:1920,height:1080} object-literal keys
      if (field === 'domain') {
        // Bare property-access chains ending in a word that also happens to
        // be a short TLD — window.app, this.dev, store.co, router.io — are
        // everywhere in real JS and match this pattern identically to an
        // actual domain once you're only looking at dotted text. A genuine
        // domain reference is essentially always inside a string literal (or
        // a comment, which this same bounded quote-state scan also treats as
        // "outside" — an acceptable trade since code far outweighs comments
        // as a source of noise here).
        if (!isInsideStringLiteral(content, valueIdx)) continue;
      }
      if (field === 'email') {
        const atIdx = value.lastIndexOf('@');
        const firstLabel = value.slice(atIdx + 1).split('.')[0];
        if (EMAIL_ASSET_SUFFIX_RE.test(firstLabel)) continue; // e.g. "logo@2x.png"
      }

      seen.add(dedupeKey);
      const { line, column } = lineAndColumn(content, valueIdx);
      const finding = {
        type: `recon-${field}`,
        field,
        severity: 'info',
        file: filePath,
        line,
        column,
        value,
        snippet: snippetAround(content, valueIdx, value.length),
      };
      if (field === 'api-path') {
        // null when nothing nearby says a verb — rendered as "Not defined"
        // rather than guessing.
        finding.method = detectHttpMethodsForValue(content, value);
      }
      findings.push(finding);
    }
  }

  // url-param: query-string parameter names pulled from every recon-url/social-url value.
  const urlParamsSeen = new Set();
  findings
    .filter((f) => f.field === 'url')
    .forEach((f) => {
      try {
        const u = new URL(f.value);
        for (const key of u.searchParams.keys()) {
          const dedupeKey = `param:${key}`;
          if (urlParamsSeen.has(dedupeKey)) continue;
          urlParamsSeen.add(dedupeKey);
          findings.push({
            type: 'recon-url-param',
            field: 'param',
            severity: 'info',
            file: filePath,
            line: f.line,
            column: f.column,
            value: key,
            snippet: f.snippet,
          });
        }
      } catch {
        // not a parseable absolute URL, skip
      }
    });

  return findings;
}

/**
 * Precision filters shared by every secret rule below (named-prefix rules
 * and the entropy fallback alike). These only ever REMOVE a candidate —
 * never widen a rule's matches — so they can't hide a value none of the
 * rules would otherwise have flagged; they exist because the previous
 * scan pass kept surfacing the same handful of non-secret shapes across
 * real bundles: literal placeholder text, standard UUIDs used as tracking/
 * correlation/request IDs, repeated-character or sequential filler, and
 * generic hash-like config values (build ids, cache-busting hashes, etc.).
 */

// Standard UUID/GUID: random-looking hex that reliably shows up throughout
// bundled JS as tracking/correlation/session/request/analytics/feature-flag
// IDs — not secrets, but easily high-entropy enough to trip the fallback.
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

// Values developers actually leave in place-of-a-secret: docs, examples,
// test fixtures, Storybook/mock data, and boilerplate scaffolding. Matched
// case-insensitively against the WHOLE value (not a substring), so a real
// secret that merely contains one of these words as part of a longer random
// string is untouched.
const PLACEHOLDER_VALUES = new Set([
  'yourapikey', 'your_api_key', 'your-api-key', 'youraccesskey', 'your_access_key',
  'yoursecret', 'your_secret', 'your-secret', 'yourtoken', 'your_token', 'your-token',
  'yourpassword', 'your_password', 'insertkeyhere', 'insert_key_here', 'insertapikeyhere',
  'insert_your_key_here', 'replaceme', 'replace_me', 'replace-me', 'changeme', 'change_me',
  'change-me', 'changethis', 'todo', 'todofillmein', 'fixme', 'notset', 'not_set', 'n/a',
  'none', 'null', 'undefined', 'nil', 'test', 'testing', 'testkey', 'test_key', 'testtoken',
  'test_token', 'testsecret', 'test_secret', 'testpassword', 'test_password', 'demo',
  'demokey', 'sample', 'samplekey', 'sample_key', 'example', 'examplekey', 'example_key',
  'placeholder', 'dummy', 'dummykey', 'dummy_key', 'fake', 'fakekey', 'fake_key', 'mock',
  'mockkey', 'mock_key', 'mocktoken', 'mock_token', 'foobar', 'foobarbaz', 'password',
  'password123', 'passw0rd', 'qwerty123', 'admin123', 'letmein', 'letmein123', 'secret123',
  'mysecret', 'mytoken', 'myapikey', 'my_api_key', 'abcdefgh', 'abcdefghij', '12345678',
  '123456789', '1234567890',
]);

function isLikelyPlaceholderOrNonSecret(value) {
  if (!value) return true;
  const normalized = value.toLowerCase().replace(/[\s_-]/g, '');
  if (PLACEHOLDER_VALUES.has(normalized) || PLACEHOLDER_VALUES.has(value.toLowerCase())) return true;
  if (/^(.)\1{6,}$/.test(value)) return true; // e.g. "xxxxxxxxxxxx", "00000000000"
  if (/^0123456789|^123456789|^abcdefghijklmnop/i.test(value)) return true; // sequential filler
  if (UUID_RE.test(value)) return true; // tracking/correlation/session/request/feature-flag IDs
  return false;
}

// Extra context words (beyond the SRI/webpack ones already covered) that
// mark a high-entropy-looking value as a non-secret identifier rather than
// a hash denylist entry — build/version/analytics/tracing IDs are randomly
// generated and legitimately high-entropy, but are not secrets.
// No \b anchors: these need to match inside camelCase/PascalCase identifiers
// too (gitCommit, buildId, sessionId, ...), where there's no actual word
// boundary between the preceding word and the keyword.
const NON_SECRET_ID_CONTEXT = /commit|git[-_]?sha|git[-_]?hash|build[-_]?id|version[-_]?hash|release[-_]?id|correlation[-_]?id|trace[-_]?id|request[-_]?id|session[-_]?id|device[-_]?id|install[-_]?id|analytics[-_]?id|ga[-_]?id|amplitude|segment[-_]?id|uuid|guid|idempotency/i;

/**
 * Secret detection: common high-confidence patterns for cloud keys, tokens,
 * and generic "key/secret/token = '...'" assignments. Regex-based, same as
 * most public secret scanners (gitleaks/trufflehog-style rules), just local.
 */
function analyzeSecrets(content, filePath) {
  const findings = [];

  const rules = [
    { name: 'aws-access-key-id', severity: 'high', re: /\bAKIA[0-9A-Z]{16}\b/g },
    { name: 'aws-secret-access-key', severity: 'high', re: /aws_secret_access_key\s*[:=]\s*['"]([A-Za-z0-9/+=]{40})['"]/gi, group: 1 },
    { name: 'google-api-key', severity: 'high', re: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
    { name: 'slack-token', severity: 'high', re: /\bxox[baprs]-[0-9A-Za-z-]{10,48}\b/g },
    { name: 'slack-webhook-url', severity: 'high', re: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]{6,}\/B[A-Za-z0-9]{6,}\/[A-Za-z0-9]{16,}/g },
    { name: 'github-token', severity: 'high', re: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g },
    { name: 'gitlab-token', severity: 'high', re: /\bglpat-[A-Za-z0-9\-_]{20}\b/g },
    { name: 'stripe-key', severity: 'high', re: /\bsk_(live|test)_[0-9a-zA-Z]{16,247}\b/g },
    { name: 'openai-api-key', severity: 'high', re: /\bsk-[A-Za-z0-9]{20,}\b/g },
    { name: 'jwt', severity: 'medium', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
    {
      name: 'private-key-block',
      severity: 'high',
      re: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    },
    // --- Provider-specific tokens (closer to gitleaks/trufflehog coverage) ---
    // Case-sensitive prefix (real Twilio SIDs are always uppercase AC/SK
    // followed by lowercase hex) — the previous case-insensitive version
    // matched any lowercase "ac"/"sk" + 32 hex chars, which is common noise
    // in minified identifiers and hash-derived variable names.
    { name: 'twilio-account-sid', severity: 'medium', re: /\bAC[a-f0-9]{32}\b/g },
    { name: 'twilio-api-key', severity: 'high', re: /\bSK[a-f0-9]{32}\b/g },
    { name: 'sendgrid-api-key', severity: 'high', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
    { name: 'mailgun-api-key', severity: 'high', re: /\bkey-[0-9a-zA-Z]{32}\b/g },
    // This dashed hex-triplet shape has no distinctive prefix of its own, so
    // it's only trustworthy with "mailgun" actually nearby — otherwise it's
    // indistinguishable from any other dash-joined hash/id triplet.
    { name: 'mailgun-api-key', severity: 'medium', re: /\b[0-9a-f]{32}-[0-9a-f]{8}-[0-9a-f]{8}\b/g, contextRequired: /mailgun/i },
    {
      name: 'heroku-api-key',
      severity: 'high',
      re: /heroku[_-]?api[_-]?key\s*[:=]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?/gi,
      group: 1,
    },
    { name: 'npm-token', severity: 'high', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
    { name: 'firebase-cloud-messaging-key', severity: 'high', re: /\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b/g },
    {
      name: 'azure-storage-account-key',
      severity: 'high',
      re: /AccountKey\s*=\s*([A-Za-z0-9+/]{86}==)/g,
      group: 1,
    },
    { name: 'azure-sas-token', severity: 'medium', re: /\bsv=\d{4}-\d{2}-\d{2}&s[srp]=[A-Za-z0-9&%=._-]{20,}/g },
    { name: 'digitalocean-token', severity: 'high', re: /\bdop_v1_[a-f0-9]{64}\b/g },
    { name: 'mailchimp-api-key', severity: 'medium', re: /\b[0-9a-f]{32}-us\d{1,2}\b/g },
    {
      name: 'generic-secret-assignment',
      severity: 'medium',
      re: /\b(api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*['"]([A-Za-z0-9\-_./+=]{8,80})['"]/gi,
      group: 2,
      // The broadest, least-qualified rule in the set (any variable merely
      // *named* key/secret/token/password) — the two extra gates below cut
      // its false-positive rate specifically, without touching the
      // provider-prefixed rules above, which are already narrow enough not
      // to need them.
      minEntropy: 2.5,
      skipIfQualifiedBy: /\b(mock|fake|test|example|sample|dummy|placeholder|demo|default|stub|fixture)\b/i,
      qualifierWindow: 20,
    },
  ];

  const foundValues = new Set();

  for (const rule of rules) {
    let m;
    while ((m = rule.re.exec(content)) !== null) {
      const value = rule.group ? m[rule.group] : m[0];
      // These three checks are judgments about the VALUE (or the text
      // immediately around where it's assigned) that hold true no matter
      // which rule re-discovers it — so once one of them says "this literal
      // string is a placeholder/test value", we remember it in foundValues
      // too, or the unqualified entropy fallback below would just re-flag
      // the exact same string a moment later under a different finding
      // type, undoing the suppression entirely.
      if (isLikelyPlaceholderOrNonSecret(value)) { foundValues.add(value); continue; }
      if (rule.minEntropy != null && shannonEntropy(value) < rule.minEntropy) { foundValues.add(value); continue; }
      if (rule.qualifierWindow != null) {
        const before = content.slice(Math.max(0, m.index - rule.qualifierWindow), m.index);
        if (rule.skipIfQualifiedBy.test(before)) { foundValues.add(value); continue; }
      }
      // contextRequired is different: it's a judgment about THIS OCCURRENCE
      // (is "mailgun" mentioned near this particular match?), not the value
      // itself, so it must NOT feed foundValues — a genuine key logged once
      // with provider context and again without it should still be caught
      // by the entropy fallback on the second occurrence.
      if (rule.contextRequired) {
        const context = content.slice(Math.max(0, m.index - 80), m.index + m[0].length + 80);
        if (!rule.contextRequired.test(context)) continue;
      }
      // When the rule captures a group (e.g. the key value inside quotes),
      // point at the group itself rather than the start of the whole match
      // (which could be the "apiKey:" label several characters earlier).
      const valueIdx = rule.group ? content.indexOf(value, m.index) : m.index;
      const { line, column } = lineAndColumn(content, valueIdx);
      foundValues.add(value);
      findings.push({
        type: `secret-${rule.name}`,
        severity: rule.severity,
        file: filePath,
        line,
        column,
        value,
        snippet: snippetAround(content, valueIdx, value.length),
        note: 'Possible secret — verify manually before reporting; may be a placeholder/example value.',
      });
    }
  }

  findHighEntropySecrets(content, foundValues).forEach((f) => {
    findings.push({ ...f, file: filePath });
  });

  return findings;
}

/**
 * Fallback for anything the named rules above miss: quoted string literals
 * that *look* like a random token/key (hex or base64-ish charset, long
 * enough) and score high on Shannon entropy, the same heuristic
 * TruffleHog/Gitleaks fall back to once their known-prefix rules don't hit.
 * Skips values already caught by a named rule, and filters out the most
 * common false-positive sources in bundled JS: SRI hashes, webpack chunk/
 * content hashes, and source-map references — all of which are legitimately
 * high-entropy but are not secrets.
 */
function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const ENTROPY_CONTEXT_DENYLIST = /integrity|sha256-|sha384-|sha512-|contenthash|chunkhash|sourcemappingurl|__webpack_require__|content-hash/i;

function findHighEntropySecrets(content, foundValues, maxFindings = 20) {
  const results = [];
  // hex-charset and base64-ish-charset candidates, each with its own
  // entropy bar since their theoretical max differs (hex maxes out at 4
  // bits/char, base64 at ~6) — a plain hash (low real-world variety per
  // position) still scores lower than truly random key material.
  const candidateRe = /['"`]([A-Za-z0-9+/_-]{20,100}=?=?)['"`]/g;
  let m;
  while ((m = candidateRe.exec(content)) !== null && results.length < maxFindings) {
    const value = m[1];
    if (foundValues.has(value)) continue; // already flagged by a named rule
    if (/^\d+$/.test(value)) continue; // pure numbers (timestamps, ids)
    // Standard UUIDs (tracking/correlation/session/request/feature-flag IDs)
    // and other common placeholder/filler shapes are legitimately
    // high-entropy but not secrets — see isLikelyPlaceholderOrNonSecret.
    if (isLikelyPlaceholderOrNonSecret(value)) continue;

    const isHex = /^[a-fA-F0-9]+$/.test(value);
    const isBase64ish = /^[A-Za-z0-9+/_-]+=*$/.test(value);
    const entropy = shannonEntropy(value);
    const threshold = isHex ? 3.6 : isBase64ish ? 4.3 : 4.0;
    if (entropy < threshold) continue;

    // Skip the well-known high-entropy-but-not-a-secret sources: look at
    // ~40 chars of context immediately before the match, bounded to the
    // current statement/line so an unrelated comment or prior statement
    // mentioning e.g. "build" or "uuid" can't suppress a real secret a
    // few characters later — a false NEGATIVE here is the worse failure
    // mode, so this boundary matters more here than almost anywhere else
    // in the scanner.
    let contextBefore = content.slice(Math.max(0, m.index - 40), m.index);
    const ctxBoundary = Math.max(contextBefore.lastIndexOf(';'), contextBefore.lastIndexOf('\n'));
    if (ctxBoundary !== -1) contextBefore = contextBefore.slice(ctxBoundary + 1);
    // Check both the surrounding context AND the value itself — a
    // self-describing hash like "sha384-<base64>" carries its own giveaway
    // prefix inside the matched string, not in the text before it.
    if (ENTROPY_CONTEXT_DENYLIST.test(contextBefore) || ENTROPY_CONTEXT_DENYLIST.test(value)) continue;
    // Build/version/analytics/tracing identifiers: randomly generated and
    // legitimately high-entropy, but not secrets.
    if (NON_SECRET_ID_CONTEXT.test(contextBefore)) continue;

    const valueIdx = m.index + m[0].indexOf(value);
    const { line, column } = lineAndColumn(content, valueIdx);
    foundValues.add(value);
    results.push({
      type: 'secret-high-entropy-string',
      severity: 'low',
      line,
      column,
      value,
      snippet: snippetAround(content, valueIdx, value.length),
      note: `Flagged by entropy heuristic (${entropy.toFixed(2)} bits/char, ${isHex ? 'hex' : isBase64ish ? 'base64-like' : 'mixed'} charset) — no known-service prefix matched. High false-positive risk (hashes, IDs, minified chunk names); verify manually.`,
    });
  }
  return results;
}


// --- Cross-file taint (workspace-aware, scoped to one scan batch) ----------
// Everything above analyzes one file in isolation. Real handlers very often
// hand event.data off to a helper imported from another file in the same
// project — `import { relay } from './bus'; window.addEventListener(...,
// e => relay(e.data))` — and if that helper's own body feeds its parameter
// into a dangerous sink, single-file analysis never sees it: the sink isn't
// in the file with the listener, and the taint isn't visible in the file
// with the sink. This pass looks across every file handed to it in the same
// scan (not the whole historical workspace — see note below) for exactly
// that shape: an exported function whose own body passes its first
// parameter into a sink, called somewhere else in the batch with event.data
// (or a known alias) as the argument.
//
// Deliberately scoped down from "the whole workspace" to "this scan's own
// batch of files": resolving a bare specifier like './bus' to a concrete
// file only makes sense when that file's source is actually in hand right
// now (matched by basename below) — reliably resolving it against some
// *other*, earlier scan's files, possibly fetched from different URLs or a
// different directory layout entirely, isn't something static analysis can
// do safely. Point every scan in a directory (`-d`) at the same project and
// this still catches the same real cross-file flows every time.
//
// Matches only the common CommonJS/ESM export and import shapes below —
// dynamic `require(someVariable)`, re-exports, and default-exported object
// literals are out of scope, the same "common shapes, not exhaustive"
// tradeoff every regex-based rule elsewhere in this file makes.
function extractExportedFunctions(content, filePath) {
  const mask = getStructuralMask(content);
  const exported = []; // { name, paramsText, body }
  const patterns = [
    // module.exports.name = function(...) / exports.name = function(...)
    /(?:module\.)?exports\s*\.\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?function\s*\(([^)]*)\)/g,
    // module.exports.name = (...) => / exports.name = (...) =>
    /(?:module\.)?exports\s*\.\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/g,
    // export function name(...)
    /export\s+(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)/g,
    // export const name = function(...) / export const name = (...) =>
    /export\s+(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?(?:function\s*)?\(([^)]*)\)\s*(?:=>)?/g,
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(mask)) !== null) {
      const name = m[1];
      const paramsText = m[2];
      const block = extractBraceBlock(content, re.lastIndex - 1);
      if (!block) continue;
      exported.push({ name, paramsText, body: block.text, file: filePath });
    }
  }

  // The other very common CommonJS shape: functions declared normally
  // earlier in the file, then handed off together at the bottom —
  // `function relay(x) {...}` ... `module.exports = { relay };` (or
  // `{ relay: relay }` / `{ send: relay }`). Each listed name is resolved
  // back to its own `function <name>(...)` declaration via the same
  // named-handler-body resolver used for postMessage's bare-identifier
  // listeners, so a renamed export (`{ send: relay }`) still finds the
  // real `relay` declaration, not a function called "send" that doesn't exist.
  const objExportRe = /(?:module\s*\.\s*)?exports\s*=\s*\{([^}]*)\}/g;
  let om;
  while ((om = objExportRe.exec(mask)) !== null) {
    om[1].split(',').forEach((entry) => {
      const trimmed = entry.trim();
      if (!trimmed) return;
      const [exportedAs, aliasTo] = trimmed.split(':').map((s) => s.trim());
      const declName = aliasTo || exportedAs;
      if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(declName)) return;
      const block = resolveNamedHandlerBody(content, declName);
      if (!block) return;
      exported.push({ name: exportedAs, paramsText: block.paramsText, body: block.text, file: filePath });
    });
  }
  return exported;
}

/** Local-name -> { importedName, specifier } for the common require()/import
 *  destructuring forms, relative specifiers only (a bare package name like
 *  'lodash' can't be resolved against this scan's own file list anyway). */
function extractRelativeImports(content) {
  const imports = [];
  const patterns = [
    /(?:const|let|var)\s*\{\s*([^}]+)\}\s*=\s*require\(\s*['"`](\.[^'"`]*)['"`]\s*\)/g,
    /import\s*\{\s*([^}]+)\}\s*from\s*['"`](\.[^'"`]*)['"`]/g,
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(content)) !== null) {
      const specifier = m[2];
      m[1].split(',').forEach((part) => {
        const [orig, alias] = part.split(':').map((s) => s.trim());
        if (!orig) return;
        imports.push({ localName: (alias || orig).replace(/\s.*$/, ''), importedName: orig, specifier });
      });
    }
  }
  return imports;
}

/** Best-effort match of a relative import specifier ('./bus', '../lib/bus')
 *  to one of this scan's own files, by basename (extension-insensitive) —
 *  full module resolution (extension probing, index.js, package.json
 *  "main") is more machinery than a static-analysis heuristic warrants. */
function resolveSpecifierToFile(specifier, files) {
  const base = specifier.split('/').pop().replace(/\.(js|mjs|cjs|ts)$/, '');
  return files.find((f) => {
    const fBase = f.filePath.split(/[\\/]/).pop().replace(/\.(js|mjs|cjs|ts)$/, '');
    return fBase === base;
  }) || null;
}

const CROSS_FILE_SINK_PATTERNS = [
  { name: 'eval', re: (t) => new RegExp(`eval\\s*\\([^)]*\\b${t}\\b`) },
  { name: 'Function-constructor', re: (t) => new RegExp(`new\\s+Function\\s*\\([^)]*\\b${t}\\b`) },
  { name: 'innerHTML', re: (t) => new RegExp(`\\.innerHTML\\s*=[^;]*\\b${t}\\b`) },
  { name: 'outerHTML', re: (t) => new RegExp(`\\.outerHTML\\s*=[^;]*\\b${t}\\b`) },
  { name: 'insertAdjacentHTML', re: (t) => new RegExp(`insertAdjacentHTML\\s*\\([^)]*\\b${t}\\b`) },
  { name: 'document.write', re: (t) => new RegExp(`document\\.write(?:ln)?\\s*\\([^)]*\\b${t}\\b`) },
  { name: 'location-assign', re: (t) => new RegExp(`location(?:\\.href)?\\s*=[^;]*\\b${t}\\b`) },
  { name: 'settimeout-string', re: (t) => new RegExp(`set(?:Timeout|Interval)\\s*\\([^,]*\\b${t}\\b`) },
];

/** Does `fn`'s own body pass its first parameter into a known dangerous
 *  sink? Deliberately a plain word-bounded check on the parameter's bare
 *  name (not the full alias/destructure taint-tracking used within a single
 *  handler) — good enough to catch the common "thin wrapper" shape
 *  (`function relay(payload) { eval(payload); }`) without re-deriving the
 *  event-specific taint machinery for a value that, here, IS the taint
 *  source (it arrived as this function's own argument, not via event.data). */
function exportedFnDangerousSink(fn) {
  const paramName = firstParamName(fn.paramsText) || (fn.paramsText || '').split(',')[0].trim();
  if (!paramName || !/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(paramName)) return null;
  for (const s of CROSS_FILE_SINK_PATTERNS) {
    const m = s.re(paramName).exec(fn.body);
    if (m) return { name: s.name, paramName };
  }
  return null;
}

/**
 * @param {{filePath: string, content: string}[]} files — every file in the
 *   current scan batch (not the whole workspace's history).
 */
function analyzeCrossFileTaint(files) {
  const findings = [];
  if (!files || files.length < 2) return findings; // needs at least 2 files to say anything cross-file

  const exportsByFile = files.map((f) => ({ file: f, exported: extractExportedFunctions(f.content, f.filePath) }));

  for (const { file, imports } of files.map((f) => ({ file: f, imports: extractRelativeImports(f.content) }))) {
    if (!imports.length) continue;
    const taintAliasRe = /\b(?:event|evt|e|msg|message)\s*\.\s*data\b/;
    // Local aliases of event.data in THIS file (same shape findDataAliases
    // looks for), so `const payload = e.data; relay(payload)` is caught too,
    // not just an inline `relay(e.data)`.
    const aliasNames = new Set();
    let am;
    const aliasRe = /(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:event|evt|e|msg|message)\s*\.\s*data\b/g;
    while ((am = aliasRe.exec(file.content)) !== null) aliasNames.add(am[1]);

    for (const imp of imports) {
      const targetFile = resolveSpecifierToFile(imp.specifier, files.filter((f) => f !== file));
      if (!targetFile) continue;
      const targetExports = exportsByFile.find((e) => e.file === targetFile);
      const fn = targetExports && targetExports.exported.find((x) => x.name === imp.importedName);
      if (!fn) continue;
      const sink = exportedFnDangerousSink(fn);
      if (!sink) continue;

      // Call site: <localName>(...) somewhere in this file, with an argument
      // that's either the raw event.data expression or one of its aliases.
      const callRe = new RegExp(`\\b${imp.localName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\(([^)]*)\\)`, 'g');
      let cm;
      while ((cm = callRe.exec(file.content)) !== null) {
        const argsText = cm[1];
        const isTainted = taintAliasRe.test(argsText) || [...aliasNames].some((a) => new RegExp(`\\b${a}\\b`).test(argsText));
        if (!isTainted) continue;
        const { line, column } = lineAndColumn(file.content, cm.index);
        findings.push({
          type: 'postmessage-cross-file-sink',
          severity: 'high',
          file: file.filePath,
          line,
          column,
          snippet: snippetAround(file.content, cm.index, cm[0].length),
          note: `event.data appears to flow into ${imp.localName}(...) here, which is imported from ${targetFile.filePath} — inside that function, its "${sink.paramName}" parameter appears to flow into ${sink.name}. Potential cross-file DOM XSS / injection via postMessage. Verify manually (this is a heuristic name-based match, not full data-flow analysis).`,
          crossFile: targetFile.filePath,
        });
      }
    }
  }
  return findings;
}

module.exports = {
  getStructuralMask,
  findMatchingBrace,
  extractBraceBlock,
  resolveNamedHandlerBody,
  lineAndColumn,
  snippetAround,
  eventVarPattern,
  firstParamName,
  findDataAliases,
  dataTaintPattern,
  classifyOriginCheck,
  findDangerousSinks,
  analyzePostMessage,
  HTTP_METHODS,
  detectHttpMethodAt,
  detectHttpMethodsForValue,
  getStringLiteralSpans,
  isInsideStringLiteral,
  isValidIpv4Octets,
  VERSION_LIKE_CONTEXT,
  EMAIL_ASSET_SUFFIX_RE,
  analyzeRecon,
  isLikelyPlaceholderOrNonSecret,
  NON_SECRET_ID_CONTEXT,
  analyzeSecrets,
  shannonEntropy,
  ENTROPY_CONTEXT_DENYLIST,
  findHighEntropySecrets,
  analyzeCrossFileTaint,
};
