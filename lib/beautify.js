'use strict';
/**
 * Lightweight, dependency-free JS "unminifier" for the jump-to-line viewer.
 * It never rewrites token text — only inserts/removes whitespace between
 * tokens — so every original character offset can be mapped forward to an
 * offset in the beautified output, which is what lets the flagged line be
 * re-highlighted correctly after reformatting. Not a full pretty-printer
 * (no real parser), just heuristics good enough to turn a wall of minified
 * JS into something a human can visually scan.
 */

const MULTI_CHAR_OPS = [
  '>>>=', '===', '!==', '**=', '...', '>>>', '<<=', '>>=', '&&=', '||=', '??=',
  '=>', '==', '!=', '<=', '>=', '&&', '||', '??', '++', '--',
  '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '**', '<<', '>>',
];

const REGEX_ALLOWED_WORDS = new Set([
  'return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void',
  'throw', 'case', 'do', 'else', 'yield', 'await',
]);

const SPACE_BOTH_SIDES_OPS = new Set([
  '=', '==', '===', '!=', '!==', '<=', '>=', '&&', '||', '??',
  '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '**=', '>>>=', '<<=', '>>=',
  '&&=', '||=', '??=', '**', '<<', '>>', '>>>', '=>',
  '+', '-', '*', '/', '%', '<', '>', '&', '|', '^', '?',
]);

const CONTROL_KEYWORDS_SPACE_BEFORE_PAREN = new Set(['if', 'for', 'while', 'switch', 'catch']);

function tokenize(src) {
  const n = src.length;
  let i = 0;
  const tokens = [];
  const isIdentStart = (c) => /[A-Za-z_$]/.test(c);
  const isIdentPart = (c) => /[A-Za-z0-9_$]/.test(c);
  const isDigit = (c) => c >= '0' && c <= '9';

  function prevTok() {
    return tokens.length ? tokens[tokens.length - 1] : null;
  }

  while (i < n) {
    const c = src[i];

    if (c === ' ' || c === '\t' || c === '\r' || c === '\n' || c === '\f' || c === '\v') {
      i++;
      continue;
    }

    if (c === '/' && src[i + 1] === '/') {
      const start = i;
      i += 2;
      while (i < n && src[i] !== '\n') i++;
      tokens.push({ type: 'linecomment', start, end: i });
      continue;
    }

    if (c === '/' && src[i + 1] === '*') {
      const start = i;
      i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) i++;
      i = Math.min(n, i + 2);
      tokens.push({ type: 'blockcomment', start, end: i });
      continue;
    }

    if (c === '"' || c === "'") {
      const q = c;
      const start = i;
      i++;
      while (i < n && src[i] !== q) {
        if (src[i] === '\\') i++;
        i++;
      }
      i = Math.min(n, i + 1);
      tokens.push({ type: 'string', start, end: i });
      continue;
    }

    if (c === '`') {
      const start = i;
      i++;
      let depth = 0;
      while (i < n) {
        if (src[i] === '\\') { i += 2; continue; }
        if (src[i] === '`' && depth === 0) { i++; break; }
        if (src[i] === '$' && src[i + 1] === '{') { depth++; i += 2; continue; }
        if (src[i] === '}' && depth > 0) { depth--; i++; continue; }
        i++;
      }
      tokens.push({ type: 'template', start, end: i });
      continue;
    }

    if (c === '/') {
      const prev = prevTok();
      const prevText = prev ? src.slice(prev.start, prev.end) : '';
      const regexAllowed = !prev
        || ['brace-open', 'paren-open', 'op', 'comma', 'semi', 'colon'].includes(prev.type)
        || (prev.type === 'word' && REGEX_ALLOWED_WORDS.has(prevText));
      if (regexAllowed) {
        const start = i;
        let j = i + 1;
        let inClass = false;
        let ok = false;
        while (j < n) {
          const ch = src[j];
          if (ch === '\\') { j += 2; continue; }
          if (ch === '[') { inClass = true; j++; continue; }
          if (ch === ']') { inClass = false; j++; continue; }
          if (ch === '\n') { ok = false; break; }
          if (ch === '/' && !inClass) { j++; ok = true; break; }
          j++;
        }
        if (ok) {
          while (j < n && /[a-z]/i.test(src[j])) j++;
          tokens.push({ type: 'regex', start, end: j });
          i = j;
          continue;
        }
        // fell through: not actually a regex (unterminated) — treat '/' as an operator below
      }
    }

    if (isIdentStart(c)) {
      const start = i;
      i++;
      while (i < n && isIdentPart(src[i])) i++;
      tokens.push({ type: 'word', start, end: i });
      continue;
    }

    if (isDigit(c) || (c === '.' && isDigit(src[i + 1]))) {
      const start = i;
      i++;
      while (i < n && /[0-9a-fA-Fxobn.]/.test(src[i])) i++;
      // trailing exponent, e.g. 1e10, 1e-10, 1.5e+3
      if (src[i] === 'e' || src[i] === 'E') {
        i++;
        if (src[i] === '+' || src[i] === '-') i++;
        while (i < n && isDigit(src[i])) i++;
      }
      tokens.push({ type: 'number', start, end: i });
      continue;
    }

    // punctuation / operators — longest match wins
    let matched = null;
    for (const op of MULTI_CHAR_OPS) {
      if (src.startsWith(op, i)) { matched = op; break; }
    }
    const start = i;
    i += matched ? matched.length : 1;
    const text = src.slice(start, i);
    let type = 'op';
    if (text === '{') type = 'brace-open';
    else if (text === '}') type = 'brace-close';
    else if (text === '(' || text === '[') type = 'paren-open';
    else if (text === ')' || text === ']') type = 'paren-close';
    else if (text === ';') type = 'semi';
    else if (text === ',') type = 'comma';
    else if (text === '.') type = 'dot';
    else if (text === ':') type = 'colon';
    tokens.push({ type, start, end: i });
  }

  return tokens;
}

/**
 * Renders tokens into readable, indented source. Returns the output text
 * plus a sorted list of { origStart, origEnd, outStart } spans — one per
 * token that was copied verbatim — used to map an original offset forward
 * into the beautified output.
 */
function beautifyRenderTokens(tokens, src) {
  let indent = 0;
  let parenDepth = 0;
  const forHeaderDepths = new Set();
  let pendingFor = false;
  const spans = [];

  // Building `out` with repeated string concatenation (or, worse, slicing
  // its tail to "fix up" whitespace already written) is O(n) per token on a
  // string that grows to the size of the whole file — O(n^2) overall, which
  // hangs on a real multi-hundred-KB bundle. Instead we push pieces onto an
  // array and track the output length ourselves; a pending newline is only
  // materialized (at whatever indent is current *then*) right before the
  // next real token, so nothing already pushed ever needs to be revisited.
  const parts = [];
  let outLen = 0;
  let pendingNewline = false; // a line break is owed before the next token
  let lastCharWasSpace = true; // true at start: no leading space needed

  const IND = () => '  '.repeat(Math.max(0, indent));
  const push = (s) => { if (!s) return; parts.push(s); outLen += s.length; lastCharWasSpace = s[s.length - 1] === ' ' || s[s.length - 1] === '\n'; };
  const requestNewline = () => { pendingNewline = true; };
  const flushPending = () => {
    if (pendingNewline) {
      push('\n' + IND());
      pendingNewline = false;
    }
  };

  let prev = null;
  for (let ti = 0; ti < tokens.length; ti++) {
    const tok = tokens[ti];
    const text = src.slice(tok.start, tok.end);
    const prevText = prev ? src.slice(prev.start, prev.end) : '';

    if (tok.type === 'brace-close') {
      indent = Math.max(0, indent - 1);
      requestNewline();
      flushPending();
    } else if (prev) {
      // Decide spacing before this token based on the previous one. Any
      // branch that wants a line break just requests one — flushed below
      // (at whatever indent is current right now) instead of writing it
      // immediately, so a run of several such requests in a row collapses
      // into exactly one break instead of stacking blank lines.
      let needSpace = false;
      if (prev.type === 'comma') needSpace = true;
      else if (prev.type === 'word' && ['word', 'number', 'string', 'template', 'regex'].includes(tok.type)) needSpace = true;
      else if (tok.type === 'brace-open') needSpace = true;
      else if (tok.type === 'op' && SPACE_BOTH_SIDES_OPS.has(text)) needSpace = true;
      else if (prev.type === 'op' && SPACE_BOTH_SIDES_OPS.has(prevText)) needSpace = true;
      else if (prev.type === 'colon') needSpace = true;
      else if (prev.type === 'word' && CONTROL_KEYWORDS_SPACE_BEFORE_PAREN.has(prevText) && tok.type === 'paren-open') needSpace = true;
      else if (prev.type === 'linecomment') { requestNewline(); }
      else if (prev.type === 'brace-close') {
        if (['else', 'catch', 'finally'].includes(text)) needSpace = true;
        else if (![')', ']', ',', ';', '.'].includes(text)) requestNewline();
      }

      flushPending();
      if (needSpace && !lastCharWasSpace) push(' ');
    } else {
      flushPending();
    }

    spans.push({ origStart: tok.start, origEnd: tok.end, outStart: outLen });
    push(text);

    if (tok.type === 'brace-open') {
      indent++;
      requestNewline();
    } else if (tok.type === 'semi') {
      if (forHeaderDepths.has(parenDepth)) push(' ');
      else requestNewline();
    } else if (tok.type === 'linecomment') {
      requestNewline();
    }

    if (tok.type === 'word') {
      pendingFor = text === 'for';
    } else if (tok.type !== 'paren-open') {
      pendingFor = false;
    }

    if (tok.type === 'paren-open' && text === '(') {
      parenDepth++;
      if (pendingFor) { forHeaderDepths.add(parenDepth); pendingFor = false; }
    } else if (tok.type === 'paren-close' && text === ')') {
      forHeaderDepths.delete(parenDepth);
      parenDepth = Math.max(0, parenDepth - 1);
    }

    prev = tok;
  }

  const out = parts.join('');

  return { text: out, spans };
}

/**
 * Beautifies `src` and returns { text, mapOffset(origOffset) }.
 * mapOffset finds the verbatim token span containing (or nearest to)
 * origOffset and returns the corresponding offset in the beautified text.
 */
function beautifyJs(src) {
  const tokens = tokenize(src);
  const { text, spans } = beautifyRenderTokens(tokens, src);

  function mapOffset(origOffset) {
    if (!spans.length) return 0;
    // Binary search for the last span whose origStart <= origOffset.
    let lo = 0, hi = spans.length - 1, ans = 0;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (spans[mid].origStart <= origOffset) { ans = mid; lo = mid + 1; }
      else hi = mid - 1;
    }
    const span = spans[ans];
    const within = Math.max(0, Math.min(origOffset - span.origStart, span.origEnd - span.origStart));
    return span.outStart + within;
  }

  return { text, mapOffset };
}

module.exports = { beautifyJs, tokenize, render: beautifyRenderTokens };
