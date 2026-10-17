/**
 * decoderOperations.ts
 *
 * High-performance string manipulation and cryptographic transformation engine for FileSanitizer Security Decoder.
 * Fully client-side, air-gapped safe, zero external network dependencies.
 */

export interface OperationParam {
  id: string;
  name: string;
  type: 'string' | 'number' | 'boolean' | 'select' | 'text';
  default: any;
  options?: { value: string; label: string }[];
  description?: string;
}

export interface DecoderOperation {
  id: string;
  name: string;
  category: 'Encodings' | 'Ciphers' | 'Threat Intel' | 'String Utilities' | 'Hashes' | 'Forensics';
  description: string;
  params: OperationParam[];
  run: (input: string, args: Record<string, any>) => string | Promise<string>;
}

export interface RecipeStep {
  stepId: string;
  operationId: string;
  args: Record<string, any>;
  disabled: boolean;
}

// -------------------------------------------------------------
// Pure JS Hash Implementations (Air-Gapped & Synchronous)
// -------------------------------------------------------------

function md5Cycle(x: number[], k: number[]) {
  let a = x[0], b = x[1], c = x[2], d = x[3];

  function cmn(q: number, a: number, b: number, x: number, s: number, t: number) {
    a = add32(add32(a, q), add32(x, t));
    return add32((a << s) | (a >>> (32 - s)), b);
  }
  function ff(a: number, b: number, c: number, d: number, x: number, s: number, t: number) {
    return cmn((b & c) | (~b & d), a, b, x, s, t);
  }
  function gg(a: number, b: number, c: number, d: number, x: number, s: number, t: number) {
    return cmn((b & d) | (c & ~d), a, b, x, s, t);
  }
  function hh(a: number, b: number, c: number, d: number, x: number, s: number, t: number) {
    return cmn(b ^ c ^ d, a, b, x, s, t);
  }
  function ii(a: number, b: number, c: number, d: number, x: number, s: number, t: number) {
    return cmn(c ^ (b | ~d), a, b, x, s, t);
  }
  function add32(a: number, b: number) {
    return (a + b) & 0xffffffff;
  }

  a = ff(a, b, c, d, k[0], 7, -680876936);
  d = ff(d, a, b, c, k[1], 12, -389564586);
  c = ff(c, d, a, b, k[2], 17, 606105819);
  b = ff(b, c, d, a, k[3], 22, -1044525330);
  a = ff(a, b, c, d, k[4], 7, -176418897);
  d = ff(d, a, b, c, k[5], 12, 1200080426);
  c = ff(c, d, a, b, k[6], 17, -1473231341);
  b = ff(b, c, d, a, k[7], 22, -45705983);
  a = ff(a, b, c, d, k[8], 7, 1770035416);
  d = ff(d, a, b, c, k[9], 12, -1958414417);
  c = ff(c, d, a, b, k[10], 17, -42063);
  b = ff(b, c, d, a, k[11], 22, -1990404162);
  a = ff(a, b, c, d, k[12], 7, 1804603682);
  d = ff(d, a, b, c, k[13], 12, -40341101);
  c = ff(c, d, a, b, k[14], 17, -1502002290);
  b = ff(b, c, d, a, k[15], 22, 1236535329);

  a = gg(a, b, c, d, k[1], 5, -165796510);
  d = gg(d, a, b, c, k[6], 9, -1069501632);
  c = gg(c, d, a, b, k[11], 14, 643717713);
  b = gg(b, c, d, a, k[0], 20, -373897302);
  a = gg(a, b, c, d, k[5], 5, -701558691);
  d = gg(d, a, b, c, k[10], 9, 38016083);
  c = gg(c, d, a, b, k[15], 14, -660478335);
  b = gg(b, c, d, a, k[4], 20, -405537848);
  a = gg(a, b, c, d, k[9], 5, 568446438);
  d = gg(d, a, b, c, k[14], 9, -1019803690);
  c = gg(c, d, a, b, k[3], 14, -187363961);
  b = gg(b, c, d, a, k[8], 20, 1163531501);
  a = gg(a, b, c, d, k[13], 5, -1444681467);
  d = gg(d, a, b, c, k[2], 9, -51403784);
  c = gg(c, d, a, b, k[7], 14, 1735328473);
  b = gg(b, c, d, a, k[12], 20, -1926607734);

  a = hh(a, b, c, d, k[5], 4, -378558);
  d = hh(d, a, b, c, k[8], 11, -2022574463);
  c = hh(c, d, a, b, k[11], 16, 1839030562);
  b = hh(b, c, d, a, k[14], 23, -35309556);
  a = hh(a, b, c, d, k[1], 4, -1530992060);
  d = hh(d, a, b, c, k[4], 11, 1272893353);
  c = hh(c, d, a, b, k[7], 16, -155497632);
  b = hh(b, c, d, a, k[10], 23, -1094730640);
  a = hh(a, b, c, d, k[13], 4, 681279174);
  d = hh(d, a, b, c, k[0], 11, -358537222);
  c = hh(c, d, a, b, k[3], 16, -722521979);
  b = hh(b, c, d, a, k[6], 23, 76029189);
  a = hh(a, b, c, d, k[9], 4, -640364487);
  d = hh(d, a, b, c, k[12], 11, -421815835);
  c = hh(c, d, a, b, k[15], 16, 530742520);
  b = hh(b, c, d, a, k[2], 23, -995338651);

  a = ii(a, b, c, d, k[0], 6, -198630844);
  d = ii(d, a, b, c, k[7], 10, 1126891415);
  c = ii(c, d, a, b, k[14], 15, -1416354905);
  b = ii(b, c, d, a, k[5], 21, -57434055);
  a = ii(a, b, c, d, k[12], 6, 1700485571);
  d = ii(d, a, b, c, k[3], 10, -1894986606);
  c = ii(c, d, a, b, k[10], 15, -1051523);
  b = ii(b, c, d, a, k[1], 21, -2054922799);
  a = ii(a, b, c, d, k[8], 6, 1873313359);
  d = ii(d, a, b, c, k[15], 10, -30611744);
  c = ii(c, d, a, b, k[6], 15, -1560198380);
  b = ii(b, c, d, a, k[13], 21, 1309151649);
  a = ii(a, b, c, d, k[4], 6, -145523070);
  d = ii(d, a, b, c, k[11], 10, -1120210379);
  c = ii(c, d, a, b, k[2], 15, 718787259);
  b = ii(b, c, d, a, k[9], 21, -343485551);

  x[0] = add32(a, x[0]);
  x[1] = add32(b, x[1]);
  x[2] = add32(c, x[2]);
  x[3] = add32(d, x[3]);
}

function md51(s: string): string {
  const txt = unescape(encodeURIComponent(s));
  const n = txt.length;
  const state = [1732584193, -271733879, -1732584194, 271733878];
  let i: number;
  for (i = 64; i <= n; i += 64) {
    md5Cycle(state, md5blk(txt.substring(i - 64, i)));
  }
  const tail = txt.substring(i - 64);
  const words = Array(16).fill(0);
  for (let j = 0; j < tail.length; j++) {
    words[j >> 2] |= tail.charCodeAt(j) << ((j % 4) << 3);
  }
  words[tail.length >> 2] |= 0x80 << ((tail.length % 4) << 3);
  if (tail.length > 55) {
    md5Cycle(state, words);
    words.fill(0);
  }
  words[14] = n * 8;
  md5Cycle(state, words);

  return state
    .map(val => {
      let hex = '';
      for (let j = 0; j < 4; j++) {
        const byte = (val >>> (j * 8)) & 0xff;
        hex += (byte < 16 ? '0' : '') + byte.toString(16);
      }
      return hex;
    })
    .join('');
}

function md5blk(s: string): number[] {
  const md5blks: number[] = [];
  for (let i = 0; i < 64; i += 4) {
    md5blks[i >> 2] =
      s.charCodeAt(i) +
      (s.charCodeAt(i + 1) << 8) +
      (s.charCodeAt(i + 2) << 16) +
      (s.charCodeAt(i + 3) << 24);
  }
  return md5blks;
}

function crc32(str: string): string {
  let crc = 0 ^ (-1);
  for (let i = 0; i < str.length; i++) {
    crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ str.charCodeAt(i)) & 0xff];
  }
  return ((crc ^ (-1)) >>> 0).toString(16).padStart(8, '0');
}

const CRC32_TABLE: number[] = (() => {
  const table: number[] = [];
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c;
  }
  return table;
})();

async function cryptoSubtleHash(str: string, algorithm: 'SHA-1' | 'SHA-256' | 'SHA-512'): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await crypto.subtle.digest(algorithm, data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// -------------------------------------------------------------
// Base58 & Base32 Helpers
// -------------------------------------------------------------

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function toBase58(str: string): string {
  const bytes = new TextEncoder().encode(str);
  const digits = [0];
  for (let i = 0; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let res = '';
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    res += B58_ALPHABET[0];
  }
  for (let i = digits.length - 1; i >= 0; i--) {
    res += B58_ALPHABET[digits[i]];
  }
  return res;
}

function fromBase58(str: string): string {
  const bytes = [0];
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    const val = B58_ALPHABET.indexOf(c);
    if (val === -1) throw new Error(`Invalid Base58 character: ${c}`);
    let carry = val;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (let i = 0; i < str.length && str[i] === B58_ALPHABET[0]; i++) {
    bytes.push(0);
  }
  return new TextDecoder().decode(new Uint8Array(bytes.reverse()));
}

function toBase32(str: string): string {
  const bytes = new TextEncoder().encode(str);
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      output += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += B32_ALPHABET[(value << (5 - bits)) & 31];
  }
  while (output.length % 8 !== 0) {
    output += '=';
  }
  return output;
}

function fromBase32(str: string): string {
  const clean = str.replace(/=+$/, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (let i = 0; i < clean.length; i++) {
    const idx = B32_ALPHABET.indexOf(clean[i]);
    if (idx === -1) throw new Error(`Invalid Base32 character: ${clean[i]}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}

// -------------------------------------------------------------
// CyberChef Parity Helper Functions
// -------------------------------------------------------------

function adler32(str: string): string {
  const bytes = new TextEncoder().encode(str);
  let a = 1;
  let b = 0;
  const MOD_ADLER = 65521;
  for (let i = 0; i < bytes.length; i++) {
    a = (a + bytes[i]) % MOD_ADLER;
    b = (b + a) % MOD_ADLER;
  }
  const checksum = ((b << 16) | a) >>> 0;
  return checksum.toString(16).padStart(8, '0');
}

function toHexdump(str: string, width: number = 16, upperCase: boolean = false, includeAscii: boolean = true): string {
  const bytes = new TextEncoder().encode(str);
  if (bytes.length === 0) return '';
  const lines: string[] = [];
  const w = Math.max(1, Math.min(64, width || 16));
  for (let offset = 0; offset < bytes.length; offset += w) {
    const chunk = bytes.slice(offset, offset + w);
    const addr = offset.toString(16).padStart(8, '0');
    const hexBytes: string[] = [];
    for (let i = 0; i < w; i++) {
      if (i < chunk.length) {
        let h = chunk[i].toString(16).padStart(2, '0');
        if (upperCase) h = h.toUpperCase();
        hexBytes.push(h);
      } else {
        hexBytes.push('  ');
      }
      if (i === 7 && w >= 16) hexBytes.push('');
    }

    if (!includeAscii) {
      lines.push(`${addr}  ${hexBytes.join(' ')}`);
      continue;
    }

    let ascii = '';
    for (let i = 0; i < chunk.length; i++) {
      const b = chunk[i];
      ascii += b >= 32 && b <= 126 ? String.fromCharCode(b) : '.';
    }
    lines.push(`${addr}  ${hexBytes.join(' ')}  |${ascii}|`);
  }
  return lines.join('\n');
}

function fromHexdump(input: string): string {
  const lines = input.split('\n');
  const byteValues: number[] = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let hexPart = trimmed;
    const addrMatch = trimmed.match(/^[0-9a-fA-F]{4,8}[:\s]\s*(.*)$/);
    if (addrMatch) {
      hexPart = addrMatch[1];
    }
    const barIndex = hexPart.indexOf('|');
    if (barIndex !== -1) {
      hexPart = hexPart.substring(0, barIndex);
    }
    const hexMatches = hexPart.match(/[0-9a-fA-F]{2}/g);
    if (hexMatches) {
      for (const h of hexMatches) {
        byteValues.push(parseInt(h, 16));
      }
    }
  }
  if (byteValues.length === 0) return input;
  const u8 = new Uint8Array(byteValues);
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(u8);
  } catch {
    let s = '';
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return s;
  }
}

function toCharcode(input: string, base: number = 10, delimiter: string = ', '): string {
  const codes: string[] = [];
  for (let i = 0; i < input.length; i++) {
    const code = input.codePointAt(i) || input.charCodeAt(i);
    let s = code.toString(base);
    if (base === 16) s = '0x' + s;
    codes.push(s);
    if (code > 0xffff) i++;
  }
  return codes.join(delimiter);
}

function fromCharcode(input: string, base: number = 0, delimiter: string = 'auto'): string {
  let tokens: string[] = [];
  if (delimiter === 'auto') {
    tokens = input.trim().split(/[\s,;]+/);
  } else if (delimiter === 'none') {
    tokens = input.trim().split(/\s+/);
  } else {
    tokens = input.split(delimiter);
  }
  const chars: string[] = [];
  for (let t of tokens) {
    t = t.trim();
    if (!t) continue;
    let num: number;
    if (base === 0) {
      num = t.toLowerCase().startsWith('0x') ? parseInt(t, 16) : parseInt(t, 10);
    } else {
      num = parseInt(t.replace(/^0x/i, ''), base);
    }
    if (!isNaN(num) && num >= 0 && num <= 0x10ffff) {
      chars.push(String.fromCodePoint(num));
    }
  }
  return chars.join('');
}

function toDecimal(input: string, delimiter: string = ' '): string {
  const bytes = new TextEncoder().encode(input);
  return Array.from(bytes).map(b => b.toString(10)).join(delimiter);
}

function fromDecimal(input: string, delimiter: string = 'auto'): string {
  let tokens: string[] = [];
  if (delimiter === 'auto') {
    tokens = input.trim().split(/[\s,;]+/);
  } else {
    tokens = input.split(delimiter);
  }
  const bytes = tokens.map(t => parseInt(t.trim(), 10)).filter(n => !isNaN(n) && n >= 0 && n <= 255);
  const u8 = new Uint8Array(bytes);
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(u8);
  } catch {
    let s = '';
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return s;
  }
}

function toOctal(input: string, delimiter: string = ' '): string {
  const bytes = new TextEncoder().encode(input);
  return Array.from(bytes).map(b => b.toString(8).padStart(3, '0')).join(delimiter);
}

function fromOctal(input: string, delimiter: string = 'auto'): string {
  let tokens: string[] = [];
  if (delimiter === 'auto') {
    tokens = input.trim().split(/[\s,;]+/);
  } else {
    tokens = input.split(delimiter);
  }
  const bytes = tokens.map(t => parseInt(t.trim(), 8)).filter(n => !isNaN(n) && n >= 0 && n <= 255);
  const u8 = new Uint8Array(bytes);
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(u8);
  } catch {
    let s = '';
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return s;
  }
}

function escapeString(input: string, escapeAll: boolean = false): string {
  if (escapeAll) {
    return Array.from(input)
      .map(c => {
        const code = c.charCodeAt(0);
        return code < 256 ? '\\x' + code.toString(16).padStart(2, '0') : '\\u' + code.toString(16).padStart(4, '0');
      })
      .join('');
  }
  return input
    .replace(/\\/g, '\\\\')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t')
    .replace(/"/g, '\\"')
    .replace(/'/g, "\\'")
    .replace(/[\x00-\x1f\x7f-\x9f]/g, (c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0'));
}

function unescapeString(input: string): string {
  return input
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\n/g, '\n')
    .replace(/\\r/g, '\r')
    .replace(/\\t/g, '\t')
    .replace(/\\"/g, '"')
    .replace(/\\'/g, "'")
    .replace(/\\\\/g, '\\');
}

function rot47(input: string): string {
  let result = '';
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    if (c >= 33 && c <= 126) {
      result += String.fromCharCode(33 + ((c - 33 + 47) % 94));
    } else {
      result += input[i];
    }
  }
  return result;
}

function caesarCipher(input: string, shift: number = 3): string {
  const s = ((shift % 26) + 26) % 26;
  let result = '';
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    if (c >= 65 && c <= 90) {
      result += String.fromCharCode(65 + ((c - 65 + s) % 26));
    } else if (c >= 97 && c <= 122) {
      result += String.fromCharCode(97 + ((c - 97 + s) % 26));
    } else {
      result += input[i];
    }
  }
  return result;
}

function vigenereCipher(input: string, key: string, decode: boolean = false): string {
  const cleanKey = (key || 'KEY').toUpperCase().replace(/[^A-Z]/g, '');
  if (!cleanKey) return input;
  let result = '';
  let keyIdx = 0;
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    const shift = cleanKey.charCodeAt(keyIdx % cleanKey.length) - 65;
    const effShift = decode ? (26 - shift) % 26 : shift;
    if (c >= 65 && c <= 90) {
      result += String.fromCharCode(65 + ((c - 65 + effShift) % 26));
      keyIdx++;
    } else if (c >= 97 && c <= 122) {
      result += String.fromCharCode(97 + ((c - 97 + effShift) % 26));
      keyIdx++;
    } else {
      result += input[i];
    }
  }
  return result;
}

function extractDomains(input: string, uniqueOnly: boolean = true): string {
  const domainRegex = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;
  const matches = input.match(domainRegex) || [];
  const filtered = matches.filter(d => !/^\d+\.\d+\.\d+\.\d+$/.test(d));
  const finalDomains = uniqueOnly ? Array.from(new Set(filtered)) : filtered;
  return finalDomains.join('\n');
}

function extractFilePaths(input: string, uniqueOnly: boolean = true): string {
  const winPathRegex = /[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+/g;
  const uncPathRegex = /\\\\[a-zA-Z0-9._-]+\\[^\\/:*?"<>|\r\n]+/g;
  const posixPathRegex = /(?:^|[\s"'])(\/(?:[a-zA-Z0-9._-]+\/)+[a-zA-Z0-9._-]+)/g;

  const matches: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = winPathRegex.exec(input)) !== null) matches.push(m[0]);
  while ((m = uncPathRegex.exec(input)) !== null) matches.push(m[0]);
  while ((m = posixPathRegex.exec(input)) !== null) matches.push(m[1]);

  const result = uniqueOnly ? Array.from(new Set(matches)) : matches;
  return result.join('\n');
}

function parseUri(input: string): string {
  const trimmed = input.trim();
  try {
    const url = new URL(trimmed.startsWith('http://') || trimmed.startsWith('https://') ? trimmed : `http://${trimmed}`);
    const params: Record<string, string> = {};
    url.searchParams.forEach((v, k) => {
      params[k] = v;
    });
    return JSON.stringify({
      href: url.href,
      protocol: url.protocol,
      username: url.username || undefined,
      password: url.password || undefined,
      host: url.host,
      hostname: url.hostname,
      port: url.port || undefined,
      pathname: url.pathname,
      search: url.search || undefined,
      searchParams: Object.keys(params).length > 0 ? params : undefined,
      hash: url.hash || undefined
    }, null, 2);
  } catch (err: any) {
    return `Error parsing URI: ${err.message}`;
  }
}

function stripHtmlTags(input: string, preserveLineBreaks: boolean = true): string {
  let s = input;
  if (preserveLineBreaks) {
    s = s.replace(/<br\s*[\/]?>/gi, '\n')
         .replace(/<\/(p|div|h[1-6]|tr|li)>/gi, '\n');
  }
  return s.replace(/<[^>]+>/g, '').trim();
}

function headLines(input: string, count: number = 10): string {
  const lines = input.split('\n');
  return lines.slice(0, Math.max(0, count)).join('\n');
}

function tailLines(input: string, count: number = 10): string {
  const lines = input.split('\n');
  return lines.slice(Math.max(0, lines.length - count)).join('\n');
}

function padLines(input: string, length: number = 40, position: 'left' | 'right' = 'right', char: string = ' '): string {
  const padChar = (char || ' ')[0];
  const lines = input.split('\n');
  return lines.map(line => {
    if (line.length >= length) return line;
    const pad = padChar.repeat(length - line.length);
    return position === 'left' ? pad + line : line + pad;
  }).join('\n');
}

function countOccurrences(input: string, target: string, regex: boolean = false, caseSensitive: boolean = false): string {
  if (!target) return '0 matches (empty search string)';
  let count = 0;
  if (regex) {
    try {
      const flags = 'g' + (caseSensitive ? '' : 'i');
      const re = new RegExp(target, flags);
      const matches = input.match(re);
      count = matches ? matches.length : 0;
    } catch (e: any) {
      return `Regex error: ${e.message}`;
    }
  } else {
    const src = caseSensitive ? input : input.toLowerCase();
    const needle = caseSensitive ? target : target.toLowerCase();
    let pos = 0;
    while ((pos = src.indexOf(needle, pos)) !== -1) {
      count++;
      pos += needle.length;
    }
  }
  return `${count} match${count === 1 ? '' : 'es'} found for "${target}"`;
}

function dateToUnixTimestamp(input: string, unit: 'seconds' | 'milliseconds' = 'seconds'): string {
  const ts = Date.parse(input.trim());
  if (isNaN(ts)) return 'Error: Invalid date format';
  return unit === 'seconds' ? Math.floor(ts / 1000).toString() : ts.toString();
}

function dateToWindowsFiletime(input: string): string {
  const ts = Date.parse(input.trim());
  if (isNaN(ts)) return 'Error: Invalid date format';
  const ms = BigInt(ts);
  const diff = 11644473600000n;
  const filetime = (ms + diff) * 10000n;
  return filetime.toString();
}

// -------------------------------------------------------------
// Operation Definitions Library
// -------------------------------------------------------------

export const DECODER_OPERATIONS: DecoderOperation[] = [
  // 1. ENCODINGS
  {
    id: 'to_base64',
    name: 'To Base64',
    category: 'Encodings',
    description: 'Encodes text into Base64 format.',
    params: [
      {
        id: 'url_safe',
        name: 'URL Safe (- and _)',
        type: 'boolean',
        default: false,
        description: 'Replaces + and / with - and _ without padding'
      }
    ],
    run: (input, args) => {
      const b64 = btoa(unescape(encodeURIComponent(input)));
      if (args.url_safe) {
        return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      }
      return b64;
    }
  },
  {
    id: 'from_base64',
    name: 'From Base64',
    category: 'Encodings',
    description: 'Decodes Base64 encoded text into UTF-8 characters or raw binary bytes.',
    params: [
      {
        id: 'strict',
        name: 'Strict Validation',
        type: 'boolean',
        default: false,
        description: 'Rejects strings with invalid padding or characters'
      }
    ],
    run: (input, args) => {
      let clean = input.trim().replace(/-/g, '+').replace(/_/g, '/');
      if (!args?.strict) {
        clean = clean.replace(/[^A-Za-z0-9+/=]/g, '');
      }
      if (!clean) return '';
      while (clean.length % 4 !== 0) {
        clean += '=';
      }
      const raw = atob(clean);
      try {
        return decodeURIComponent(escape(raw));
      } catch {
        return raw;
      }
    }
  },
  {
    id: 'to_hex',
    name: 'To Hex',
    category: 'Encodings',
    description: 'Converts ASCII/UTF-8 string into hexadecimal byte representation.',
    params: [
      {
        id: 'delimiter',
        name: 'Delimiter',
        type: 'select',
        default: 'space',
        options: [
          { value: 'none', label: 'None (414243)' },
          { value: 'space', label: 'Space (41 42 43)' },
          { value: '0x', label: '0x Prefix (0x41 0x42)' },
          { value: 'colon', label: 'Colon (41:42:43)' },
          { value: 'comma', label: 'Comma (41,42,43)' }
        ]
      },
      {
        id: 'uppercase',
        name: 'Uppercase',
        type: 'boolean',
        default: true
      }
    ],
    run: (input, args) => {
      const bytes = new TextEncoder().encode(input);
      const hexArr = Array.from(bytes).map(b => {
        const h = b.toString(16).padStart(2, '0');
        return args.uppercase ? h.toUpperCase() : h.toLowerCase();
      });

      if (args.delimiter === 'space') return hexArr.join(' ');
      if (args.delimiter === '0x') return hexArr.map(h => `0x${h}`).join(' ');
      if (args.delimiter === 'colon') return hexArr.join(':');
      if (args.delimiter === 'comma') return hexArr.join(',');
      return hexArr.join('');
    }
  },
  {
    id: 'from_hex',
    name: 'From Hex',
    category: 'Encodings',
    description: 'Decodes hexadecimal bytes into readable text or raw binary string.',
    params: [
      {
        id: 'ignore_errors',
        name: 'Ignore Non-Hex Chars',
        type: 'boolean',
        default: true
      }
    ],
    run: (input, args) => {
      let clean = input.replace(/0x/gi, '');
      if (args.ignore_errors) {
        clean = clean.replace(/[^0-9a-fA-F]/g, '');
      } else {
        clean = clean.trim();
      }
      if (clean.length % 2 !== 0) {
        clean = '0' + clean;
      }
      const bytes = new Uint8Array(clean.length / 2);
      for (let i = 0; i < clean.length; i += 2) {
        bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
      }
      try {
        return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      } catch {
        let bin = '';
        for (let i = 0; i < bytes.length; i++) {
          bin += String.fromCharCode(bytes[i]);
        }
        return bin;
      }
    }
  },
  {
    id: 'to_url',
    name: 'URL Encode',
    category: 'Encodings',
    description: 'Encodes characters for use in URIs/URLs (%20, etc).',
    params: [
      {
        id: 'encode_all',
        name: 'Encode All Characters',
        type: 'boolean',
        default: false
      }
    ],
    run: (input, args) => {
      if (args.encode_all) {
        return input.split('').map(c => '%' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')).join('');
      }
      return encodeURIComponent(input);
    }
  },
  {
    id: 'from_url',
    name: 'URL Decode',
    category: 'Encodings',
    description: 'Decodes percent-encoded URL strings (%20 -> space).',
    params: [],
    run: (input) => {
      const text = input.replace(/\+/g, ' ');
      try {
        return decodeURIComponent(text);
      } catch {
        return text.replace(/%([0-9a-fA-F]{2})/g, (match, hex) => {
          try {
            return decodeURIComponent(match);
          } catch {
            return String.fromCharCode(parseInt(hex, 16));
          }
        });
      }
    }
  },
  {
    id: 'to_html_entity',
    name: 'To HTML Entity',
    category: 'Encodings',
    description: 'Converts characters into HTML entities (&amp;, &#x3C;, etc).',
    params: [
      {
        id: 'format',
        name: 'Format',
        type: 'select',
        default: 'named',
        options: [
          { value: 'named', label: 'Named (&amp;, &lt;, &gt;)' },
          { value: 'hex', label: 'Hex (&#x41;)' },
          { value: 'decimal', label: 'Decimal (&#65;)' }
        ]
      }
    ],
    run: (input, args) => {
      if (args.format === 'hex') {
        return input.split('').map(c => `&#x${c.charCodeAt(0).toString(16)};`).join('');
      }
      if (args.format === 'decimal') {
        return input.split('').map(c => `&#${c.charCodeAt(0)};`).join('');
      }
      const map: Record<string, string> = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
      };
      return input.replace(/[&<>"']/g, m => map[m]);
    }
  },
  {
    id: 'from_html_entity',
    name: 'From HTML Entity',
    category: 'Encodings',
    description: 'Decodes HTML entities back into characters.',
    params: [],
    run: (input) => {
      return input
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'")
        .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        .replace(/&#(\d+);/g, (_, dec) => String.fromCharCode(parseInt(dec, 10)));
    }
  },
  {
    id: 'to_binary',
    name: 'To Binary',
    category: 'Encodings',
    description: 'Converts text into 8-bit binary representation.',
    params: [
      {
        id: 'delimiter',
        name: 'Delimiter',
        type: 'select',
        default: 'space',
        options: [
          { value: 'space', label: 'Space' },
          { value: 'none', label: 'None' },
          { value: 'comma', label: 'Comma' }
        ]
      }
    ],
    run: (input, args) => {
      const bytes = new TextEncoder().encode(input);
      const binArr = Array.from(bytes).map(b => b.toString(2).padStart(8, '0'));
      const sep = args.delimiter === 'space' ? ' ' : args.delimiter === 'comma' ? ',' : '';
      return binArr.join(sep);
    }
  },
  {
    id: 'from_binary',
    name: 'From Binary',
    category: 'Encodings',
    description: 'Decodes binary string (0s and 1s) into readable text.',
    params: [],
    run: (input) => {
      const clean = input.replace(/[^01]/g, '');
      const bytes: number[] = [];
      for (let i = 0; i < clean.length; i += 8) {
        const byteStr = clean.substring(i, i + 8);
        if (byteStr.length === 8) {
          bytes.push(parseInt(byteStr, 2));
        }
      }
      const u8 = new Uint8Array(bytes);
      try {
        return new TextDecoder('utf-8', { fatal: true }).decode(u8);
      } catch {
        let s = '';
        for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
        return s;
      }
    }
  },
  {
    id: 'to_base58',
    name: 'To Base58',
    category: 'Encodings',
    description: 'Encodes text using the Bitcoin Base58 alphabet.',
    params: [],
    run: (input) => toBase58(input)
  },
  {
    id: 'from_base58',
    name: 'From Base58',
    category: 'Encodings',
    description: 'Decodes Bitcoin Base58 encoded string.',
    params: [],
    run: (input) => fromBase58(input.trim())
  },
  {
    id: 'to_base32',
    name: 'To Base32',
    category: 'Encodings',
    description: 'Encodes text using standard RFC 4648 Base32.',
    params: [],
    run: (input) => toBase32(input)
  },
  {
    id: 'from_base32',
    name: 'From Base32',
    category: 'Encodings',
    description: 'Decodes RFC 4648 Base32 encoded text.',
    params: [],
    run: (input) => fromBase32(input.trim())
  },
  {
    id: 'to_hexdump',
    name: 'To Hexdump',
    category: 'Encodings',
    description: 'Formats text into a standard 16-byte offset hexdump with hex bytes and ASCII representation.',
    params: [
      {
        id: 'width',
        name: 'Bytes per Line',
        type: 'number',
        default: 16,
        description: 'Number of bytes per row (typically 16)'
      },
      {
        id: 'uppercase',
        name: 'Uppercase Hex',
        type: 'boolean',
        default: false,
        description: 'Format hex digits in uppercase'
      },
      {
        id: 'include_ascii',
        name: 'Include ASCII Column',
        type: 'boolean',
        default: true,
        description: 'Display printable ASCII characters on the right'
      }
    ],
    run: (input, args) => toHexdump(input, Number(args.width) || 16, Boolean(args.uppercase), args.include_ascii !== false)
  },
  {
    id: 'from_hexdump',
    name: 'From Hexdump',
    category: 'Encodings',
    description: 'Parses a standard hexdump back into raw byte characters.',
    params: [],
    run: (input) => fromHexdump(input)
  },
  {
    id: 'to_charcode',
    name: 'To Charcode',
    category: 'Encodings',
    description: 'Converts text into character codes in decimal, hex, or octal.',
    params: [
      {
        id: 'base',
        name: 'Base',
        type: 'select',
        default: '10',
        options: [
          { value: '10', label: 'Decimal (65, 66)' },
          { value: '16', label: 'Hexadecimal (0x41, 0x42)' },
          { value: '8', label: 'Octal (101, 102)' }
        ]
      },
      {
        id: 'delimiter',
        name: 'Delimiter',
        type: 'select',
        default: ', ',
        options: [
          { value: ', ', label: 'Comma + Space (, )' },
          { value: ' ', label: 'Space' },
          { value: '; ', label: 'Semicolon (; )' }
        ]
      }
    ],
    run: (input, args) => toCharcode(input, Number(args.base) || 10, args.delimiter || ', ')
  },
  {
    id: 'from_charcode',
    name: 'From Charcode',
    category: 'Encodings',
    description: 'Decodes comma- or space-separated character codes into text.',
    params: [
      {
        id: 'base',
        name: 'Base Radix',
        type: 'select',
        default: '0',
        options: [
          { value: '0', label: 'Auto (Detect 0x / Decimal)' },
          { value: '10', label: 'Decimal (10)' },
          { value: '16', label: 'Hexadecimal (16)' },
          { value: '8', label: 'Octal (8)' }
        ]
      },
      {
        id: 'delimiter',
        name: 'Delimiter',
        type: 'select',
        default: 'auto',
        options: [
          { value: 'auto', label: 'Auto (Comma, Space, Semicolon)' },
          { value: ', ', label: 'Comma' },
          { value: ' ', label: 'Space' }
        ]
      }
    ],
    run: (input, args) => fromCharcode(input, Number(args.base) || 0, args.delimiter || 'auto')
  },
  {
    id: 'to_decimal',
    name: 'To Decimal',
    category: 'Encodings',
    description: 'Converts UTF-8 bytes to unsigned decimal byte integers (0-255).',
    params: [
      {
        id: 'delimiter',
        name: 'Delimiter',
        type: 'select',
        default: ' ',
        options: [
          { value: ' ', label: 'Space' },
          { value: ', ', label: 'Comma + Space' },
          { value: ',', label: 'Comma' }
        ]
      }
    ],
    run: (input, args) => toDecimal(input, args.delimiter || ' ')
  },
  {
    id: 'from_decimal',
    name: 'From Decimal',
    category: 'Encodings',
    description: 'Decodes space- or comma-separated decimal byte values (0-255) into UTF-8 text.',
    params: [
      {
        id: 'delimiter',
        name: 'Delimiter',
        type: 'select',
        default: 'auto',
        options: [
          { value: 'auto', label: 'Auto (Space or Comma)' },
          { value: ' ', label: 'Space' },
          { value: ',', label: 'Comma' }
        ]
      }
    ],
    run: (input, args) => fromDecimal(input, args.delimiter || 'auto')
  },
  {
    id: 'to_octal',
    name: 'To Octal',
    category: 'Encodings',
    description: 'Encodes text into 3-digit octal byte representations.',
    params: [
      {
        id: 'delimiter',
        name: 'Delimiter',
        type: 'select',
        default: ' ',
        options: [
          { value: ' ', label: 'Space' },
          { value: ', ', label: 'Comma + Space' }
        ]
      }
    ],
    run: (input, args) => toOctal(input, args.delimiter || ' ')
  },
  {
    id: 'from_octal',
    name: 'From Octal',
    category: 'Encodings',
    description: 'Decodes octal numbers into UTF-8 text.',
    params: [
      {
        id: 'delimiter',
        name: 'Delimiter',
        type: 'select',
        default: 'auto',
        options: [
          { value: 'auto', label: 'Auto (Space or Comma)' },
          { value: ' ', label: 'Space' }
        ]
      }
    ],
    run: (input, args) => fromOctal(input, args.delimiter || 'auto')
  },
  {
    id: 'escape_string',
    name: 'Escape String',
    category: 'Encodings',
    description: 'Escapes control characters (\\n, \\r, \\t, quotes, backslashes) or converts all characters to hex escape sequences.',
    params: [
      {
        id: 'escape_all',
        name: 'Escape All Characters (\\xHH / \\uHHHH)',
        type: 'boolean',
        default: false,
        description: 'Encode all characters as hex escape literals'
      }
    ],
    run: (input, args) => escapeString(input, Boolean(args.escape_all))
  },
  {
    id: 'unescape_string',
    name: 'Unescape String',
    category: 'Encodings',
    description: 'Unescapes standard C-style and hex escape sequences (\\n, \\t, \\xHH, \\uHHHH, \\\\).',
    params: [],
    run: (input) => unescapeString(input)
  },

  // 2. CIPHERS & OBFUSCATION
  {
    id: 'rot13',
    name: 'ROT13',
    category: 'Ciphers',
    description: 'Rotates alphabetical characters by 13 (or custom amount).',
    params: [
      {
        id: 'amount',
        name: 'Amount',
        type: 'number',
        default: 13,
        description: 'Number of positions to rotate (1 - 25)'
      }
    ],
    run: (input, args) => {
      const shift = ((args.amount % 26) + 26) % 26;
      return input.replace(/[a-zA-Z]/g, (c) => {
        const code = c.charCodeAt(0);
        const base = code >= 65 && code <= 90 ? 65 : 97;
        return String.fromCharCode(((code - base + shift) % 26) + base);
      });
    }
  },
  {
    id: 'xor',
    name: 'XOR',
    category: 'Ciphers',
    description: 'Applies bitwise XOR against a repeating text or hex key.',
    params: [
      {
        id: 'key',
        name: 'Key',
        type: 'string',
        default: 'secret',
        description: 'String or hex key (e.g. 5A, 0x5A, secret) used for repeating XOR'
      },
      {
        id: 'hex_output',
        name: 'Output as Hex',
        type: 'boolean',
        default: false,
        description: 'Format resulting binary data as hex string'
      }
    ],
    run: (input, args) => {
      const keyStr = String(args.key ?? 'key');
      let keyBytes: Uint8Array;
      const isHexKey = /^0x[0-9a-fA-F]+$/i.test(keyStr) || /^[0-9a-fA-F]{2}$/i.test(keyStr);
      if (isHexKey) {
        const clean = keyStr.replace(/^0x/i, '');
        const arr: number[] = [];
        for (let i = 0; i < clean.length; i += 2) {
          arr.push(parseInt(clean.substring(i, i + 2), 16));
        }
        keyBytes = new Uint8Array(arr.length ? arr : [0]);
      } else {
        keyBytes = new TextEncoder().encode(keyStr || 'key');
      }

      let isBinary = true;
      for (let i = 0; i < input.length; i++) {
        if (input.charCodeAt(i) > 255) {
          isBinary = false;
          break;
        }
      }

      let inputBytes: Uint8Array;
      if (isBinary) {
        inputBytes = new Uint8Array(input.length);
        for (let i = 0; i < input.length; i++) {
          inputBytes[i] = input.charCodeAt(i) & 0xff;
        }
      } else {
        inputBytes = new TextEncoder().encode(input);
      }

      const outBytes = new Uint8Array(inputBytes.length);
      for (let i = 0; i < inputBytes.length; i++) {
        outBytes[i] = inputBytes[i] ^ keyBytes[i % keyBytes.length];
      }

      if (args.hex_output) {
        return Array.from(outBytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
      }
      try {
        return new TextDecoder('utf-8', { fatal: true }).decode(outBytes);
      } catch {
        let res = '';
        for (let i = 0; i < outBytes.length; i++) {
          res += String.fromCharCode(outBytes[i]);
        }
        return res;
      }
    }
  },
  {
    id: 'reverse_text',
    name: 'Reverse Text',
    category: 'Ciphers',
    description: 'Reverses string character-by-character, word-by-word, or line-by-line.',
    params: [
      {
        id: 'mode',
        name: 'Mode',
        type: 'select',
        default: 'character',
        options: [
          { value: 'character', label: 'By Character (abc -> cba)' },
          { value: 'word', label: 'By Word (hello world -> world hello)' },
          { value: 'line', label: 'By Line (top to bottom)' }
        ]
      }
    ],
    run: (input, args) => {
      if (args.mode === 'line') {
        return input.split('\n').reverse().join('\n');
      }
      if (args.mode === 'word') {
        return input.split(/(\s+)/).reverse().join('');
      }
      return Array.from(input).reverse().join('');
    }
  },
  {
    id: 'atbash',
    name: 'Atbash Cipher',
    category: 'Ciphers',
    description: 'Substitutes alphabetical letters with their reverse alphabet position (A<->Z, B<->Y).',
    params: [],
    run: (input) => {
      return input.replace(/[a-zA-Z]/g, (c) => {
        const code = c.charCodeAt(0);
        if (code >= 65 && code <= 90) {
          return String.fromCharCode(90 - (code - 65));
        }
        return String.fromCharCode(122 - (code - 97));
      });
    }
  },
  {
    id: 'rot47',
    name: 'ROT47',
    category: 'Ciphers',
    description: 'Rotates standard visible ASCII characters (ASCII 33 ! through 126 ~) by 47 positions. Applying twice returns original text.',
    params: [],
    run: (input) => rot47(input)
  },
  {
    id: 'caesar_cipher',
    name: 'Caesar Cipher',
    category: 'Ciphers',
    description: 'Shifts alphabetical characters by an integer key value (-25 to +25).',
    params: [
      {
        id: 'shift',
        name: 'Shift Amount',
        type: 'number',
        default: 3,
        description: 'Number of alphabet positions to shift'
      }
    ],
    run: (input, args) => caesarCipher(input, Number(args.shift) || 3)
  },
  {
    id: 'vigenere_cipher',
    name: 'Vigenère Cipher',
    category: 'Ciphers',
    description: 'Polyalphabetic substitution cipher using a keyword to shift letters.',
    params: [
      {
        id: 'key',
        name: 'Key',
        type: 'string',
        default: 'SECRET',
        description: 'Alphabetical key string'
      },
      {
        id: 'mode',
        name: 'Mode',
        type: 'select',
        default: 'encode',
        options: [
          { value: 'encode', label: 'Encode / Encrypt' },
          { value: 'decode', label: 'Decode / Decrypt' }
        ]
      }
    ],
    run: (input, args) => vigenereCipher(input, String(args.key || 'SECRET'), args.mode === 'decode')
  },

  // 3. THREAT INTEL & DEFANGING
  {
    id: 'defang_url',
    name: 'Defang URL & IP',
    category: 'Threat Intel',
    description: 'Defangs URLs and IPs to prevent accidental clicking (http -> hxxp, . -> [.], : -> [:]).',
    params: [
      {
        id: 'defang_scheme',
        name: 'Defang Scheme (http -> hxxp)',
        type: 'boolean',
        default: true
      },
      {
        id: 'brackets_around_dots',
        name: 'Bracket Dots ([.])',
        type: 'boolean',
        default: true
      }
    ],
    run: (input, args) => {
      let res = input;
      if (args.defang_scheme) {
        res = res.replace(/https?:\/\//gi, (m) => m.toLowerCase().replace('http', 'hxxp'));
        res = res.replace(/ftp:\/\//gi, 'fxp://');
      }
      if (args.brackets_around_dots) {
        res = res.replace(/\./g, '[.]');
      }
      return res;
    }
  },
  {
    id: 'refang_url',
    name: 'Refang URL & IP',
    category: 'Threat Intel',
    description: 'Restores defanged indicators back into actionable URLs, domains, and IP addresses.',
    params: [],
    run: (input) => {
      return input
        .replace(/hxxps?:\/\//gi, (m) => m.toLowerCase().replace('hxxp', 'http'))
        .replace(/fxp:\/\//gi, 'ftp://')
        .replace(/\[\.\]/g, '.')
        .replace(/\(\.\)/g, '.')
        .replace(/\[:\]/g, ':')
        .replace(/\{\.\}/g, '.');
    }
  },
  {
    id: 'extract_urls',
    name: 'Extract URLs',
    category: 'Threat Intel',
    description: 'Extracts all HTTP/HTTPS/FTP URLs from raw text.',
    params: [
      {
        id: 'unique_only',
        name: 'Deduplicate',
        type: 'boolean',
        default: true
      }
    ],
    run: (input, args) => {
      const urlRegex = /https?:\/\/[^\s<>"'{}|\\^`[\]]+/gi;
      const matches = input.match(urlRegex) || [];
      const list = args.unique_only ? Array.from(new Set(matches)) : matches;
      return list.join('\n');
    }
  },
  {
    id: 'extract_ips',
    name: 'Extract IP Addresses',
    category: 'Threat Intel',
    description: 'Extracts valid IPv4 and IPv6 addresses from input text.',
    params: [
      {
        id: 'unique_only',
        name: 'Deduplicate',
        type: 'boolean',
        default: true
      }
    ],
    run: (input, args) => {
      const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
      const matches = input.match(ipv4Regex) || [];
      const list = args.unique_only ? Array.from(new Set(matches)) : matches;
      return list.join('\n');
    }
  },
  {
    id: 'extract_emails',
    name: 'Extract Emails',
    category: 'Threat Intel',
    description: 'Extracts valid email addresses from input.',
    params: [
      {
        id: 'unique_only',
        name: 'Deduplicate',
        type: 'boolean',
        default: true
      }
    ],
    run: (input, args) => {
      const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
      const matches = input.match(emailRegex) || [];
      const list = args.unique_only ? Array.from(new Set(matches)) : matches;
      return list.join('\n');
    }
  },
  {
    id: 'extract_hashes',
    name: 'Extract Hashes',
    category: 'Threat Intel',
    description: 'Extracts MD5 (32 hex), SHA-1 (40 hex), and SHA-256 (64 hex) hashes.',
    params: [
      {
        id: 'hash_type',
        name: 'Type',
        type: 'select',
        default: 'all',
        options: [
          { value: 'all', label: 'All Hashes' },
          { value: 'md5', label: 'MD5 (32 hex)' },
          { value: 'sha1', label: 'SHA-1 (40 hex)' },
          { value: 'sha256', label: 'SHA-256 (64 hex)' }
        ]
      }
    ],
    run: (input, args) => {
      const md5 = input.match(/\b[a-fA-F0-9]{32}\b/g) || [];
      const sha1 = input.match(/\b[a-fA-F0-9]{40}\b/g) || [];
      const sha256 = input.match(/\b[a-fA-F0-9]{64}\b/g) || [];

      let list: string[] = [];
      if (args.hash_type === 'md5') list = md5;
      else if (args.hash_type === 'sha1') list = sha1;
      else if (args.hash_type === 'sha256') list = sha256;
      else list = [...sha256, ...sha1, ...md5];

      return Array.from(new Set(list)).join('\n');
    }
  },
  {
    id: 'parse_jwt',
    name: 'Parse JWT',
    category: 'Threat Intel',
    description: 'Decodes JSON Web Token (Header, Payload, and Signature).',
    params: [],
    run: (input) => {
      const parts = input.trim().split('.');
      if (parts.length < 2) {
        throw new Error('Input is not a valid JWT token (must contain at least 2 dot-separated parts).');
      }
      const decodeB64Url = (str: string, section: string) => {
        let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4 !== 0) b64 += '=';
        try {
          const raw = atob(b64);
          try {
            return JSON.parse(decodeURIComponent(escape(raw)));
          } catch {
            return JSON.parse(raw);
          }
        } catch (e: any) {
          throw new Error(`Failed to decode JWT ${section}: ${e.message}`);
        }
      };

      const header = decodeB64Url(parts[0], 'header');
      const payload = decodeB64Url(parts[1], 'payload');

      return JSON.stringify(
        {
          header,
          payload,
          signature: parts[2] || '[none]'
        },
        null,
        2
      );
    }
  },
  {
    id: 'extract_domains',
    name: 'Extract Domains',
    category: 'Threat Intel',
    description: 'Extracts all fully qualified domain names (FQDN) from unstructured text.',
    params: [
      {
        id: 'unique_only',
        name: 'Unique Only',
        type: 'boolean',
        default: true,
        description: 'Deduplicate extracted domain names'
      }
    ],
    run: (input, args) => extractDomains(input, args.unique_only !== false)
  },
  {
    id: 'extract_file_paths',
    name: 'Extract File Paths',
    category: 'Threat Intel',
    description: 'Extracts Windows drive paths (C:\\...), UNC network shares (\\\\host\\share), and POSIX filesystem paths (/usr/bin/...).',
    params: [
      {
        id: 'unique_only',
        name: 'Unique Only',
        type: 'boolean',
        default: true,
        description: 'Deduplicate extracted paths'
      }
    ],
    run: (input, args) => extractFilePaths(input, args.unique_only !== false)
  },
  {
    id: 'parse_uri',
    name: 'Parse URI',
    category: 'Threat Intel',
    description: 'Parses and decomposes uniform resource identifiers into protocol, host, port, path, query parameters, and fragments.',
    params: [],
    run: (input) => parseUri(input)
  },

  // 4. STRING UTILITIES
  {
    id: 'to_upper',
    name: 'To Upper Case',
    category: 'String Utilities',
    description: 'Converts all characters to UPPERCASE.',
    params: [],
    run: (input) => input.toUpperCase()
  },
  {
    id: 'to_lower',
    name: 'To Lower Case',
    category: 'String Utilities',
    description: 'Converts all characters to lowercase.',
    params: [],
    run: (input) => input.toLowerCase()
  },
  {
    id: 'trim',
    name: 'Trim Whitespace',
    category: 'String Utilities',
    description: 'Removes leading and trailing whitespace from input or per line.',
    params: [
      {
        id: 'per_line',
        name: 'Per Line',
        type: 'boolean',
        default: true
      }
    ],
    run: (input, args) => {
      if (args.per_line) {
        return input.split('\n').map(l => l.trim()).join('\n');
      }
      return input.trim();
    }
  },
  {
    id: 'find_replace',
    name: 'Find & Replace',
    category: 'String Utilities',
    description: 'Replaces matches using plain text or regular expressions.',
    params: [
      {
        id: 'find',
        name: 'Find',
        type: 'string',
        default: '',
        description: 'Target pattern to locate'
      },
      {
        id: 'replace',
        name: 'Replace With',
        type: 'string',
        default: '',
        description: 'Replacement string'
      },
      {
        id: 'regex',
        name: 'Use Regular Expression',
        type: 'boolean',
        default: false
      },
      {
        id: 'case_insensitive',
        name: 'Case Insensitive (i)',
        type: 'boolean',
        default: false
      }
    ],
    run: (input, args) => {
      if (!args.find) return input;
      if (args.regex) {
        const flags = (args.case_insensitive ? 'i' : '') + 'g';
        const re = new RegExp(args.find, flags);
        return input.replace(re, args.replace || '');
      }
      if (args.case_insensitive) {
        const escaped = args.find.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        return input.replace(new RegExp(escaped, 'gi'), args.replace || '');
      }
      return input.split(args.find).join(args.replace || '');
    }
  },
  {
    id: 'split_join',
    name: 'Split & Join',
    category: 'String Utilities',
    description: 'Splits string by a delimiter and re-joins with a new delimiter.',
    params: [
      {
        id: 'split_by',
        name: 'Split By',
        type: 'string',
        default: ',',
        description: 'Character or substring to split on'
      },
      {
        id: 'join_by',
        name: 'Join By',
        type: 'string',
        default: '\\n',
        description: 'Replacement delimiter (supports \\n, \\t)'
      }
    ],
    run: (input, args) => {
      const splitBy = args.split_by || ',';
      let joinBy = args.join_by || '\n';
      joinBy = joinBy.replace(/\\n/g, '\n').replace(/\\t/g, '\t');
      return input.split(splitBy).join(joinBy);
    }
  },
  {
    id: 'sort_lines',
    name: 'Sort Lines',
    category: 'String Utilities',
    description: 'Sorts lines alphabetically, numerically, or by length.',
    params: [
      {
        id: 'order',
        name: 'Order',
        type: 'select',
        default: 'alphabetical',
        options: [
          { value: 'alphabetical', label: 'Alphabetical (A - Z)' },
          { value: 'reverse', label: 'Reverse Alphabetical (Z - A)' },
          { value: 'length', label: 'By Line Length' },
          { value: 'numeric', label: 'Numeric' }
        ]
      }
    ],
    run: (input, args) => {
      const lines = input.split('\n');
      if (args.order === 'reverse') {
        lines.sort((a, b) => b.localeCompare(a));
      } else if (args.order === 'length') {
        lines.sort((a, b) => a.length - b.length);
      } else if (args.order === 'numeric') {
        lines.sort((a, b) => (parseFloat(a) || 0) - (parseFloat(b) || 0));
      } else {
        lines.sort((a, b) => a.localeCompare(b));
      }
      return lines.join('\n');
    }
  },
  {
    id: 'unique_lines',
    name: 'Unique Lines',
    category: 'String Utilities',
    description: 'Removes duplicate lines from text.',
    params: [
      {
        id: 'case_sensitive',
        name: 'Case Sensitive',
        type: 'boolean',
        default: true
      }
    ],
    run: (input, args) => {
      const lines = input.split('\n');
      if (args.case_sensitive) {
        return Array.from(new Set(lines)).join('\n');
      }
      const seen = new Set<string>();
      const result: string[] = [];
      for (const line of lines) {
        const lower = line.toLowerCase();
        if (!seen.has(lower)) {
          seen.add(lower);
          result.push(line);
        }
      }
      return result.join('\n');
    }
  },
  {
    id: 'add_line_numbers',
    name: 'Add Line Numbers',
    category: 'String Utilities',
    description: 'Prepends line numbers to each line of text.',
    params: [
      {
        id: 'start',
        name: 'Start At',
        type: 'number',
        default: 1
      },
      {
        id: 'pad',
        name: 'Padded (01, 02)',
        type: 'boolean',
        default: true
      }
    ],
    run: (input, args) => {
      const lines = input.split('\n');
      const start = args.start || 1;
      const padLen = args.pad ? String(lines.length + start).length : 1;
      return lines
        .map((line, idx) => `${String(idx + start).padStart(padLen, '0')}: ${line}`)
        .join('\n');
    }
  },
  {
    id: 'format_json',
    name: 'Format JSON',
    category: 'String Utilities',
    description: 'Prettifies minified JSON with indentation.',
    params: [
      {
        id: 'indent',
        name: 'Indent Spaces',
        type: 'number',
        default: 2
      }
    ],
    run: (input, args) => {
      const parsed = JSON.parse(input.trim());
      return JSON.stringify(parsed, null, args.indent || 2);
    }
  },
  {
    id: 'minify_json',
    name: 'Minify JSON',
    category: 'String Utilities',
    description: 'Removes all unnecessary whitespace and indentation from JSON.',
    params: [],
    run: (input) => {
      const parsed = JSON.parse(input.trim());
      return JSON.stringify(parsed);
    }
  },
  {
    id: 'strip_html_tags',
    name: 'Strip HTML Tags',
    category: 'String Utilities',
    description: 'Removes all HTML and XML markup tags, optionally preserving paragraph and line breaks.',
    params: [
      {
        id: 'preserve_breaks',
        name: 'Preserve Line Breaks',
        type: 'boolean',
        default: true,
        description: 'Convert <p> and <br> tags into newlines'
      }
    ],
    run: (input, args) => stripHtmlTags(input, args.preserve_breaks !== false)
  },
  {
    id: 'head_lines',
    name: 'Head (First N Lines)',
    category: 'String Utilities',
    description: 'Extracts the first N lines from text (similar to Unix head).',
    params: [
      {
        id: 'lines',
        name: 'Line Count',
        type: 'number',
        default: 10,
        description: 'Number of lines to output from start'
      }
    ],
    run: (input, args) => headLines(input, Number(args.lines) || 10)
  },
  {
    id: 'tail_lines',
    name: 'Tail (Last N Lines)',
    category: 'String Utilities',
    description: 'Extracts the last N lines from text (similar to Unix tail).',
    params: [
      {
        id: 'lines',
        name: 'Line Count',
        type: 'number',
        default: 10,
        description: 'Number of lines to output from end'
      }
    ],
    run: (input, args) => tailLines(input, Number(args.lines) || 10)
  },
  {
    id: 'pad_lines',
    name: 'Pad Lines',
    category: 'String Utilities',
    description: 'Pads lines to a fixed character width using a padding character.',
    params: [
      {
        id: 'length',
        name: 'Target Width',
        type: 'number',
        default: 40,
        description: 'Desired line length'
      },
      {
        id: 'position',
        name: 'Position',
        type: 'select',
        default: 'right',
        options: [
          { value: 'right', label: 'Right Pad' },
          { value: 'left', label: 'Left Pad' }
        ]
      },
      {
        id: 'char',
        name: 'Pad Character',
        type: 'string',
        default: ' ',
        description: 'Character used for padding'
      }
    ],
    run: (input, args) => padLines(input, Number(args.length) || 40, args.position || 'right', args.char || ' ')
  },
  {
    id: 'count_occurrences',
    name: 'Count Occurrences',
    category: 'String Utilities',
    description: 'Counts the number of occurrences of a string or regular expression.',
    params: [
      {
        id: 'target',
        name: 'Search Target / Pattern',
        type: 'string',
        default: '',
        description: 'String or regex pattern to search for'
      },
      {
        id: 'regex',
        name: 'Regex Search',
        type: 'boolean',
        default: false,
        description: 'Treat search string as a regular expression'
      },
      {
        id: 'case_sensitive',
        name: 'Case Sensitive',
        type: 'boolean',
        default: false,
        description: 'Match exact casing'
      }
    ],
    run: (input, args) => countOccurrences(input, String(args.target || ''), Boolean(args.regex), Boolean(args.case_sensitive))
  },

  // 5. HASHES & CHECKSUMS
  {
    id: 'hash_md5',
    name: 'MD5',
    category: 'Hashes',
    description: 'Computes MD5 hash checksum (32 hex characters).',
    params: [],
    run: (input) => md51(input)
  },
  {
    id: 'hash_sha1',
    name: 'SHA-1',
    category: 'Hashes',
    description: 'Computes SHA-1 cryptographic hash (40 hex characters).',
    params: [],
    run: async (input) => await cryptoSubtleHash(input, 'SHA-1')
  },
  {
    id: 'hash_sha256',
    name: 'SHA-256',
    category: 'Hashes',
    description: 'Computes SHA-256 cryptographic hash (64 hex characters).',
    params: [],
    run: async (input) => await cryptoSubtleHash(input, 'SHA-256')
  },
  {
    id: 'hash_sha512',
    name: 'SHA-512',
    category: 'Hashes',
    description: 'Computes SHA-512 cryptographic hash (128 hex characters).',
    params: [],
    run: async (input) => await cryptoSubtleHash(input, 'SHA-512')
  },
  {
    id: 'hash_crc32',
    name: 'CRC32',
    category: 'Hashes',
    description: 'Computes standard CRC32 checksum (8 hex characters).',
    params: [],
    run: (input) => crc32(input)
  },
  {
    id: 'hash_adler32',
    name: 'Adler-32',
    category: 'Hashes',
    description: 'Computes standard Adler-32 rolling checksum (8 hex characters).',
    params: [],
    run: (input) => adler32(input)
  },

  // 6. FORENSICS & TIMESTAMPS
  {
    id: 'unix_timestamp_to_date',
    name: 'Unix Timestamp to Date',
    category: 'Forensics',
    description: 'Converts Unix epoch timestamp (seconds or milliseconds) into ISO 8601 UTC date string.',
    params: [
      {
        id: 'unit',
        name: 'Unit',
        type: 'select',
        default: 'auto',
        options: [
          { value: 'auto', label: 'Auto Detect (sec vs ms)' },
          { value: 'seconds', label: 'Seconds (10 digits)' },
          { value: 'milliseconds', label: 'Milliseconds (13 digits)' }
        ]
      }
    ],
    run: (input, args) => {
      const num = parseFloat(input.trim());
      if (isNaN(num)) throw new Error('Input is not a valid numeric Unix timestamp.');

      let ms = num;
      if (args.unit === 'seconds' || (args.unit === 'auto' && num < 10000000000)) {
        ms = num * 1000;
      }
      const d = new Date(ms);
      if (isNaN(d.getTime())) throw new Error('Calculated date is invalid.');
      return d.toISOString();
    }
  },
  {
    id: 'windows_filetime_to_date',
    name: 'Windows FileTime to Date',
    category: 'Forensics',
    description: 'Converts Windows 64-bit FileTime (100ns intervals since Jan 1, 1601) into ISO 8601 UTC date.',
    params: [],
    run: (input) => {
      const clean = input.replace(/[^0-9]/g, '');
      if (!clean) throw new Error('Input is not a valid numeric Windows FileTime.');
      const filetime = BigInt(clean);
      // Windows epoch starts 1601-01-01, Unix epoch starts 1970-01-01.
      // Difference is 11,644,473,600 seconds = 116,444,736,000,000,000 100ns intervals.
      const EPOCH_DIFFERENCE = BigInt('116444736000000000');
      const unixNano100 = filetime - EPOCH_DIFFERENCE;
      const unixMs = Number(unixNano100 / BigInt(10000));
      const d = new Date(unixMs);
      if (isNaN(d.getTime())) throw new Error('Invalid Windows FileTime timestamp.');
      return d.toISOString();
    }
  },
  {
    id: 'date_to_unix_timestamp',
    name: 'Date to Unix Timestamp',
    category: 'Forensics',
    description: 'Parses human-readable date/time string into Unix epoch timestamp.',
    params: [
      {
        id: 'unit',
        name: 'Output Unit',
        type: 'select',
        default: 'seconds',
        options: [
          { value: 'seconds', label: 'Seconds (10 digits)' },
          { value: 'milliseconds', label: 'Milliseconds (13 digits)' }
        ]
      }
    ],
    run: (input, args) => dateToUnixTimestamp(input, args.unit || 'seconds')
  },
  {
    id: 'date_to_windows_filetime',
    name: 'Date to Windows FileTime',
    category: 'Forensics',
    description: 'Converts date string to 64-bit Windows FILETIME (100-nanosecond intervals since Jan 1, 1601).',
    params: [],
    run: (input) => dateToWindowsFiletime(input)
  },
  {
    id: 'extract_strings',
    name: 'Extract Strings',
    category: 'Forensics',
    description: 'Extracts sequences of printable ASCII characters (minimum length threshold) from mixed or binary data.',
    params: [
      {
        id: 'min_length',
        name: 'Min Length',
        type: 'number',
        default: 4,
        description: 'Minimum number of consecutive printable ASCII characters (3-32)'
      }
    ],
    run: (input, args) => {
      const minLen = Math.max(1, Number(args.min_length) || 4);
      const regex = new RegExp(`[\\x20-\\x7E]{${minLen},}`, 'g');
      const matches = input.match(regex) || [];
      return matches.join('\n');
    }
  },
  {
    id: 'remove_null_bytes',
    name: 'Remove Null Bytes',
    category: 'String Utilities',
    description: 'Strips 0x00 null bytes, converting UTF-16LE binary-spaced strings (e.g. PowerShell payloads) to clean ASCII.',
    params: [],
    run: (input) => {
      return input.replace(/\x00/g, '');
    }
  }
];

// Helper to look up an operation by ID
export function getOperationById(id: string): DecoderOperation | undefined {
  return DECODER_OPERATIONS.find(op => op.id === id);
}

// Recipe execution pipeline
export async function executeRecipe(
  input: string,
  recipe: RecipeStep[]
): Promise<{ output: string; executionTimeMs: number; errorStepIndex?: number; errorMessage?: string }> {
  const startTime = performance.now();
  let current = input;

  for (let i = 0; i < recipe.length; i++) {
    const step = recipe[i];
    if (step.disabled) continue;

    const op = getOperationById(step.operationId);
    if (!op) continue;

    try {
      current = await op.run(current, step.args);
    } catch (err: any) {
      return {
        output: current,
        executionTimeMs: performance.now() - startTime,
        errorStepIndex: i,
        errorMessage: `Step ${i + 1} (${op.name}) failed: ${err?.message || String(err)}`
      };
    }
  }

  return {
    output: current,
    executionTimeMs: performance.now() - startTime
  };
}

export interface DecoderPreset {
  id: string;
  name: string;
  category: 'Malware Research' | 'Binary Analysis' | 'Vulnerability Research' | 'Threat Intel & Defanging' | string;
  description: string;
  steps: Array<{
    operationId: string;
    args: Record<string, any>;
    disabled?: boolean;
  }>;
}

// Built-in presets categorized for Malware Research, Binary Analysis, Vulnerability Research, and IOC Defanging
export const DECODER_PRESETS: DecoderPreset[] = [
  // Malware Research Presets
  {
    id: 'malware_xor_b64',
    name: 'Malware XOR & Base64 Unpack',
    category: 'Malware Research',
    description: 'Decode Base64 payload, apply XOR key 0x5A, extract printable strings, and defang IOCs',
    steps: [
      { operationId: 'from_base64', args: { strict: false }, disabled: false },
      { operationId: 'xor', args: { key: '5A', hex_output: false }, disabled: false },
      { operationId: 'extract_strings', args: { min_length: 4 }, disabled: false },
      { operationId: 'defang_url', args: { defang_scheme: true, brackets_around_dots: true }, disabled: false }
    ]
  },
  {
    id: 'powershell_b64',
    name: 'PowerShell -EncodedCommand',
    category: 'Malware Research',
    description: 'Decode PowerShell Base64 payload, remove null padding bytes, and extract URLs',
    steps: [
      { operationId: 'from_base64', args: { strict: false }, disabled: false },
      { operationId: 'remove_null_bytes', args: {}, disabled: false },
      { operationId: 'extract_urls', args: { unique_only: true }, disabled: false },
      { operationId: 'defang_url', args: { defang_scheme: true, brackets_around_dots: true }, disabled: false }
    ]
  },
  {
    id: 'malware_rev_b64',
    name: 'Reversed Base64 Recovery',
    category: 'Malware Research',
    description: 'Reverse string sequence, decode Base64, and trim whitespace',
    steps: [
      { operationId: 'reverse_text', args: { mode: 'character' }, disabled: false },
      { operationId: 'from_base64', args: { strict: false }, disabled: false },
      { operationId: 'trim', args: { per_line: true }, disabled: false }
    ]
  },
  {
    id: 'malware_c2_dropper',
    name: 'C2 Dropper IOC Extractor',
    category: 'Malware Research',
    description: 'Extract URLs and IPs, defang protocols, and deduplicate IOC lines',
    steps: [
      { operationId: 'extract_urls', args: { unique_only: true }, disabled: false },
      { operationId: 'defang_url', args: { defang_scheme: true, brackets_around_dots: true }, disabled: false },
      { operationId: 'unique_lines', args: { case_sensitive: false }, disabled: false },
      { operationId: 'sort_lines', args: { order: 'alphabetical' }, disabled: false }
    ]
  },

  // Binary Analysis Presets
  {
    id: 'binary_hex_strings',
    name: 'Hex Dump to ASCII Strings',
    category: 'Binary Analysis',
    description: 'Decode raw hexadecimal dump, filter printable strings, and add line numbers',
    steps: [
      { operationId: 'from_hex', args: { ignore_errors: true }, disabled: false },
      { operationId: 'extract_strings', args: { min_length: 4 }, disabled: false },
      { operationId: 'add_line_numbers', args: { start: 1, pad: 3 }, disabled: false }
    ]
  },
  {
    id: 'binary_bitwise_not',
    name: 'Bitwise NOT / XOR 0xFF Invert',
    category: 'Binary Analysis',
    description: 'Invert bytes with 0xFF bitwise key, decode hex, and extract strings',
    steps: [
      { operationId: 'xor', args: { key: 'FF', hex_output: false }, disabled: false },
      { operationId: 'from_hex', args: { ignore_errors: true }, disabled: false },
      { operationId: 'extract_strings', args: { min_length: 4 }, disabled: false }
    ]
  },

  // Vulnerability Research Presets
  {
    id: 'vuln_xss_multidecode',
    name: 'Web Exploit & XSS Multi-Decode',
    category: 'Vulnerability Research',
    description: 'Multi-stage URL decoding followed by HTML entity decoding for payload analysis',
    steps: [
      { operationId: 'from_url', args: {}, disabled: false },
      { operationId: 'from_html_entity', args: {}, disabled: false },
      { operationId: 'trim', args: { per_line: false }, disabled: false }
    ]
  },
  {
    id: 'vuln_sqli_unmask',
    name: 'SQLi Hex & URL Unmasker',
    category: 'Vulnerability Research',
    description: 'Decode hex-encoded SQL injection vectors and URL-encoded query strings',
    steps: [
      { operationId: 'from_hex', args: { ignore_errors: true }, disabled: false },
      { operationId: 'from_url', args: {}, disabled: false },
      { operationId: 'unique_lines', args: { case_sensitive: false }, disabled: false }
    ]
  },
  {
    id: 'vuln_jwt_exploit',
    name: 'JWT Attack Surface Dissector',
    category: 'Vulnerability Research',
    description: 'Trim whitespace and parse JSON Web Token headers, claims payload, and signature',
    steps: [
      { operationId: 'trim', args: { per_line: false }, disabled: false },
      { operationId: 'parse_jwt', args: {}, disabled: false }
    ]
  },
  {
    id: 'vuln_path_traversal',
    name: 'Path Traversal Double-URL Normalize',
    category: 'Vulnerability Research',
    description: 'Double URL decode to unpack nested %252e%252e directory traversal attempts',
    steps: [
      { operationId: 'from_url', args: {}, disabled: false },
      { operationId: 'from_url', args: {}, disabled: false },
      { operationId: 'trim', args: { per_line: true }, disabled: false }
    ]
  },

  // Threat Intel & General Presets
  {
    id: 'defang_all',
    name: 'Extract & Defang IOCs',
    category: 'Threat Intel & Defanging',
    description: 'Extract URLs, bracket dots, and defang protocols',
    steps: [
      { operationId: 'extract_urls', args: { unique_only: true }, disabled: false },
      { operationId: 'defang_url', args: { defang_scheme: true, brackets_around_dots: true }, disabled: false }
    ]
  },
  {
    id: 'decode_b64_json',
    name: 'Base64 to Pretty JSON',
    category: 'Threat Intel & Defanging',
    description: 'Decode Base64 payload and format as indented JSON',
    steps: [
      { operationId: 'from_base64', args: { strict: false }, disabled: false },
      { operationId: 'format_json', args: { indent: 2 }, disabled: false }
    ]
  },
  {
    id: 'clean_ioc_list',
    name: 'Deduplicate & Sort IOC List',
    category: 'Threat Intel & Defanging',
    description: 'Trim, deduplicate unique lines, and sort alphabetically',
    steps: [
      { operationId: 'trim', args: { per_line: true }, disabled: false },
      { operationId: 'unique_lines', args: { case_sensitive: false }, disabled: false },
      { operationId: 'sort_lines', args: { order: 'alphabetical' }, disabled: false }
    ]
  },
  {
    id: 'binary_hexdump_parse',
    name: 'Hexdump Parser & Extractor',
    category: 'Binary Analysis',
    description: 'Parse raw hexdump into bytes, extract printable strings, and deduplicate lines',
    steps: [
      { operationId: 'from_hexdump', args: {}, disabled: false },
      { operationId: 'extract_strings', args: { min_length: 4 }, disabled: false },
      { operationId: 'unique_lines', args: { case_sensitive: false }, disabled: false }
    ]
  },
  {
    id: 'malware_rot47_b64',
    name: 'ROT47 & Base64 Payload Decrypt',
    category: 'Malware Research',
    description: 'Reverse ROT47 obfuscation and decode Base64 payload',
    steps: [
      { operationId: 'rot47', args: {}, disabled: false },
      { operationId: 'from_base64', args: { strict: false }, disabled: false },
      { operationId: 'trim', args: { per_line: true }, disabled: false }
    ]
  },
  {
    id: 'threat_extract_all_iocs',
    name: 'Full Domain & URL IOC Harvester',
    category: 'Threat Intel & Defanging',
    description: 'Extract URLs and domains, deduplicate and defang',
    steps: [
      { operationId: 'extract_urls', args: { unique_only: true }, disabled: false },
      { operationId: 'defang_url', args: { defang_scheme: true, brackets_around_dots: true }, disabled: false },
      { operationId: 'unique_lines', args: { case_sensitive: false }, disabled: false },
      { operationId: 'sort_lines', args: { order: 'alphabetical' }, disabled: false }
    ]
  }
];
