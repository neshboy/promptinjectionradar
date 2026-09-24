/**
 * Shannon-entropy-aware base64 detection.
 *
 * We don't just regex-match "looks like base64" - lots of things look like
 * base64 (long hex ids, hashes, path segments) but aren't an encoded
 * instruction block. Instead we:
 *   1. find candidate substrings using the base64 charset,
 *   2. require a minimum length,
 *   3. compute the Shannon entropy of the candidate and require it be high
 *      enough to look like encoded data rather than e.g. "aaaaaaaaaa...",
 *   4. actually decode it and verify it round-trips back to the same
 *      base64 text (proving it's real, well-formed base64, not a random
 *      run of base64-alphabet characters),
 *   5. check the decoded bytes are plausible UTF-8 text (high printable
 *      ratio, no replacement characters) before treating it as text worth
 *      re-scanning.
 */

export interface Base64Candidate {
  raw: string;
  index: number;
}

export interface DecodedBase64 {
  raw: string;
  index: number;
  decoded: string;
  entropy: number;
}

const BASE64_CANDIDATE_RE = /[A-Za-z0-9+/]{24,}={0,2}/g;

export const MIN_BASE64_LENGTH = 24;
export const MIN_BASE64_ENTROPY = 3.2; // bits/char; random text-derived base64 is usually ~4-4.5
export const MIN_PRINTABLE_RATIO = 0.85;

/** Shannon entropy of a string, in bits per character. */
export function shannonEntropy(input: string): number {
  if (input.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of input) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / input.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Find raw base64-charset substrings above the minimum length. */
export function findBase64Candidates(text: string): Base64Candidate[] {
  const candidates: Base64Candidate[] = [];
  for (const match of text.matchAll(BASE64_CANDIDATE_RE)) {
    if (match.index === undefined) continue;
    candidates.push({ raw: match[0], index: match.index });
  }
  return candidates;
}

/**
 * Fraction of characters in `s` that are "plausible" plain text: printable
 * ASCII, common punctuation, or whitespace. Used to reject decoded binary
 * garbage that happens to survive a naive UTF-8 decode.
 */
function printableRatio(s: string): number {
  if (s.length === 0) return 0;
  let printable = 0;
  for (const ch of s) {
    const code = ch.codePointAt(0) ?? 0;
    const isPrintableAscii = code >= 0x20 && code <= 0x7e;
    const isWhitespace = code === 0x09 || code === 0x0a || code === 0x0d;
    if (isPrintableAscii || isWhitespace) printable++;
  }
  return printable / s.length;
}

/**
 * Attempt to decode a base64 candidate. Returns the decoded text only if:
 *   - the candidate meets the length + entropy thresholds,
 *   - it round-trips exactly back to the same base64 (ignoring padding),
 *   - the decoded bytes are valid UTF-8 with no replacement characters,
 *   - the decoded text is mostly printable (so it reads like instructions,
 *     not compressed/binary data).
 */
export function tryDecodeBase64(candidate: string): string | null {
  if (candidate.length < MIN_BASE64_LENGTH) return null;

  const entropy = shannonEntropy(candidate);
  if (entropy < MIN_BASE64_ENTROPY) return null;

  let buf: Buffer;
  try {
    buf = Buffer.from(candidate, "base64");
  } catch {
    return null;
  }
  if (buf.length === 0) return null;

  // Round-trip check: re-encoding the decoded bytes must reproduce the
  // original candidate (modulo '=' padding), proving this is well-formed
  // base64 and not just an accidental run of base64-alphabet characters.
  const reencoded = buf.toString("base64").replace(/=+$/, "");
  const stripped = candidate.replace(/=+$/, "");
  if (reencoded !== stripped) return null;

  // Reject if the UTF-8 decode is lossy (contains the replacement char but
  // the original bytes didn't intend one).
  const text = buf.toString("utf8");
  if (text.includes("�")) return null;

  if (printableRatio(text) < MIN_PRINTABLE_RATIO) return null;

  return text;
}

/**
 * Scan `text` for base64 candidates and return the ones that decode to
 * plausible text, along with their entropy for reporting/debugging.
 */
export function findDecodableBase64Blocks(text: string): {
  candidates: Base64Candidate[];
  decoded: DecodedBase64[];
} {
  const candidates = findBase64Candidates(text);
  const decoded: DecodedBase64[] = [];
  for (const candidate of candidates) {
    const result = tryDecodeBase64(candidate.raw);
    if (result !== null) {
      decoded.push({
        raw: candidate.raw,
        index: candidate.index,
        decoded: result,
        entropy: shannonEntropy(candidate.raw),
      });
    }
  }
  return { candidates, decoded };
}
