import { PATTERN_RULES } from "./patterns.js";
import { findDecodableBase64Blocks } from "./entropy.js";
import {
  findCssHiddenBlocks,
  findHtmlComments,
  findZeroWidthChars,
  stripZeroWidthChars,
} from "./hidden.js";
import type {
  Finding,
  FindingSource,
  ScanOptions,
  ScanResult,
  ScanStats,
  Severity,
} from "./types.js";

const SEVERITY_RANK: Record<Severity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const DEFAULT_FAIL_ON: Severity = "high";
const DEFAULT_MAX_DECODE_DEPTH = 1;

// Precompute a global-flag RegExp for each rule once at module load, rather
// than recompiling one from scratch on every runPatternLibrary() call (which
// happens once for the plain pass, once per zero-width-stripped pass, once
// per HTML comment, once per CSS-hidden block, and once per decoded base64
// block). String.prototype.matchAll() resets lastIndex internally per call,
// so reusing the same compiled RegExp instance across calls is safe.
const GLOBAL_RULES = PATTERN_RULES.map((rule) => ({
  ...rule,
  re: new RegExp(rule.pattern.source, rule.pattern.flags.includes("g") ? rule.pattern.flags : rule.pattern.flags + "g"),
}));

/** Run the core pattern library (direct_override, exfiltration, fetch_execute, authority_escalation) against a plain string. */
function runPatternLibrary(
  text: string,
  source: FindingSource,
  decodedContent?: string,
): Finding[] {
  const findings: Finding[] = [];
  for (const rule of GLOBAL_RULES) {
    for (const m of text.matchAll(rule.re)) {
      if (m.index === undefined) continue;
      findings.push({
        ruleId: rule.id,
        category: rule.category,
        severity: rule.severity,
        description: rule.description,
        matchedText: m[0],
        index: m.index,
        source,
        ...(decodedContent !== undefined ? { decodedContent } : {}),
      });
    }
  }
  return findings;
}

/**
 * Scan `content` (untrusted text pulled from a web page, document, or tool
 * output) for prompt-injection attempts.
 *
 * This looks for:
 *   - direct instruction-override language, exfiltration instructions,
 *     fetch-and-execute instructions, and authority-escalation language
 *     anywhere in the visible text,
 *   - zero-width/invisible Unicode characters, which are flagged on their
 *     own and whose removal is re-scanned (a phrase can be split up with
 *     invisible characters to dodge a naive scanner while still rendering
 *     normally to a human or being read as a whole by a text extractor),
 *   - HTML comments (never rendered, but present in raw fetched HTML),
 *   - CSS-hidden text (display:none, visibility:hidden, opacity:0,
 *     font-size:0, white-on-white),
 *   - base64-looking blocks that decode (via a Shannon-entropy-checked,
 *     round-trip-verified decoder) to plausible UTF-8 text, which are then
 *     recursively re-scanned with the same pattern library.
 *
 * All discovered obfuscated/hidden text is re-run through the same pattern
 * library used for plain text, so an attacker can't dodge detection just by
 * moving the payload into a comment, a hidden span, or a base64 blob.
 */
export function scan(content: string, options: ScanOptions = {}): ScanResult {
  const maxDecodeDepth = options.maxDecodeDepth ?? DEFAULT_MAX_DECODE_DEPTH;
  const findings: Finding[] = [];
  const base64Candidates = new Set<string>();
  let base64DecodedCount = 0;

  // 1. Plain-text pattern matches.
  findings.push(...runPatternLibrary(content, "plain"));

  // 2. Zero-width / invisible character detection.
  const zeroWidthMatches = findZeroWidthChars(content);
  if (zeroWidthMatches.length > 0) {
    findings.push({
      ruleId: "hidden.zero-width-characters",
      category: "hidden_content",
      severity: "medium",
      description: `Found ${zeroWidthMatches.length} zero-width/invisible Unicode character(s) (${[
        ...new Set(zeroWidthMatches.map((z) => z.codePoint)),
      ].join(", ")}), which can hide or splice text invisibly.`,
      matchedText: zeroWidthMatches
        .slice(0, 20)
        .map((z) => z.codePoint)
        .join(","),
      index: zeroWidthMatches[0].index,
      source: "plain",
    });

    // Strip them and re-run the pattern library: a phrase can be broken up
    // with invisible characters specifically to dodge naive keyword/regex
    // scanning while still reading correctly once stripped (or rendering
    // identically to a human either way, since the characters are invisible).
    const stripped = stripZeroWidthChars(content);
    if (stripped !== content) {
      const revealedFindings = runPatternLibrary(stripped, "zero-width-stripped", stripped);
      // Only keep findings that were NOT already found in the plain pass,
      // i.e. ones that only appear once the invisible characters are removed.
      const plainMatchKeys = new Set(
        findings.filter((f) => f.source === "plain").map((f) => `${f.ruleId}:${f.matchedText}`),
      );
      for (const f of revealedFindings) {
        if (!plainMatchKeys.has(`${f.ruleId}:${f.matchedText}`)) {
          findings.push(f);
        }
      }

      // Also re-run base64 detection on the stripped text: an attacker can
      // splice a zero-width character into an otherwise-valid base64 blob
      // to dodge the base64 detector below (which only sees the original,
      // still-spliced `content`) while the blob decodes just fine once the
      // invisible character is removed.
      if (maxDecodeDepth > 0) {
        const { candidates, decoded } = findDecodableBase64Blocks(stripped);
        for (const c of candidates) base64Candidates.add(c.raw);
        base64DecodedCount += decoded.length;
        for (const block of decoded) {
          findings.push({
            ruleId: "encoded.base64-decoded-block",
            category: "encoded_instructions",
            severity: "medium",
            description: `Found a base64-encoded block (revealed after stripping zero-width characters) that decodes to plausible text (entropy ${block.entropy.toFixed(
              2,
            )} bits/char). Decoded content was re-scanned.`,
            matchedText: block.raw.slice(0, 120),
            index: block.index,
            source: "base64-decoded",
            decodedContent: block.decoded,
          });
          findings.push(...runPatternLibrary(block.decoded, "base64-decoded", block.decoded));
        }
      }
    }
  }

  // 3. HTML comments.
  const comments = findHtmlComments(content);
  for (const comment of comments) {
    if (!comment.content.trim()) continue;
    findings.push({
      ruleId: "hidden.html-comment",
      category: "hidden_content",
      severity: "low",
      description: "Content contains an HTML comment, which is invisible when rendered but visible to a raw text/HTML reader.",
      matchedText: comment.content.slice(0, 200),
      index: comment.index,
      source: "html-comment",
    });
    findings.push(...runPatternLibrary(comment.content, "html-comment", comment.content));
  }

  // 4. CSS-hidden blocks (display:none, opacity:0, white-on-white, etc).
  const cssHidden = findCssHiddenBlocks(content);
  for (const block of cssHidden) {
    findings.push({
      ruleId: `hidden.css-${block.reason}`,
      category: "hidden_content",
      severity: "medium",
      description: `Content contains a <${block.tag}> element hidden via CSS (${block.reason}) that would not be visible to a human reader.`,
      matchedText: block.innerText.slice(0, 200),
      index: block.index,
      source: "css-hidden",
    });
    findings.push(...runPatternLibrary(block.innerText, "css-hidden", block.innerText));
  }

  // 5. Base64 blocks: entropy-checked, round-trip-verified decode, then
  //    recursively re-scan the decoded text (bounded by maxDecodeDepth).
  if (maxDecodeDepth > 0) {
    const { candidates, decoded } = findDecodableBase64Blocks(content);
    for (const c of candidates) base64Candidates.add(c.raw);
    base64DecodedCount += decoded.length;
    for (const block of decoded) {
      findings.push({
        ruleId: "encoded.base64-decoded-block",
        category: "encoded_instructions",
        severity: "medium",
        description: `Found a base64-encoded block that decodes to plausible text (entropy ${block.entropy.toFixed(
          2,
        )} bits/char). Decoded content was re-scanned.`,
        matchedText: block.raw.slice(0, 120),
        index: block.index,
        source: "base64-decoded",
        decodedContent: block.decoded,
      });
      findings.push(...runPatternLibrary(block.decoded, "base64-decoded", block.decoded));
    }
  }

  const stats: ScanStats = {
    inputLength: content.length,
    zeroWidthCharCount: zeroWidthMatches.length,
    htmlCommentCount: comments.length,
    cssHiddenBlockCount: cssHidden.length,
    base64CandidateCount: base64Candidates.size,
    base64DecodedCount,
  };

  const maxSeverity = findings.reduce<Severity | "none">((max, f) => {
    if (max === "none") return f.severity;
    return SEVERITY_RANK[f.severity] > SEVERITY_RANK[max] ? f.severity : max;
  }, "none");

  return {
    verdict: findings.length > 0 ? "flagged" : "clean",
    maxSeverity,
    findings,
    stats,
  };
}

/** Returns true if `result` should be treated as a failure for CI/exit-code purposes. */
export function isFailingResult(result: ScanResult, failOn: Severity = DEFAULT_FAIL_ON): boolean {
  if (result.maxSeverity === "none") return false;
  return SEVERITY_RANK[result.maxSeverity] >= SEVERITY_RANK[failOn];
}

export { SEVERITY_RANK, DEFAULT_FAIL_ON };
