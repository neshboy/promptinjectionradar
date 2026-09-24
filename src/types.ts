/**
 * Shared types for PromptInjectionRadar.
 */

export type Severity = "low" | "medium" | "high" | "critical";

export type FindingCategory =
  | "direct_override"
  | "exfiltration"
  | "fetch_execute"
  | "authority_escalation"
  | "hidden_content"
  | "encoded_instructions";

/**
 * Where the raw text of a finding was discovered. "plain" means it was
 * visible in the original text as given to scan(). The other sources mean
 * the text was only revealed after PromptInjectionRadar unwrapped some kind
 * of obfuscation (zero-width characters, an HTML comment, CSS-hidden text,
 * or a base64 blob) and re-ran the pattern library against what it found.
 */
export type FindingSource =
  | "plain"
  | "zero-width-stripped"
  | "html-comment"
  | "css-hidden"
  | "base64-decoded";

export interface Finding {
  /** Stable machine-readable id for the specific rule that fired. */
  ruleId: string;
  category: FindingCategory;
  severity: Severity;
  /** Human-readable explanation of why this matched. */
  description: string;
  /** The exact substring that triggered the rule. */
  matchedText: string;
  /** Character offset of the match within the text that was scanned (see `source`). */
  index: number;
  source: FindingSource;
  /**
   * If this finding was only found after decoding/unwrapping obfuscated
   * content (base64, zero-width stripping, HTML comment, CSS-hidden span),
   * this holds the decoded/revealed text that the rule actually matched
   * against, so a reviewer can see exactly what was hidden.
   */
  decodedContent?: string;
}

export interface ScanStats {
  /** Length in characters of the original input. */
  inputLength: number;
  /** Number of zero-width / invisible-formatting codepoints found. */
  zeroWidthCharCount: number;
  /** Number of HTML comments found. */
  htmlCommentCount: number;
  /** Number of CSS-hidden text blocks found (white-on-white, display:none, etc). */
  cssHiddenBlockCount: number;
  /** Number of base64-looking candidate substrings that were examined. */
  base64CandidateCount: number;
  /** Number of base64 candidates that decoded to plausible text and were re-scanned. */
  base64DecodedCount: number;
}

export interface ScanResult {
  /** "clean" if no findings at all, "flagged" if there is at least one finding. */
  verdict: "clean" | "flagged";
  /** Highest severity among all findings, or "none" if there are no findings. */
  maxSeverity: Severity | "none";
  findings: Finding[];
  stats: ScanStats;
}

export interface ScanOptions {
  /**
   * Minimum severity that should cause a non-zero CLI exit code / a "reject"
   * proxy verdict. Defaults to "high".
   */
  failOn?: Severity;
  /** Maximum recursion depth for decoding nested obfuscation. Defaults to 1. */
  maxDecodeDepth?: number;
}
