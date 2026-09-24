import type { Finding, ScanResult } from "./types.js";

/**
 * Produce an annotated copy of `content` with every finding that was found
 * directly in the visible text wrapped in a
 * [PROMPTINJECTIONRADAR:SEVERITY:CATEGORY] ... [/PROMPTINJECTIONRADAR] marker,
 * so a downstream agent (or a human reviewer) can see exactly what was
 * flagged and where, in context.
 *
 * Findings that were only discovered by decoding/unwrapping obfuscated
 * content (base64, zero-width-stripped, HTML comments, CSS-hidden blocks)
 * don't have a reliable byte offset in the *original* content (their index
 * refers to the decoded/revealed text), so instead of guessing at a splice
 * point, they're summarized in a banner comment prepended to the output.
 */
export function annotateContent(content: string, result: ScanResult): string {
  const inline = result.findings.filter((f) => f.source === "plain");
  const other = result.findings.filter((f) => f.source !== "plain");

  // Walk from the end of the string backwards so earlier splices don't
  // invalidate the indices of findings we haven't applied yet.
  const sorted = [...inline].sort((a, b) => b.index - a.index);
  let annotated = content;
  for (const f of sorted) {
    const start = f.index;
    const end = start + f.matchedText.length;
    if (annotated.slice(start, end) !== f.matchedText) continue; // safety guard against overlaps
    const marker = `[PROMPTINJECTIONRADAR:${f.severity.toUpperCase()}:${f.category}]${
      f.matchedText
    }[/PROMPTINJECTIONRADAR]`;
    annotated = annotated.slice(0, start) + marker + annotated.slice(end);
  }

  if (other.length > 0) {
    const lines = other.map((f: Finding) => formatBannerLine(f));
    const banner = `<!-- PROMPTINJECTIONRADAR: ${other.length} additional finding(s) detected in hidden/encoded content (not inline-annotated because they were only visible after decoding):\n${lines.join(
      "\n",
    )}\n-->\n`;
    annotated = banner + annotated;
  }

  return annotated;
}

function formatBannerLine(f: Finding): string {
  const decoded = f.decodedContent ? ` | revealed: ${truncate(f.decodedContent, 80)}` : "";
  return `  - [${f.severity.toUpperCase()}] ${f.category} via ${f.source}: ${truncate(f.matchedText, 80)}${decoded}`;
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}...` : s;
}
