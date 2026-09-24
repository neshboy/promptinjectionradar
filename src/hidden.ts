/**
 * Detection of "hidden channel" tricks: text that a human skimming a
 * rendered page/document would never see, but which a text-extraction
 * pipeline feeding an LLM agent would happily include verbatim.
 *
 *   - zero-width / invisible Unicode formatting characters, which can be
 *     interspersed inside a phrase to break naive keyword/regex matching
 *     while remaining invisible when rendered,
 *   - HTML comments, which never render but are often present in raw
 *     fetched HTML that gets passed to an agent,
 *   - CSS-hidden blocks: display:none, visibility:hidden, opacity:0,
 *     font-size:0, and white-text-on-white-background.
 */

export interface ZeroWidthMatch {
  codePoint: string; // e.g. "U+200B"
  index: number;
}

export interface HtmlComment {
  content: string;
  index: number;
}

export type CssHiddenReason =
  | "display-none"
  | "visibility-hidden"
  | "opacity-zero"
  | "font-size-zero"
  | "white-on-white";

export interface CssHiddenBlock {
  tag: string;
  style: string;
  innerText: string;
  index: number;
  reason: CssHiddenReason;
}

// Unicode category "Cf" (Format) covers zero-width space/joiners (U+200B,
// U+200C, U+200D), word joiner (U+2060), invisible math operators
// (U+2061-U+2064), the BOM / zero-width no-break space (U+FEFF), and the
// Unicode "tag" characters (U+E0001, U+E0020-U+E007F) that have been
// documented as an invisible smuggling channel for hidden instructions. We
// additionally list variation selectors (U+FE00-U+FE0F, category Mn)
// explicitly by escape sequence since they are not covered by \p{Cf} but
// have also been used to hide covert text (e.g. "emoji variation selector"
// smuggling). Written with explicit \u escapes rather than literal
// invisible characters so the source stays auditable/grep-able.
const ZERO_WIDTH_RE = /[\uFE00-\uFE0F]|\p{Cf}/gu;

export function findZeroWidthChars(text: string): ZeroWidthMatch[] {
  const matches: ZeroWidthMatch[] = [];
  for (const m of text.matchAll(ZERO_WIDTH_RE)) {
    if (m.index === undefined) continue;
    const cp = m[0].codePointAt(0) ?? 0;
    matches.push({
      codePoint: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`,
      index: m.index,
    });
  }
  return matches;
}

/** Remove zero-width/invisible characters, revealing what they may be hiding or splicing together. */
export function stripZeroWidthChars(text: string): string {
  return text.replace(ZERO_WIDTH_RE, "");
}

const HTML_COMMENT_RE = /<!--([\s\S]*?)-->/g;

export function findHtmlComments(text: string): HtmlComment[] {
  const comments: HtmlComment[] = [];
  for (const m of text.matchAll(HTML_COMMENT_RE)) {
    if (m.index === undefined) continue;
    comments.push({ content: m[1], index: m.index });
  }
  return comments;
}

const STYLED_TAG_RE =
  /<([a-zA-Z][a-zA-Z0-9]*)\b[^>]*\bstyle\s*=\s*(["'])([^"']*)\2[^>]*>([\s\S]*?)<\/\1\s*>/gi;

const WHITE_VALUES = new Set(["white", "#fff", "#ffffff"]);

function isWhiteColor(value: string): boolean {
  const v = value.trim().toLowerCase().replace(/\s+/g, "");
  if (WHITE_VALUES.has(v)) return true;
  const rgbMatch = v.match(/^rgba?\((\d+),(\d+),(\d+)(?:,[\d.]+)?\)$/);
  if (rgbMatch) {
    return rgbMatch[1] === "255" && rgbMatch[2] === "255" && rgbMatch[3] === "255";
  }
  return false;
}

function extractCssProperty(style: string, prop: string): string | null {
  const re = new RegExp(`(?:^|;)\\s*${prop}\\s*:\\s*([^;]+)`, "i");
  const m = style.match(re);
  return m ? m[1].trim() : null;
}

function stripTags(html: string): string {
  return html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}

export function findCssHiddenBlocks(text: string): CssHiddenBlock[] {
  const blocks: CssHiddenBlock[] = [];
  for (const m of text.matchAll(STYLED_TAG_RE)) {
    if (m.index === undefined) continue;
    const [, tag, , style, innerHtml] = m;
    const innerText = stripTags(innerHtml);
    if (!innerText) continue;

    let reason: CssHiddenReason | null = null;

    if (/display\s*:\s*none\b/i.test(style)) {
      reason = "display-none";
    } else if (/visibility\s*:\s*hidden\b/i.test(style)) {
      reason = "visibility-hidden";
    } else if (/opacity\s*:\s*0(?:\.0+)?\b/i.test(style)) {
      reason = "opacity-zero";
    } else if (/font-size\s*:\s*0(?:px)?\b/i.test(style)) {
      reason = "font-size-zero";
    } else {
      const color = extractCssProperty(style, "color");
      const bg =
        extractCssProperty(style, "background-color") ?? extractCssProperty(style, "background");
      if (color && bg && isWhiteColor(color) && isWhiteColor(bg)) {
        reason = "white-on-white";
      }
    }

    if (reason) {
      blocks.push({ tag, style, innerText, index: m.index, reason });
    }
  }
  return blocks;
}
