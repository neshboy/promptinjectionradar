export { scan, isFailingResult } from "./scanner.js";
export { PATTERN_RULES } from "./patterns.js";
export type { PatternRule } from "./patterns.js";
export {
  shannonEntropy,
  findBase64Candidates,
  tryDecodeBase64,
  findDecodableBase64Blocks,
} from "./entropy.js";
export {
  findZeroWidthChars,
  stripZeroWidthChars,
  findHtmlComments,
  findCssHiddenBlocks,
} from "./hidden.js";
export type {
  Finding,
  FindingCategory,
  FindingSource,
  ScanOptions,
  ScanResult,
  ScanStats,
  Severity,
} from "./types.js";
