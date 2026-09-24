#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { scan, isFailingResult } from "./scanner.js";
import { annotateContent } from "./annotate.js";
import { startProxyServer } from "./proxy.js";
import type { ScanResult, Severity } from "./types.js";

const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

function isSeverity(value: string): value is Severity {
  return (SEVERITIES as string[]).includes(value);
}

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      data += chunk;
    });
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });
}

interface Flags {
  json: boolean;
  annotate: boolean;
  failOn: Severity;
  port: number;
  positional: string[];
}

function parseFlags(args: string[]): Flags {
  const flags: Flags = { json: false, annotate: false, failOn: "high", port: 8790, positional: [] };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--json") {
      flags.json = true;
    } else if (arg === "--annotate") {
      flags.annotate = true;
    } else if (arg === "--fail-on") {
      const value = args[++i];
      if (!value || !isSeverity(value)) {
        throw new Error(`--fail-on requires one of: ${SEVERITIES.join(", ")}`);
      }
      flags.failOn = value;
    } else if (arg.startsWith("--fail-on=")) {
      const value = arg.slice("--fail-on=".length);
      if (!isSeverity(value)) {
        throw new Error(`--fail-on requires one of: ${SEVERITIES.join(", ")}`);
      }
      flags.failOn = value;
    } else if (arg === "--port") {
      const value = args[++i];
      flags.port = Number(value);
    } else if (arg.startsWith("--port=")) {
      flags.port = Number(arg.slice("--port=".length));
    } else {
      flags.positional.push(arg);
    }
  }
  return flags;
}

function printUsage(): void {
  console.log(`PromptInjectionRadar - detect prompt-injection attempts in untrusted content

Usage:
  promptinjectionradar scan <file>        Scan a file
  cat file | promptinjectionradar scan    Scan stdin (omit <file>, or pass "-")
  promptinjectionradar proxy [--port N]   Start the HTTP scanning proxy (default port 8790)

Options:
  --json              Print machine-readable JSON instead of a human report
  --annotate           Print the annotated content (inline markers) instead of a report
  --fail-on <sev>      Minimum severity that causes a non-zero exit code (low|medium|high|critical, default: high)
  --port <n>           Port for "proxy" mode (default: 8790)

Exit codes (scan):
  0  clean, or findings below --fail-on severity
  1  at least one finding at or above --fail-on severity
  2  usage / runtime error
`);
}

function severityLabel(result: ScanResult): string {
  return result.maxSeverity === "none" ? "none" : result.maxSeverity.toUpperCase();
}

function printHumanReport(result: ScanResult, failOn: Severity): void {
  const failing = isFailingResult(result, failOn);
  console.log("PromptInjectionRadar scan report");
  console.log("=================================");
  console.log(`Verdict:        ${result.verdict.toUpperCase()}${failing ? " (FAILS CI GATE)" : ""}`);
  console.log(`Max severity:   ${severityLabel(result)}`);
  console.log(`Input length:   ${result.stats.inputLength} chars`);
  console.log(
    `Hidden content: zero-width=${result.stats.zeroWidthCharCount}, html-comments=${result.stats.htmlCommentCount}, css-hidden=${result.stats.cssHiddenBlockCount}, base64-candidates=${result.stats.base64CandidateCount}, base64-decoded=${result.stats.base64DecodedCount}`,
  );
  console.log("");

  if (result.findings.length === 0) {
    console.log("No findings.");
    return;
  }

  console.log(`Findings (${result.findings.length}):`);
  result.findings.forEach((f, i) => {
    console.log(
      `${i + 1}. [${f.severity.toUpperCase()}] ${f.category} via ${f.source} — ${f.ruleId}`,
    );
    console.log(`   matched: ${JSON.stringify(f.matchedText.slice(0, 160))}`);
    if (f.decodedContent) {
      console.log(`   revealed: ${JSON.stringify(f.decodedContent.slice(0, 160))}`);
    }
    console.log(`   ${f.description}`);
  });
  console.log("");
  console.log(
    `Exit code: ${failing ? 1 : 0} (fail-on=${failOn}, max-severity=${severityLabel(result)})`,
  );
}

async function runScan(flags: Flags): Promise<number> {
  const file = flags.positional[0];
  const content =
    !file || file === "-" ? await readStdin() : readFileSync(file, "utf8");

  const result = scan(content);

  if (flags.annotate) {
    console.log(annotateContent(content, result));
  } else if (flags.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printHumanReport(result, flags.failOn);
  }

  return isFailingResult(result, flags.failOn) ? 1 : 0;
}

async function runProxy(flags: Flags): Promise<number> {
  if (!Number.isInteger(flags.port) || flags.port <= 0) {
    throw new Error(`invalid --port: ${flags.port}`);
  }
  const server = await startProxyServer({ port: flags.port, failOn: flags.failOn });
  console.log(
    `PromptInjectionRadar proxy listening on http://127.0.0.1:${flags.port}  (try GET /fetch?url=https://example.com)`,
  );
  await new Promise<void>((resolve) => {
    process.on("SIGINT", () => {
      server.close(() => resolve());
    });
    process.on("SIGTERM", () => {
      server.close(() => resolve());
    });
  });
  return 0;
}

async function main(): Promise<number> {
  const [command, ...rest] = process.argv.slice(2);

  if (!command || command === "--help" || command === "-h") {
    printUsage();
    return command ? 0 : 1;
  }

  const flags = parseFlags(rest);

  if (command === "scan") {
    return runScan(flags);
  }
  if (command === "proxy") {
    return runProxy(flags);
  }

  console.error(`Unknown command: ${command}`);
  printUsage();
  return 2;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err) => {
    console.error(`Error: ${(err as Error).message}`);
    process.exitCode = 2;
  });
