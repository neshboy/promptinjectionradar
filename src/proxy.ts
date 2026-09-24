import { createServer, type Server } from "node:http";
import { scan, isFailingResult } from "./scanner.js";
import { annotateContent } from "./annotate.js";
import type { Severity } from "./types.js";

export interface ProxyOptions {
  port: number;
  failOn?: Severity;
}

/**
 * A minimal HTTP proxy: GET /fetch?url=<url> fetches the target URL
 * server-side, scans the response body with scan(), and returns the
 * verdict + findings + an annotated copy of the content as JSON. The
 * verdict is also surfaced as response headers so a caller that only cares
 * about pass/fail can check headers without parsing the body.
 *
 * Note: this fetches whatever URL it's told to fetch. It's meant to be run
 * locally / in a trusted environment (e.g. as a pre-fetch step in an agent
 * pipeline or a CI job), not exposed as a public open proxy - see the
 * README "Limitations" section.
 */
export function createProxyServer(options: ProxyOptions): Server {
  const failOn = options.failOn ?? "high";

  return createServer((req, res) => {
    void handleRequest(req.url, options.port, failOn, res);
  });
}

async function handleRequest(
  rawUrl: string | undefined,
  port: number,
  failOn: Severity,
  res: import("node:http").ServerResponse,
): Promise<void> {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(rawUrl ?? "/", `http://127.0.0.1:${port}`);
  } catch {
    sendJson(res, 400, {}, { error: "could not parse request URL" });
    return;
  }

  if (parsedUrl.pathname === "/health") {
    sendJson(res, 200, {}, { ok: true });
    return;
  }

  if (parsedUrl.pathname !== "/fetch") {
    sendJson(res, 404, {}, { error: "not found. Use GET /fetch?url=<url>" });
    return;
  }

  const target = parsedUrl.searchParams.get("url");
  if (!target) {
    sendJson(res, 400, {}, { error: "missing required ?url= query parameter" });
    return;
  }

  let targetUrl: URL;
  try {
    targetUrl = new URL(target);
  } catch {
    sendJson(res, 400, {}, { error: `invalid url: ${target}` });
    return;
  }
  if (targetUrl.protocol !== "http:" && targetUrl.protocol !== "https:") {
    sendJson(res, 400, {}, { error: `unsupported protocol: ${targetUrl.protocol}` });
    return;
  }

  try {
    const upstream = await fetch(targetUrl.toString(), {
      redirect: "follow",
      headers: { "user-agent": "PromptInjectionRadar-Proxy/0.1" },
    });
    const body = await upstream.text();
    const result = scan(body);
    const annotated = annotateContent(body, result);
    const failing = isFailingResult(result, failOn);

    sendJson(
      res,
      200,
      {
        "x-promptinjectionradar-verdict": failing ? "reject" : result.verdict,
        "x-promptinjectionradar-max-severity": result.maxSeverity,
        "x-promptinjectionradar-finding-count": String(result.findings.length),
      },
      {
        url: targetUrl.toString(),
        upstreamStatus: upstream.status,
        verdict: result.verdict,
        recommendedAction: failing ? "reject" : "allow",
        maxSeverity: result.maxSeverity,
        findings: result.findings,
        stats: result.stats,
        annotatedContent: annotated,
      },
    );
  } catch (err) {
    sendJson(res, 502, {}, { error: `failed to fetch/scan target: ${(err as Error).message}` });
  }
}

function sendJson(
  res: import("node:http").ServerResponse,
  status: number,
  headers: Record<string, string>,
  body: unknown,
): void {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(body, null, 2));
}

export function startProxyServer(options: ProxyOptions): Promise<Server> {
  return new Promise((resolve) => {
    const server = createProxyServer(options);
    server.listen(options.port, () => resolve(server));
  });
}
