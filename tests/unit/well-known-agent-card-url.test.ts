import test from "node:test";
import assert from "node:assert/strict";

/**
 * Regression tests for the A2A Agent Card public URL (Phase 2.3 — Zynda hardening).
 *
 * The card must advertise a routable public origin and MUST NEVER advertise the
 * wildcard bind host `0.0.0.0` (or `::`), even when the request arrives with
 * `Host: 0.0.0.0:20128`. It must honor the configured public-base-URL settings
 * (`OMNIROUTE_PUBLIC_BASE_URL` / `NEXT_PUBLIC_BASE_URL`) and the explicit
 * `OMNIROUTE_BASE_URL` admin override, rather than a hardcoded URL.
 */

const { getBaseUrl } = await import("../../src/lib/wellKnown.ts");

const ENV_KEYS = [
  "OMNIROUTE_BASE_URL",
  "OMNIROUTE_PUBLIC_BASE_URL",
  "NEXT_PUBLIC_BASE_URL",
  "NEXT_PUBLIC_APP_URL",
  "PORT",
  "DASHBOARD_PORT",
  "OMNIROUTE_TRUST_PROXY",
] as const;

const ORIGINAL: Record<string, string | undefined> = {};
for (const key of ENV_KEYS) ORIGINAL[key] = process.env[key];

function clearEnv() {
  for (const key of ENV_KEYS) delete process.env[key];
}

test.beforeEach(() => {
  clearEnv();
});

test.after(() => {
  for (const key of ENV_KEYS) {
    if (ORIGINAL[key] === undefined) delete process.env[key];
    else process.env[key] = ORIGINAL[key];
  }
});

function req(url: string, headers?: Record<string, string>): Request {
  return new Request(url, { headers: new Headers(headers) });
}

test("OMNIROUTE_BASE_URL admin override is honored and trailing slash stripped", () => {
  process.env.OMNIROUTE_BASE_URL = "https://omniport.ink/";
  assert.equal(
    getBaseUrl(req("http://0.0.0.0:20128/.well-known/agent.json")),
    "https://omniport.ink"
  );
});

test("configured OMNIROUTE_PUBLIC_BASE_URL wins over a 0.0.0.0 request host", () => {
  process.env.OMNIROUTE_PUBLIC_BASE_URL = "https://omniport.ink";
  const base = getBaseUrl(req("http://0.0.0.0:20128/.well-known/agent.json"));
  assert.equal(base, "https://omniport.ink");
  assert.ok(!base.includes("0.0.0.0"));
});

test("NEXT_PUBLIC_BASE_URL is honored when no request is supplied (programmatic)", () => {
  process.env.NEXT_PUBLIC_BASE_URL = "https://omniport.ink";
  assert.equal(getBaseUrl(), "https://omniport.ink");
});

test("a 0.0.0.0 Host never leaks into the base URL — falls back to loopback", () => {
  const base = getBaseUrl(req("http://0.0.0.0:20128/.well-known/agent.json"));
  assert.ok(!base.includes("0.0.0.0"), `expected no 0.0.0.0 in ${base}`);
  assert.equal(base, "http://localhost:20128");
});

test("an unroutable OMNIROUTE_BASE_URL override is rejected and falls through", () => {
  process.env.OMNIROUTE_BASE_URL = "http://0.0.0.0:20128";
  process.env.OMNIROUTE_PUBLIC_BASE_URL = "https://omniport.ink";
  assert.equal(getBaseUrl(req("http://0.0.0.0:20128/x")), "https://omniport.ink");
});

test("a routable request origin is used when nothing else is configured", () => {
  assert.equal(
    getBaseUrl(req("https://omniport.ink/.well-known/agent.json")),
    "https://omniport.ink"
  );
});

test("loopback default honors PORT when no request and no public base URL", () => {
  process.env.PORT = "31000";
  assert.equal(getBaseUrl(), "http://localhost:31000");
});

test("the live /.well-known/agent.json card advertises the configured URL, never 0.0.0.0", async () => {
  process.env.OMNIROUTE_PUBLIC_BASE_URL = "https://omniport.ink";
  const { GET } = await import("../../src/app/.well-known/agent.json/route.ts");
  const res = await GET(req("http://0.0.0.0:20128/.well-known/agent.json") as never);
  const body = (await res.json()) as { url: string };
  assert.equal(body.url, "https://omniport.ink/a2a");
  assert.ok(!body.url.includes("0.0.0.0"));
});

test("the live /.well-known/agent-card.json (v1.0) card never advertises 0.0.0.0", async () => {
  const { GET } = await import("../../src/app/.well-known/agent-card.json/route.ts");
  const res = await GET(req("http://0.0.0.0:20128/.well-known/agent-card.json") as never);
  const body = (await res.json()) as { url: string; supportedInterfaces: { url: string }[] };
  assert.ok(!body.url.includes("0.0.0.0"), `card url leaked bind host: ${body.url}`);
  assert.equal(body.url, "http://localhost:20128/a2a");
  for (const iface of body.supportedInterfaces) {
    assert.ok(!iface.url.includes("0.0.0.0"));
  }
});
