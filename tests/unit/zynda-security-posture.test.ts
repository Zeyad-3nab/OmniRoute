import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/**
 * Phase 2 (Zynda hardening) — security-posture regression tests.
 *
 * Complements tests/unit/authz/handler-auth-bypass.test.ts (which already pins
 * the /v1/* handler guard: keyless→401, invalid→401, valid→allow, anonymous when
 * REQUIRE_API_KEY is off). Here we pin the surfaces that test does NOT cover:
 *   - /a2a authentication (authenticateA2ARequest) mirrors the /v1 posture.
 *   - MCP stays LOCAL_ONLY (isLocalOnlyPath), while /v1 does not.
 *   - CORS is fail-closed by default and never emits an unrestricted wildcard
 *     paired with credentials.
 */

const TEST_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "omr-zynda-sec-"));
process.env.DATA_DIR = TEST_DATA_DIR;
process.env.API_KEY_SECRET = "test-api-key-secret-for-zynda-posture-tests-0001";

const apiKeysDb = await import("../../src/lib/db/apiKeys.ts");
const core = await import("../../src/lib/db/core.ts");
const { authenticateA2ARequest } = await import("../../src/lib/a2a/authenticate.ts");
const { isLocalOnlyPath } = await import("../../src/server/authz/routeGuard.ts");
const cors = await import("../../src/server/cors/origins.ts");

const ENV_KEYS = [
  "REQUIRE_API_KEY",
  "OMNIROUTE_API_KEY",
  "ROUTER_API_KEY",
  "JWT_SECRET",
  "CORS_ALLOW_ALL",
  "CORS_ALLOWED_ORIGINS",
  "CORS_ORIGIN",
] as const;
const ORIGINAL: Record<string, string | undefined> = {};
for (const k of ENV_KEYS) ORIGINAL[k] = process.env[k];

function resetStorage() {
  core.resetDbInstance();
  apiKeysDb.resetApiKeyState();
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  fs.mkdirSync(TEST_DATA_DIR, { recursive: true });
  for (const k of ENV_KEYS) delete process.env[k];
}

test.beforeEach(() => resetStorage());

test.after(() => {
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  for (const k of ENV_KEYS) {
    if (ORIGINAL[k] === undefined) delete process.env[k];
    else process.env[k] = ORIGINAL[k];
  }
});

function a2aRequest(headers?: HeadersInit): Request {
  return new Request("http://localhost/a2a", { method: "POST", headers: new Headers(headers) });
}

// ---------- /a2a authentication ----------

test("/a2a rejects a keyless request when REQUIRE_API_KEY=true", async () => {
  process.env.REQUIRE_API_KEY = "true";
  assert.equal(await authenticateA2ARequest(a2aRequest()), false);
});

test("/a2a accepts a valid OmniRoute key when REQUIRE_API_KEY=true", async () => {
  process.env.REQUIRE_API_KEY = "true";
  const created = await apiKeysDb.createApiKey("zynda-a2a-key", "machine-a2a-1");
  assert.ok(created?.key);
  assert.equal(
    await authenticateA2ARequest(a2aRequest({ authorization: `Bearer ${created.key}` })),
    true
  );
});

test("/a2a rejects an invalid key when REQUIRE_API_KEY=true", async () => {
  process.env.REQUIRE_API_KEY = "true";
  assert.equal(
    await authenticateA2ARequest(a2aRequest({ authorization: "Bearer not-a-real-key" })),
    false
  );
});

test("/a2a stays keyless (local-first) when REQUIRE_API_KEY is unset and no key configured", async () => {
  assert.equal(await authenticateA2ARequest(a2aRequest()), true);
});

test("/a2a honors a configured OMNIROUTE_API_KEY when REQUIRE_API_KEY is off", async () => {
  process.env.OMNIROUTE_API_KEY = "s2s-shared-key-abc";
  assert.equal(
    await authenticateA2ARequest(a2aRequest({ authorization: "Bearer s2s-shared-key-abc" })),
    true
  );
  assert.equal(await authenticateA2ARequest(a2aRequest({ authorization: "Bearer wrong" })), false);
});

// ---------- MCP LOCAL_ONLY ----------

test("MCP routes are classified LOCAL_ONLY, inference routes are not", () => {
  assert.equal(isLocalOnlyPath("/api/mcp/stream"), true);
  assert.equal(isLocalOnlyPath("/api/mcp/sse"), true);
  assert.equal(isLocalOnlyPath("/api/services/ninerouter/start"), true);
  // The client inference surface must remain reachable off-box.
  assert.equal(isLocalOnlyPath("/api/v1/chat/completions"), false);
  assert.equal(isLocalOnlyPath("/v1/chat/completions"), false);
});

// ---------- CORS ----------

test("CORS is fail-closed by default — no wildcard, unknown origin not echoed", () => {
  const status = cors.getCorsStatus();
  assert.equal(status.allowAll, false);
  assert.equal(cors.resolveAllowedOrigin("https://evil.example.com"), null);
  assert.equal(cors.resolveAllowedOrigin(null), null);
});

test("relaxed /v1 CORS never pairs an origin/wildcard with Allow-Credentials", () => {
  // Token-bearing cross-origin request with no allowlist match on the relaxed
  // /v1 surface: the Origin is echoed (not a blanket '*'), and crucially no
  // Access-Control-Allow-Credentials header is ever emitted.
  const request = new Request("http://localhost/v1/chat/completions", {
    method: "POST",
    headers: new Headers({ origin: "https://app.zynda.example", authorization: "Bearer k" }),
  });
  const response = new Response(null, { status: 200 });
  cors.applyCorsHeaders(response, request, true);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), "https://app.zynda.example");
  assert.equal(response.headers.get("Access-Control-Allow-Credentials"), null);
});

test("management/dashboard CORS surface stays fail-closed (no relax)", () => {
  const request = new Request("http://localhost/api/keys", {
    method: "POST",
    headers: new Headers({ origin: "https://evil.example.com", cookie: "auth_token=x" }),
  });
  const response = new Response(null, { status: 200 });
  cors.applyCorsHeaders(response, request, false);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), null);
  assert.equal(response.headers.get("Access-Control-Allow-Credentials"), null);
});
