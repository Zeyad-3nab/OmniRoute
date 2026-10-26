import test from "node:test";
import assert from "node:assert/strict";

const { extractSessionAffinityKey } = await import("../../src/sse/services/sessionAffinityPin.ts");
const { isProviderBlockedByIdOrAlias } = await import("../../src/shared/utils/noAuthProviders.ts");
const { computeBillableTokens } =
  await import("../../open-sse/handlers/chatCore/upstreamTimeouts.ts");
const { resolveModelOrError } = await import("../../src/sse/handlers/chatHelpers.ts");

test("x-session-affinity is accepted as the gateway session key", () => {
  const headers = new Headers({ "x-session-affinity": "zynda-session-42" });
  assert.equal(extractSessionAffinityKey({ messages: [] }, headers), "header:zynda-session-42");
});

test("explicit affinity headers take precedence over derived prompt hashes", () => {
  const headers = new Headers({ "x-session-affinity": "stable-session" });
  const key = extractSessionAffinityKey(
    { messages: [{ role: "user", content: "different prompt" }] },
    headers
  );
  assert.equal(key, "header:stable-session");
});

test("streaming billable usage includes supported cache-write tokens", () => {
  assert.equal(
    computeBillableTokens({
      prompt_tokens: 10,
      completion_tokens: 5,
      prompt_tokens_details: { cache_write_tokens: 7 },
    }),
    22
  );
});

test("blocked no-auth provider ids and aliases are recognized", () => {
  assert.equal(isProviderBlockedByIdOrAlias("zcode", ["zcode"]), true);
  assert.equal(isProviderBlockedByIdOrAlias("cloudflare-playground", ["cfp"]), true);
  assert.equal(isProviderBlockedByIdOrAlias("opencode", ["opencode"]), true);
  assert.equal(isProviderBlockedByIdOrAlias("opencode-zen", ["opencode"]), true);
  assert.equal(isProviderBlockedByIdOrAlias("opencode-go", ["opencode"]), true);
  assert.equal(isProviderBlockedByIdOrAlias("openai", ["opencode"]), false);
});

test("unknown models use a distinct 404/model_not_found response", async () => {
  const result = await resolveModelOrError("zynda-model-does-not-exist", { messages: [] });
  assert.equal(result.error?.status, 404);
  const body = await result.error?.json();
  assert.equal(body.error.code, "model_not_found");
});
