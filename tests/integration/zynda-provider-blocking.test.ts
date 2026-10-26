import assert from "node:assert/strict";
import test from "node:test";

import { createChatPipelineHarness } from "./_chatPipelineHarness.ts";

const harness = await createChatPipelineHarness("zynda-provider-blocking");
const {
  BaseExecutor,
  buildRequest,
  combosDb,
  handleChat,
  resetStorage,
  settingsDb,
  toPlainHeaders,
} = harness;

test.beforeEach(async () => {
  BaseExecutor.RETRY_CONFIG.delayMs = 0;
  await resetStorage();
});

test.afterEach(async () => {
  await resetStorage();
});

test.after(async () => {
  await harness.cleanup();
});

function body(model: string) {
  return {
    model,
    stream: false,
    messages: [{ role: "user", content: "blocked provider regression" }],
  };
}

test("blocked direct provider returns 503 without reaching the executor", async () => {
  await settingsDb.updateSettings({ blockedProviders: ["zcode"] });
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    return new Response("unexpected upstream call", { status: 500 });
  };

  const response = await handleChat(buildRequest({ body: body("zcode/glm-5.3-flash") }));
  const payload = (await response.json()) as { error?: { code?: string } };

  assert.equal(response.status, 503);
  assert.equal(payload.error?.code, "provider_unavailable");
  assert.equal(fetchCalls, 0);
});

test("blocked combo target is skipped before upstream dispatch", async () => {
  await settingsDb.updateSettings({ blockedProviders: ["opencode"] });
  await combosDb.createCombo({
    name: "zynda-blocked-opencode",
    strategy: "priority",
    models: ["opencode-zen/opencode/big-pickle"],
  });
  let fetchCalls = 0;
  globalThis.fetch = async (_url, init = {}) => {
    fetchCalls += 1;
    void toPlainHeaders(init.headers);
    return new Response("unexpected upstream call", { status: 500 });
  };

  const response = await handleChat(buildRequest({ body: body("zynda-blocked-opencode") }));

  assert.notEqual(response.status, 200);
  assert.equal(fetchCalls, 0);
});
