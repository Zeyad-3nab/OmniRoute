import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/**
 * Phase 3 + 4 (Zynda hardening) — least-privilege key + per-model combo mapping.
 *
 * Proves the supported schema enforces the Zynda `zynda-prod` profile:
 *   modelAccessMode="restricted", catalogScope="combos", allowAutoCombos=false,
 *   cacheDefaultMode="bypass", allowedEndpoints=["chat","models"], and an
 *   allowedCombos allow-list of Vercel-style catalog IDs.
 *
 * And that /v1/models (filterCatalogModelsForKey) exposes EXACTLY the approved
 * combo IDs for that key — no provider models, no unauthorized combos, no vag/*,
 * no auto/*; that combo names containing "/" are accepted; and that a combo maps
 * to its exact underlying model id.
 */

const TEST_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "omr-zynda-key-"));
process.env.DATA_DIR = TEST_DATA_DIR;
process.env.API_KEY_SECRET = "test-api-key-secret-for-zynda-key-tests-0001";

const apiKeysDb = await import("../../src/lib/db/apiKeys.ts");
const core = await import("../../src/lib/db/core.ts");
const { filterCatalogModelsForKey } =
  await import("../../src/app/api/v1/models/catalogKeyFilter.ts");
const { isComboNameAllowedForKey, isAutoComboDeniedForKey } =
  await import("../../src/shared/utils/apiKeyPolicy.ts");
const { comboNameSchema } = await import("../../src/shared/validation/schemas/combo.ts");
const { getComboModelString } = await import("../../src/lib/combos/steps.ts");
const { resolveCanonicalEndpointPath, resolveEndpointCategory } =
  await import("../../src/shared/constants/endpointCategories.ts");

// The approved Zynda catalog IDs (Vercel-style, slash-containing).
const ZYNDA_COMBOS = ["anthropic/claude-haiku-5.5", "zai/glm-5.3-flash", "alibaba/qwen3.8-flash"];

function resetStorage() {
  core.resetDbInstance();
  apiKeysDb.resetApiKeyState();
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  fs.mkdirSync(TEST_DATA_DIR, { recursive: true });
}

test.beforeEach(() => resetStorage());

test.after(() => {
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

async function createZyndaKey(): Promise<{ id: string; key: string }> {
  const created = await apiKeysDb.createApiKey("zynda-prod", "machine-zynda", [], {
    modelAccessMode: "restricted",
    allowedModels: [],
    allowedCombos: [...ZYNDA_COMBOS],
  });
  assert.ok(created?.id && created?.key, "createApiKey must return id + key");
  await apiKeysDb.updateApiKeyPermissions(created.id, {
    catalogScope: "combos",
    allowAutoCombos: false,
    cacheDefaultMode: "bypass",
    allowedEndpoints: ["chat", "models"],
  });
  return { id: created.id, key: created.key };
}

test("the zynda-prod profile persists every least-privilege field", async () => {
  const { key } = await createZyndaKey();
  const meta = await apiKeysDb.getApiKeyMetadata(key);
  assert.ok(meta, "metadata must resolve");
  assert.equal(meta.modelAccessMode, "restricted");
  assert.equal(meta.catalogScope, "combos");
  assert.equal(meta.allowAutoCombos, false);
  assert.equal(meta.cacheDefaultMode, "bypass");
  assert.deepEqual([...(meta.allowedEndpoints ?? [])].sort(), ["chat", "models"]);
  assert.deepEqual([...(meta.allowedCombos ?? [])].sort(), [...ZYNDA_COMBOS].sort());
});

test("auto combos are denied for the zynda-prod key", async () => {
  const { key } = await createZyndaKey();
  const meta = await apiKeysDb.getApiKeyMetadata(key);
  assert.equal(isAutoComboDeniedForKey(meta, "auto/best-coding"), true);
  assert.equal(isAutoComboDeniedForKey(meta, "anthropic/claude-haiku-5.5"), false);
});

test("allowedCombos gate: approved combos allowed, others denied", async () => {
  const { key } = await createZyndaKey();
  const meta = await apiKeysDb.getApiKeyMetadata(key);
  for (const name of ZYNDA_COMBOS) {
    assert.equal(isComboNameAllowedForKey(meta.allowedCombos, name), true, name);
  }
  assert.equal(isComboNameAllowedForKey(meta.allowedCombos, "zai/glm-6-ultra"), false);
  assert.equal(isComboNameAllowedForKey(meta.allowedCombos, "openai/gpt-5"), false);
});

test("restricted key denies arbitrary provider models", async () => {
  const { key } = await createZyndaKey();
  assert.equal(await apiKeysDb.isModelAllowedForKey(key, "openai/gpt-4o"), false);
  assert.equal(await apiKeysDb.isModelAllowedForKey(key, "google/gemini-2.5-pro"), false);
});

test("/v1/models exposes exactly the approved combo IDs for the zynda key — no providers, no vag/*, no auto/*", async () => {
  const { key } = await createZyndaKey();
  const catalog = [
    { id: "anthropic/claude-haiku-5.5", owned_by: "combo" },
    { id: "zai/glm-5.3-flash", owned_by: "combo" },
    { id: "alibaba/qwen3.8-flash", owned_by: "combo" },
    { id: "vag/secret-combo", owned_by: "combo" }, // must NOT appear
    { id: "auto/best-coding", owned_by: "combo" }, // must NOT appear
    { id: "openai/gpt-4o", owned_by: "openai" }, // provider model — hidden by catalogScope
    { id: "anthropic/claude-3-5-sonnet", owned_by: "anthropic" },
  ];
  const deps = {
    isModelAllowedForKey: apiKeysDb.isModelAllowedForKey,
    isModelBlockedByPatterns: apiKeysDb.isModelBlockedByPatterns,
  };
  const filtered = await filterCatalogModelsForKey(
    key,
    catalog,
    { catalogScope: "combos", allowedCombos: [...ZYNDA_COMBOS], blockedModels: [] },
    deps,
    async () => {}
  );
  assert.deepEqual(
    filtered.map((m) => m.id).sort(),
    [...ZYNDA_COMBOS].sort(),
    "catalog must list only the approved Zynda combos"
  );
});

// ---------- Phase 4: combo naming + model mapping ----------

test("combo names containing '/' are accepted by the schema", () => {
  for (const name of ZYNDA_COMBOS) {
    assert.equal(comboNameSchema.safeParse(name).success, true, name);
  }
  // A name with an illegal character is rejected.
  assert.equal(comboNameSchema.safeParse("bad$name").success, false);
});

test("a combo maps to its exact underlying model id", () => {
  // String step (already provider-qualified).
  assert.equal(getComboModelString("cc/claude-haiku-5-5"), "cc/claude-haiku-5-5");
  // Object step — provider + model resolve to the full id.
  assert.equal(
    getComboModelString({ model: "claude-haiku-5-5", provider: "cc" }),
    "cc/claude-haiku-5-5"
  );
  // The mapping does not silently rewrite to a similarly-named model.
  assert.notEqual(getComboModelString("cc/claude-haiku-5-5"), "anthropic/claude-haiku-5.5");
});

test("the three Zynda endpoints resolve to the key's allowed categories", () => {
  const allowed = new Set(["chat", "models"]);
  for (const p of ["/v1/messages", "/v1/chat/completions", "/v1/models"]) {
    const category = resolveEndpointCategory(resolveCanonicalEndpointPath(p));
    assert.ok(category && allowed.has(category), `${p} -> ${category}`);
  }
  // An endpoint the Zynda key does NOT allow maps to a category outside the set.
  const images = resolveEndpointCategory(resolveCanonicalEndpointPath("/v1/images/generations"));
  assert.equal(images, "images");
  assert.equal(allowed.has(images!), false);
});
