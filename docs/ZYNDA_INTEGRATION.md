# Zynda Integration & Instance Hardening

Operator runbook for pointing Zynda (a server-to-server caller using Vercel-style
catalog IDs) at an OmniRoute deployment, and for securing that deployment.

This documents **verified behavior of the installed version (3.8.52)**. Most of the
requested security posture is already implemented — the only source change this
work added is an Agent Card URL fix (see §2.3). Everything else is configuration,
a least-privilege API key, and per-model combos, all created through supported
settings/admin APIs. Where a prerequisite could not be verified from source
(e.g. whether a provider account is actually connected), it is called out rather
than assumed.

---

## 1. How Zynda talks to OmniRoute

Zynda calls OmniRoute **server-to-server** (no browser). It uses OpenAI/Anthropic
wire formats against `/v1/chat/completions`, `/v1/messages`, and `/v1/models`, with
Vercel-style catalog IDs such as `anthropic/claude-haiku-5.5`, `zai/glm-5.3-flash`,
`alibaba/qwen3.8-flash`. Each catalog ID maps to a dedicated OmniRoute combo.

Because the caller is server-side, **browser CORS is irrelevant to it** (see §2.2).

---

## 2. Securing the instance (highest priority)

### 2.1 API authentication

Enforcement is controlled by **`REQUIRE_API_KEY`** (read via
`isRequireApiKeyEnabled()` in `src/shared/utils/featureFlags.ts`, which **fails
closed** — on a read error it behaves as `true`). Set it in the deployment
environment:

```ini
REQUIRE_API_KEY=true
```

What this protects, verified in source:

| Surface                                      | Mechanism                                                                                | File                                                                                                |
| -------------------------------------------- | ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `/v1/*` (middleware)                         | `clientApiPolicy` rejects `401 AUTH_002` before the handler runs, never parsing the body | `src/server/authz/policies/clientApi.ts:57-101`                                                     |
| `/v1/*` (handler safety-net)                 | `enforceClientApiRouteAuth(request)` runs **before** Zod body validation                 | `src/app/api/v1/chat/completions/route.ts:108-109` (auth) vs `:181` (Zod)                           |
| `/a2a` (JSON-RPC, outside the proxy matcher) | `authenticateA2ARequest()` — same `REQUIRE_API_KEY` posture                              | `src/lib/a2a/authenticate.ts:30-48`, `src/app/a2a/route.ts:165-169`                                 |
| MCP                                          | `LOCAL_ONLY` — loopback enforced before any auth                                         | `src/server/authz/routeGuard.ts:35` (`/api/mcp/`), `src/server/authz/policies/management.ts:99-171` |

Key ordering guarantee (the reported failure where an empty body returns a
validation error instead of `401`): with `REQUIRE_API_KEY=true`, an unauthenticated
`POST /v1/chat/completions` is rejected at the auth layer (middleware **and**
handler) **before** `request.json()` / Zod `safeParse`. This is pinned by
`tests/unit/authz/handler-auth-bypass.test.ts` and
`tests/unit/zynda-security-posture.test.ts`.

`OMNIROUTE_API_KEY` (and legacy `ROUTER_API_KEY`) is an **optional** persistent
passthrough/service key that always validates (`src/sse/services/auth.ts:3582`). It
protects the same surfaces as any other valid key and is the shared secret the
`/a2a` keyless-with-configured-key path checks. It is **not** required to enforce
auth — `REQUIRE_API_KEY=true` is sufficient and is the primary control. Only set
`OMNIROUTE_API_KEY` if you want a fixed service credential for internal tooling;
never commit its value.

> Note: `.env.example` ships `REQUIRE_API_KEY=false` on purpose — OmniRoute is
> local-first by default. **Do not rely on the default; set `=true` in the VPS
> deployment env.** This is a per-deployment setting, not a code change.

### 2.2 CORS vs authentication

They are different controls:

- **Authentication** decides _whether a request is allowed to run at all_ (checked
  server-side on every request; applies to Zynda).
- **CORS** only decides _whether a browser on another origin may read the
  response_. It is a browser-enforced read-gate and has **no bearing on
  server-to-server callers like Zynda**.

CORS is already fail-closed by default (`src/server/cors/origins.ts`): no wildcard
unless `CORS_ALLOW_ALL=true`; an unknown `Origin` is not echoed. For the Zynda
deployment:

```ini
# Do NOT set CORS_ALLOW_ALL=true. Leave CORS unconfigured (fail-closed) unless a
# specific browser app needs it, in which case allowlist its exact origin:
# CORS_ALLOWED_ORIGINS=https://your-browser-app.example.com
```

The `/v1/*` surface may echo the request `Origin` (or `*` only when there is no
`Origin` header) for **token-bearing** requests, and **never** pairs that with
`Access-Control-Allow-Credentials` (`applyCorsHeaders` never sets that header) —
this is the hardened GHSA-7px7-29v2-m97p behavior and is deliberately preserved,
not loosened. Pinned by `tests/unit/zynda-security-posture.test.ts`.

### 2.3 Agent Card public URL (the one source change)

**Before:** `getBaseUrl()` resolved `OMNIROUTE_BASE_URL` → request origin →
`localhost`, so a request with `Host: 0.0.0.0:20128` made the card advertise
`http://0.0.0.0:20128/a2a`, and the configured public-base-URL settings were
ignored.

**After (`src/lib/wellKnown.ts`):** resolution is now
`OMNIROUTE_BASE_URL` (admin override) → the hardened public origin
(`resolvePublicOrigin` — honors `OMNIROUTE_PUBLIC_BASE_URL` / `NEXT_PUBLIC_BASE_URL`
/ `NEXT_PUBLIC_APP_URL`, then a trusted `X-Forwarded-Host`, then the request
origin) → `localhost`. In **every** branch an unroutable host (`0.0.0.0`, `::`,
wildcard) is rejected and falls through, so the card can never advertise the bind
address. Pinned by `tests/unit/well-known-agent-card-url.test.ts`.

To advertise the real public address behind the reverse proxy, set:

```ini
OMNIROUTE_PUBLIC_BASE_URL=https://omniport.ink
```

The card at `/.well-known/agent.json` and `/.well-known/agent-card.json` then
advertises `https://omniport.ink/a2a`. (If the proxy forwards a trusted
`X-Forwarded-Host: omniport.ink` and `OMNIROUTE_TRUST_PROXY` permits it, the card
resolves the same value without the env var — but setting
`OMNIROUTE_PUBLIC_BASE_URL` is the explicit, recommended choice.)

> `https://omniport.ink/a2a` as the externally reachable path is **unverified** —
> confirm against the live reverse-proxy config before relying on it.

### 2.4 Verification

Automated (run now, no production needed):

```bash
node --import tsx/esm --test \
  tests/unit/authz/handler-auth-bypass.test.ts \
  tests/unit/zynda-security-posture.test.ts \
  tests/unit/well-known-agent-card-url.test.ts \
  tests/unit/zynda-key-and-combos.test.ts
```

Production smoke test (run on the deployed instance, after setting the env above):

```bash
# Expect 401 (auth rejected before body validation)
curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST https://omniport.ink/v1/chat/completions \
  -H 'Content-Type: application/json' -d '{}'

# Expect the card to advertise the public URL, never 0.0.0.0
curl -s https://omniport.ink/.well-known/agent.json | grep -o '"url":"[^"]*"'
```

---

## 3. The `zynda-prod` least-privilege key

All field names below are the **verified** schema (`src/lib/db/apiKeys.ts`,
`src/lib/db/apiKeys/permissionsUpdate.ts`). The task's illustrative JSON maps as:

| Illustrative field                                                       | Actual field                                            | Value for Zynda                                                                                                                                   |
| ------------------------------------------------------------------------ | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `modelAccessMode: "restricted"`                                          | `modelAccessMode`                                       | `"restricted"`                                                                                                                                    |
| `catalogScope: "combos"`                                                 | `catalogScope`                                          | `"combos"`                                                                                                                                        |
| `allowAutoCombos: false`                                                 | `allowAutoCombos`                                       | `false`                                                                                                                                           |
| `cacheDefaultMode: "bypass"`                                             | `cacheDefaultMode`                                      | `"bypass"` (skips semantic cache lookup — `open-sse/handlers/chatCore/semanticCache.ts`)                                                          |
| `allowedEndpoints: ["/v1/messages","/v1/chat/completions","/v1/models"]` | `allowedEndpoints` (stores **category IDs**, not paths) | `["chat","models"]` (`/v1/messages` + `/v1/chat/completions` → `chat`; `/v1/models` → `models`; see `src/shared/constants/endpointCategories.ts`) |
| (approved combos)                                                        | `allowedCombos`                                         | the Zynda catalog IDs (see §4)                                                                                                                    |

### Create / rotate / revoke (admin API — requires `manage` scope)

All key-admin routes are under `/api/keys` and require `requireManagementAuth`
(a dashboard session, a trusted-loopback call, or an API key carrying the
**`manage`** scope — `src/lib/api/requireManagementAuth.ts`).

**Create** (`POST /api/keys`) — the created secret is in the response; capture it
securely and never log or commit it:

```bash
# $ADMIN = a manage-scoped key or dashboard session; $BASE = https://omniport.ink
curl -s -X POST "$BASE/api/keys" -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json' -d '{
    "name": "zynda-prod",
    "modelAccessMode": "restricted",
    "allowedModels": [],
    "allowedCombos": ["anthropic/claude-haiku-5.5","zai/glm-5.3-flash","alibaba/qwen3.8-flash"]
  }'
# -> capture .key from the response (shown once)
```

Then set the remaining policy with **`PATCH /api/keys/{id}`**:

```bash
curl -s -X PATCH "$BASE/api/keys/$KEY_ID" -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json' -d '{
    "catalogScope": "combos",
    "allowAutoCombos": false,
    "cacheDefaultMode": "bypass",
    "allowedEndpoints": ["chat","models"]
  }'
```

**Rotate** (`POST /api/keys/{id}/regenerate`) — invalidates the old secret
immediately, returns the new one:

```bash
curl -s -X POST "$BASE/api/keys/$KEY_ID/regenerate" -H "Authorization: Bearer $ADMIN"
```

**Revoke** (`DELETE /api/keys/{id}`):

```bash
curl -s -X DELETE "$BASE/api/keys/$KEY_ID" -H "Authorization: Bearer $ADMIN"
```

The dashboard (API Manager) performs the same operations through the UI.

### `/v1/models` filtering

`/v1/models` **does** filter per key (`src/app/api/v1/models/catalog.ts` →
`filterCatalogModelsForKey`): with `catalogScope:"combos"` it lists only combo
rows, gated by `allowedCombos`; provider models and `auto/*` are hidden
(`allowAutoCombos:false` also suppresses auto-combo synthesis). So the `zynda-prod`
key sees exactly its approved catalog IDs. Pinned by
`tests/unit/zynda-key-and-combos.test.ts`.

> Caveat: `GET /v1/combos` (the combos listing) does **not** per-key-filter — it
> returns all combos. Zynda should discover its catalog via `/v1/models`, which
> does filter.

---

## 4. One combo per Zynda catalog model

Verified combo schema (`src/shared/validation/schemas/combo.ts`,
`src/lib/combos/steps.ts`):

- The targets field is **`models`** (an array) — there is no `steps` field.
- Combo **names may contain `/`** (`comboNameSchema` regex includes `/`), so
  `anthropic/claude-haiku-5.5` is a valid combo name.
- A string entry like `"cc/claude-haiku-5-5"` maps to that exact provider/model;
  an object entry `{ "model": "...", "provider": "..." }` resolves to
  `provider/model`.

Create via `POST /api/combos` (manage-auth, `createComboSchema`):

```bash
curl -s -X POST "$BASE/api/combos" -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json' -d '{
    "name": "anthropic/claude-haiku-5.5",
    "strategy": "priority",
    "models": ["cc/claude-haiku-5-5"]
  }'
```

Repeat per approved Zynda catalog ID, each targeting the **correct** underlying
model/account.

**Hard constraints (enforced by the key config above, not the combo):**

- Do **not** add `vag/*` to any combo.
- Do **not** include `auto/*` or unauthenticated providers in Zynda's approved
  combos (the `zynda-prod` key sets `allowAutoCombos:false`).

**Unverified prerequisites — do NOT create blindly:** whether accounts for
`zai`/GLM, `alibaba`/qwen, or the Claude Code (`cc/*`) target are actually
connected cannot be determined from source. Before creating a production combo,
confirm the target model id exists and a provider connection is present
(`GET /v1/models` with an unrestricted key, or the Providers dashboard). If an
account is missing, report the missing prerequisite instead of fabricating
availability.

---

## 5. Fail-fast resilience (scope reference)

Verified in `src/lib/resilience/settings.ts` /
`src/lib/resilience/settings/types.ts` and the per-combo
`comboRuntimeConfigSchema` (`src/shared/validation/schemas/combo.ts`):

| Requested                            | Actual setting                                                                                         | Scope                        | Notes                                                                               |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------ | ---------------------------- | ----------------------------------------------------------------------------------- |
| `waitForCooldown.enabled=false`      | `waitForCooldown` (`enabled`, …)                                                                       | **Global only**              | No per-key/per-combo variant. Changing affects all users.                           |
| `comboCooldownWait.enabled=false`    | `comboCooldownWait` (`enabled`, …)                                                                     | **Global only**              | Applies to all combo strategies.                                                    |
| `maxGlobalAttempts=3`                | `maxGlobalAttempts`                                                                                    | **Per-combo** (`config`)     | Set it on each Zynda combo (min 1, hard cap 200). Prefer this over a global change. |
| `queueDepth=0`                       | `config.queueDepth` (per-combo) / `requestQueue.maxQueueDepth` (global)                                | **Per-combo** and **global** | Per-combo `0` = fail over immediately.                                              |
| `alwaysPreserveClientCache="always"` | `alwaysPreserveClientCache` (`"auto"\|"always"\|"never"`) global; `context_cache_protection` per-combo | Global + per-combo analog    | Honor the documented enum semantics.                                                |

**Recommendation:** use the per-combo knobs (`maxGlobalAttempts`, `queueDepth`) on
the Zynda combos so the fail-fast behavior is scoped to Zynda. `waitForCooldown` /
`comboCooldownWait` are **global-only**; disabling them affects every other user,
so change them only with that understood.

---

## 6. What is NOT verified here

- Nothing was deployed or run against production. The `401` smoke test and the
  Agent Card public URL must be confirmed on the live instance (§2.4).
- Vercel fallback behavior (on the Zynda side) is out of this repo's scope and
  unverified.
- Phases 6–12 of the original brief (pre-stream HTTP error commit, SSE keepalive
  framing, error-type distinctions, session affinity, streaming usage, provider
  blocking, cache/compression/logging/executor audit) were investigated but are
  **not** part of this change set — several already behave as asked in 3.8.52
  (e.g. `x-session-affinity` has an equivalent via `x-session-id`/`x-omniroute-session`
  with `sessionAffinityTtlMs`; `blockedProviders` exists for no-auth providers).
  Track them as follow-ups.
