import type { NextRequest } from "next/server";

import { configuredPublicOrigins, resolvePublicOrigin } from "@/server/origin/publicOrigin";

/**
 * Bind hosts that must never be advertised as a public address. A server
 * commonly binds `0.0.0.0` (all interfaces) / `::`, and Next.js standalone then
 * reports that wildcard host in `request.nextUrl.origin`. Advertising
 * `http://0.0.0.0:20128/a2a` on the Agent Card hands peers an address they can
 * never route to (S2 follow-up — the request-origin fix previously still let a
 * `Host: 0.0.0.0` request leak the bind host into the card).
 */
const UNROUTABLE_HOSTS = new Set([
  "0.0.0.0",
  "::",
  "[::]",
  "0000:0000:0000:0000:0000:0000:0000:0000",
  "*",
  "",
]);

function isRoutableOrigin(origin: string): boolean {
  try {
    const { hostname, protocol } = new URL(origin);
    if (protocol !== "http:" && protocol !== "https:") return false;
    return !UNROUTABLE_HOSTS.has(hostname.toLowerCase());
  } catch {
    return false;
  }
}

function stripTrailingSlash(value: string): string {
  return value.endsWith("/") ? value.replace(/\/+$/, "") : value;
}

/**
 * Derive the base URL for A2A agent card endpoints.
 *
 * Resolution order (first routable wins):
 *   1. `OMNIROUTE_BASE_URL` — explicit admin override (kept for back-compat).
 *   2. The hardened public origin — the configured public-base-URL settings
 *      (`OMNIROUTE_PUBLIC_BASE_URL` / `NEXT_PUBLIC_BASE_URL` / `NEXT_PUBLIC_APP_URL`),
 *      then a trusted reverse-proxy `X-Forwarded-Host`, then the request origin
 *      (see `resolvePublicOrigin`). This is what lets the card advertise the real
 *      public HTTPS origin (e.g. `https://omniport.ink/a2a`) behind a proxy
 *      without hardcoding it.
 *   3. The loopback default — never a wildcard bind host.
 *
 * In every branch an unroutable host (`0.0.0.0`, `::`, wildcard) is rejected and
 * falls through to the next candidate, so the card can never advertise the bind
 * address even if the client supplied `Host: 0.0.0.0:20128`.
 */
export function getBaseUrl(request?: NextRequest | null): string {
  const override = process.env.OMNIROUTE_BASE_URL?.trim();
  if (override && isRoutableOrigin(override)) return stripTrailingSlash(override);

  if (request) {
    try {
      const resolved = resolvePublicOrigin(request).origin;
      if (isRoutableOrigin(resolved)) return resolved;
    } catch {
      // Fall through to the configured/loopback candidates below.
    }
  } else {
    // Programmatic / unit-test invocation with no Request: honor the configured
    // public-base-URL settings before the loopback default.
    const configured = configuredPublicOrigins()[0]?.origin;
    if (configured && isRoutableOrigin(configured)) return configured;
  }

  const defaultPort = process.env.PORT || process.env.DASHBOARD_PORT || 20128;
  return `http://localhost:${defaultPort}`;
}
