/**
 * Cloudflare Access auth + per-user token auth.
 *
 * Resolution order on every request:
 *   1) Cloudflare Access SSO (header `Cf-Access-Authenticated-User-Email`)
 *   2) Per-user token (Authorization: Bearer xxx OR ?token=xxx) — looked up in `tokens` table
 *   3) Legacy shared bearer `TRACKER_TOKEN` env (only if `LEGACY_BEARER_ADMIN=true`)
 */
import type { Context } from "hono";

export type Actor = {
  email: string;
  name?: string;
  team?: string;
  via: "access" | "user-token" | "legacy-bearer";
  is_admin: boolean;
};

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function getActor(c: Context): Promise<Actor | null> {
  const env = c.env as any;

  // 1) Cloudflare Access SSO
  const accessEmail = c.req.header("cf-access-authenticated-user-email");
  if (accessEmail) {
    const adminList = (env.ADMIN_EMAILS || "").split(",").map((s: string) => s.trim().toLowerCase()).filter(Boolean);
    return {
      email: accessEmail,
      via: "access",
      is_admin: adminList.includes(accessEmail.toLowerCase()),
    };
  }

  // 2) Token from header or query
  const auth = c.req.header("authorization");
  let raw: string | null = null;
  if (auth?.startsWith("Bearer ")) raw = auth.slice(7);
  if (!raw) raw = new URL(c.req.url).searchParams.get("token");
  if (!raw) return null;

  // Look up per-user token first
  const hash = await sha256Hex(raw);
  const row: any = await env.DB.prepare(
    "SELECT user_email, user_name, team, is_admin FROM tokens WHERE token_hash = ? AND revoked_at IS NULL"
  ).bind(hash).first();
  if (row) {
    // Touch last_used (best-effort, don't await)
    c.executionCtx.waitUntil(
      env.DB.prepare("UPDATE tokens SET last_used_at = ? WHERE token_hash = ?")
        .bind(new Date().toISOString(), hash).run().catch(() => {})
    );
    return { email: row.user_email, name: row.user_name, team: row.team, via: "user-token", is_admin: !!row.is_admin };
  }

  // 3) Legacy shared bearer (bootstrap only)
  if (env.TRACKER_TOKEN && raw === env.TRACKER_TOKEN) {
    const legacyAdmin = String(env.LEGACY_BEARER_ADMIN || "").toLowerCase() === "true";
    return {
      email: "system:bearer",
      via: "legacy-bearer",
      is_admin: legacyAdmin,
    };
  }

  return null;
}

export function isAdmin(actor: Actor, _env: { ADMIN_EMAILS?: string }): boolean {
  return !!actor.is_admin;
}

export async function hashToken(raw: string): Promise<string> {
  return sha256Hex(raw);
}

export function generateToken(): string {
  // 32-byte token, urlsafe-ish base64 without padding
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
