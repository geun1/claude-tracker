/**
 * Auth + role-based access control.
 *
 * Roles:
 *   admin    — sees everything across all teams
 *   manager  — sees everyone in their own team
 *   general  — sees only their own data (default)
 *
 * Resolution order:
 *   1) Cloudflare Access SSO (header `Cf-Access-Authenticated-User-Email`)
 *      role/team are looked up from the `tokens` table by email
 *   2) Per-user token (Bearer or ?token=) — role/team from the token row
 *   3) Legacy shared bearer (TRACKER_TOKEN env, only if LEGACY_BEARER_ADMIN=true)
 */
import type { Context } from "hono";

export type Role = "admin" | "manager" | "general";
export type Actor = {
  email: string;
  name?: string;
  team?: string;
  role: Role;
  via: "access" | "user-token" | "legacy-bearer";
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
    let role: Role = adminList.includes(accessEmail.toLowerCase()) ? "admin" : "general";
    let team: string | undefined; let name: string | undefined;
    // Look up role/team from any active token issued for this email
    try {
      const row: any = await env.DB.prepare(
        "SELECT role, team, user_name FROM tokens WHERE user_email = ? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1"
      ).bind(accessEmail).first();
      if (row) { if (row.role && role !== "admin") role = row.role as Role; team = row.team; name = row.user_name; }
    } catch {}
    return { email: accessEmail, name, team, role, via: "access" };
  }

  // 2) Per-user token (header or query)
  const auth = c.req.header("authorization");
  let raw: string | null = null;
  if (auth?.startsWith("Bearer ")) raw = auth.slice(7);
  if (!raw) raw = new URL(c.req.url).searchParams.get("token");
  if (raw) {
    const hash = await sha256Hex(raw);
    const row: any = await env.DB.prepare(
      "SELECT user_email, user_name, team, role FROM tokens WHERE token_hash = ? AND revoked_at IS NULL"
    ).bind(hash).first();
    if (row) {
      c.executionCtx.waitUntil(
        env.DB.prepare("UPDATE tokens SET last_used_at = ? WHERE token_hash = ?")
          .bind(new Date().toISOString(), hash).run().catch(() => {})
      );
      return { email: row.user_email, name: row.user_name, team: row.team, role: (row.role || "general") as Role, via: "user-token" };
    }
    // 3) Legacy bearer
    if (env.TRACKER_TOKEN && raw === env.TRACKER_TOKEN) {
      const legacyAdmin = String(env.LEGACY_BEARER_ADMIN || "").toLowerCase() === "true";
      return { email: "system:bearer", role: legacyAdmin ? "admin" : "general", via: "legacy-bearer" };
    }
  }

  return null;
}

/** Returns SQL fragment + params to scope a query to what the actor can see. */
export function scopeFor(actor: Actor): { sql: string; params: any[] } {
  if (actor.role === "admin") return { sql: "", params: [] };
  if (actor.role === "manager" && actor.team) {
    return { sql: " AND team = ? ", params: [actor.team] };
  }
  // general (or manager without team)
  return { sql: " AND user_email = ? ", params: [actor.email] };
}

export function canSeeUser(actor: Actor, targetEmail: string, targetTeam: string | null | undefined): boolean {
  if (actor.role === "admin") return true;
  if (actor.role === "manager") return !!actor.team && targetTeam === actor.team;
  return targetEmail === actor.email;
}

export function canIssueRole(actor: Actor, role: Role): boolean {
  if (actor.role === "admin") return true; // admin can issue any role
  if (actor.role === "manager") return role === "general"; // manager can only invite general users
  return false;
}

export function isAdmin(actor: Actor): boolean { return actor.role === "admin"; }
export function isManagerOrAbove(actor: Actor): boolean { return actor.role === "admin" || actor.role === "manager"; }

export async function hashToken(raw: string): Promise<string> { return sha256Hex(raw); }
export function generateToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
