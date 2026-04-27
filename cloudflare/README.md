# claude-tracker on Cloudflare (Workers + D1 + R2)

Edge-deployed multi-tenant tracker with SSO, PII masking, R2 blob offload, and daily retention cron.

## Architecture

```
Claude Code hook  ──▶  https://tracker.aptner.com/events
                          │
                          ▼   (Cloudflare Access SSO)
                       Worker (Hono)
                          │
              ┌───────────┼────────────┐
              ▼           ▼            ▼
            D1 DB      R2 Blobs    Cron (04:00 UTC)
         (events,     (>50KB       (purge per
          messages,   payloads)    RETENTION_DAYS)
          access_log)
```

## Why Cloudflare for this

- **D1**: SQLite-compatible, 5GB free, ~50ms p50 worldwide. No connection pooling.
- **R2**: $0.015/GB egress-free. Ideal for large transcript bodies.
- **Workers**: Globally edge-deployed, 0ms cold start. No infra to manage.
- **Access**: Free SSO (Google Workspace / Okta / Azure AD) with zero code.
- Single source: `wrangler deploy` ships code + DB migrations + cron + assets.

## One-time setup

```bash
cd cloudflare
npm install

# 1) Create the D1 database
npm run db:create
# → copy the database_id into wrangler.toml

# 2) Create the R2 bucket
npm run r2:create

# 3) Apply schema
npm run db:migrate

# 4) Set secrets
wrangler secret put TRACKER_TOKEN     # Optional shared bearer for legacy hooks
wrangler secret put ADMIN_EMAILS      # comma-separated, e.g. gsong@aptner.com
# Cf-Access-* headers come automatically from Cloudflare Access — no secret needed.

# 5) Copy static assets into ./public so [assets] picks them up
mkdir -p public
cp ../server/dashboard.html ../server/sessions.html public/

# 6) Deploy
npm run deploy
```

After deploy, in Cloudflare dashboard:

1. **Custom Domain** → bind `tracker.aptner.com` to the Worker.
2. **Zero Trust → Access → Applications** → add a self-hosted app at that hostname.
   - Identity provider: Google Workspace / Okta / etc.
   - Policy: `email ends with @aptner.com`.
3. **Audit logs** → enable for the Access app.

## Authentication model

| Route | Auth |
|-------|------|
| `/`, `/browse`, `/dashboard.html`, `/sessions.html` | Anonymous (just static HTML; data fetches require auth) |
| `/health` | Anonymous |
| `/events`, `/messages/bulk` | Cloudflare Access **OR** `Authorization: Bearer $TRACKER_TOKEN` |
| `/api/*` | Cloudflare Access **only** |
| `/api/audit` | Access + email in `ADMIN_EMAILS` |

Non-admin users see only their own data + sessions of teammates (same `team` field).
Admins see everything.

## Data privacy

Ingestion runs `maskJsonValue()` on every payload:

- **Not masked**: `email` (it's the user identity key).
- **Masked**: API keys (Anthropic/OpenAI/GitHub/AWS/Slack), JWTs, private keys,
  Korean phone/SSN, credit cards, `Authorization` headers, `*_KEY=*_TOKEN=` env
  assignments, public IPv4 in text bodies.
- **Normalized**: `/Users/<name>/...` → `~/...`.

Anything > 50KB is offloaded to R2 (so D1 rows stay small and fast).

## Retention

Set `RETENTION_DAYS` in `wrangler.toml` (default 365). The daily cron at 04:00 UTC:

1. Lists all R2 keys referenced by events/messages older than the cutoff.
2. Deletes those R2 objects.
3. Deletes the D1 rows.
4. Records the run in `retention_runs`.

## Backups

D1 has built-in **Point-in-Time Recovery** (last 30 days, free). No litestream needed.
For longer-term archives, run `wrangler d1 export claude-tracker --output backup.sql`
on a cron from a CI job, push to R2 or a private S3.

## Pointing the hook at your Worker

On each developer's machine:

```bash
/tracker-config https://tracker.aptner.com/events
# Cloudflare Access in the browser → SSO once → cookie persists.
# For headless hooks running in shells, use CF Service Token:
#   curl -H 'CF-Access-Client-Id: ...' -H 'CF-Access-Client-Secret: ...'
# OR fall back to TRACKER_TOKEN (set above).
```

The hook script silently posts events; the dashboard lives at
`https://tracker.aptner.com/`.

## Cost projection (≤200 users)

| Component | Free tier | Expected |
|-----------|-----------|----------|
| Workers requests | 100k/day | ≤30k/day |
| D1 reads/writes | 5M/d read · 100k/d write | well under |
| R2 storage | 10GB | ~2GB after 1 yr |
| Access seats | 50 free | covered |

Realistically: **$0–5/month** for a 200-user team.

## Migrating from the local Express server

You can run both side-by-side during cutover:

```bash
# Mirror events to both
endpoint_legacy=http://localhost:3737/events
endpoint_cf=https://tracker.aptner.com/events
```

To one-shot import the existing SQLite into D1:

```bash
sqlite3 /tmp/tracker-corp.db .dump | wrangler d1 execute claude-tracker --remote --file=/dev/stdin
```

(Tip: strip `BEGIN TRANSACTION/COMMIT` and remove `CREATE TABLE` for tables that
already exist before piping.)
