#!/usr/bin/env node
/**
 * /tracker-jira <subcommand> ... — duse-ai-plugin Jira credential management.
 *
 * Subcommands:
 *   status                                       현재 Jira 연결 상태
 *   set    --url=URL --email=E --token=T         자격증명 저장 (Worker가 검증 후 암호화 저장)
 *   test   --url=URL --email=E --token=T         저장 안 하고 테스트만
 *   test                                         이미 저장된 자격증명 재확인
 *   disconnect                                   서버에서 자격증명 삭제
 *
 * 자격증명은 Worker DB(user_integrations)에 INTEGRATION_KEY로 암호화 저장됩니다.
 * 한 번 저장하면, 같은 user-token을 쓰는 모든 Claude 세션에서 자동 사용 가능합니다.
 *
 * Reads ~/.claude/tracker.json for { endpoint, token } (Worker auth).
 */
const fs = require("fs");
const os = require("os");
const path = require("path");

function loadConfig() {
  const candidates = [
    process.env.CLAUDE_TRACKER_CONFIG,
    path.join(os.homedir(), ".claude", "tracker.json"),
    path.join(os.homedir(), ".config", "claude-tracker", "config.json"),
  ].filter(Boolean);
  for (const p of candidates) {
    try { if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, "utf8")); } catch {}
  }
  return {};
}

async function call(method, pathName, body) {
  const cfg = loadConfig();
  const endpoint = cfg.endpoint || process.env.CLAUDE_TRACKER_ENDPOINT || cfg.server;
  const token = cfg.token || process.env.CLAUDE_TRACKER_TOKEN;
  if (!endpoint || !token) throw new Error("tracker.json에 endpoint/token 없음 — /tracker-config 먼저 실행");
  const base = endpoint.replace(/\/events\/?$/, "").replace(/\/$/, "");
  const url = base + pathName;
  const res = await fetch(url, {
    method,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = { _raw: text }; }
  if (!res.ok) throw new Error(json.error || json.detail || `HTTP ${res.status}`);
  return json;
}

function parseFlags(argv) {
  const out = {};
  for (const a of argv) {
    if (!a.startsWith("--")) continue;
    const [k, ...v] = a.replace(/^--/, "").split("=");
    out[k] = v.length ? v.join("=") : true;
  }
  return out;
}

function fmtStatus(j) {
  const lines = [];
  lines.push("🎟  Jira 연결됨");
  lines.push(`  base_url    : ${j.base_url || "?"}`);
  lines.push(`  account     : ${j.account_email || "?"}`);
  let meta = {}; try { meta = JSON.parse(j.meta_json || "{}"); } catch {}
  if (meta.displayName)              lines.push(`  displayName : ${meta.displayName}`);
  if (typeof meta.projectsCount === "number") lines.push(`  projects    : ${meta.projectsCount}`);
  if (j.updated_at)                  lines.push(`  updated     : ${j.updated_at}`);
  return lines.join("\n");
}

(async () => {
  const sub = process.argv[2];
  const flags = parseFlags(process.argv.slice(3));
  try {
    if (!sub || sub === "status") {
      const list = await call("GET", "/api/integrations");
      const j = (list || []).find((x) => x.kind === "jira");
      if (!j) {
        console.log("✗ Jira 미연결");
        console.log("");
        console.log("연결: /tracker-jira set --url=https://your.atlassian.net --email=you@x.com --token=ATATT...");
        return;
      }
      console.log(fmtStatus(j));
      return;
    }

    if (sub === "set") {
      const base_url = flags.url || flags["base-url"];
      const email = flags.email;
      const token = flags.token;
      if (!base_url || !email || !token) {
        throw new Error("usage: /tracker-jira set --url=URL --email=EMAIL --token=ATATT...");
      }
      const r = await call("POST", "/api/integrations/jira", { base_url, email, token });
      console.log("✓ Jira 자격증명 저장 완료 (서버에 암호화 저장)");
      if (r.displayName)                          console.log(`  Jira user : ${r.displayName}`);
      if (typeof r.projectsCount === "number")    console.log(`  projects  : ${r.projectsCount}`);
      console.log("");
      console.log("같은 tracker 토큰을 쓰는 모든 Claude 세션에서 즉시 사용 가능합니다.");
      console.log("→ /tracker-ticket list  또는  /tracker-ticket context <KEY>");
      return;
    }

    if (sub === "test") {
      const base_url = flags.url || flags["base-url"];
      const email = flags.email;
      const token = flags.token;
      const anyFlag = base_url || email || token;
      if (anyFlag) {
        if (!base_url || !email || !token) {
          throw new Error("test에 플래그를 주려면 --url, --email, --token 모두 필요");
        }
        const r = await call("POST", "/api/integrations/jira/test", { base_url, email, token });
        if (r.ok) {
          console.log("✓ 테스트 성공 (저장되지 않음)");
          if (r.user?.displayName)                console.log(`  Jira user : ${r.user.displayName}`);
          if (typeof r.projectsCount === "number") console.log(`  projects  : ${r.projectsCount}`);
        } else {
          console.log(`✗ 테스트 실패: ${r.error || "unknown"}`);
          process.exit(1);
        }
      } else {
        const r = await call("GET", "/api/integrations/jira/tickets");
        if (!r.ok) {
          console.log(`✗ 저장된 자격증명 확인 실패: ${r.error || "unknown"}`);
          process.exit(1);
        }
        console.log("✓ 저장된 Jira 자격증명 정상 동작");
        console.log(`  base_url      : ${r.base_url}`);
        console.log(`  open tickets  : ${r.count}`);
      }
      return;
    }

    if (sub === "disconnect" || sub === "remove") {
      await call("DELETE", "/api/integrations/jira");
      // Re-arm the bootstrap nudge so the user gets a reminder next session.
      try { fs.unlinkSync(path.join(os.homedir(), ".claude", ".tracker-jira-nudged")); } catch {}
      console.log("✓ Jira 연결 해제됨 (서버에서 자격증명 삭제)");
      return;
    }

    console.log("usage: /tracker-jira <status|set|test|disconnect> [flags]");
    console.log("");
    console.log("  status                                          현재 연결 상태");
    console.log("  set --url=URL --email=E --token=T               저장 (자동 검증)");
    console.log("  test --url=URL --email=E --token=T              저장 안 하고 테스트");
    console.log("  test                                            저장된 자격증명 확인");
    console.log("  disconnect                                      연결 해제");
    process.exit(2);
  } catch (e) {
    console.error("error:", e.message || e);
    process.exit(1);
  }
})();
