/**
 * Minimal Jira REST API client (Cloud).
 * Auth: HTTP Basic — base64("email:api_token")
 */
type JiraConn = { base_url: string; email: string; token: string };

function authHeader(c: JiraConn) {
  const b = btoa(`${c.email}:${c.token}`);
  return { Authorization: `Basic ${b}`, Accept: "application/json", "Content-Type": "application/json" };
}

export async function pingJira(c: JiraConn): Promise<{ ok: boolean; user?: any; projectsCount?: number; error?: string }> {
  try {
    const url = c.base_url.replace(/\/$/, "");
    const me = await fetch(`${url}/rest/api/3/myself`, { headers: authHeader(c) });
    if (!me.ok) return { ok: false, error: `auth failed (${me.status})` };
    const user = await me.json<any>();
    const proj = await fetch(`${url}/rest/api/3/project/search?maxResults=1`, { headers: authHeader(c) });
    // (project/search는 deprecated 아님 — issue search만 마이그레이션)
    let projectsCount = 0;
    if (proj.ok) { const p = await proj.json<any>(); projectsCount = p.total || 0; }
    return { ok: true, user, projectsCount };
  } catch (e: any) { return { ok: false, error: String(e?.message || e) }; }
}

export async function fetchTicket(c: JiraConn, key: string): Promise<any | null> {
  try {
    const url = c.base_url.replace(/\/$/, "");
    const r = await fetch(`${url}/rest/api/3/issue/${encodeURIComponent(key)}?fields=summary,status,assignee`,
      { headers: authHeader(c) });
    if (!r.ok) return null;
    const j = await r.json<any>();
    return {
      key: j.key,
      summary: j.fields?.summary || null,
      status: j.fields?.status?.name || null,
      assignee_email: j.fields?.assignee?.emailAddress || null,
      url: `${url}/browse/${j.key}`,
    };
  } catch { return null; }
}

// 사용자와 관련된 미완료 티켓 (LLM 컨텍스트용).
// assignee/reporter/watcher 또는 최근 update 본 티켓까지 폭넓게.
export async function fetchAssignedOpen(c: JiraConn, max = 50): Promise<any[]> {
  const url = c.base_url.replace(/\/$/, "");
  const queries = [
    // 1. 본인 담당/보고/관전 + 미완료
    '(assignee = currentUser() OR reporter = currentUser() OR watcher = currentUser()) AND statusCategory != Done ORDER BY updated DESC',
    // 2. 폴백: 최근 30일 내 자신이 활동한 모든 티켓
    'updated >= -30d AND (assignee = currentUser() OR reporter = currentUser()) ORDER BY updated DESC',
    // 3. 마지막 폴백: 최근 14일 내 모든 미완료 티켓 (좁은 워크스페이스용)
    'updated >= -14d AND statusCategory != Done ORDER BY updated DESC',
  ];
  // Atlassian이 2024-2025 사이에 /rest/api/3/search를 deprecate(410) 시키고
  // /rest/api/3/search/jql (POST) 로 이전. POST + body로 호출.
  for (const jql of queries) {
    try {
      const r = await fetch(`${url}/rest/api/3/search/jql`, {
        method: "POST",
        headers: { ...authHeader(c), "Content-Type": "application/json" },
        body: JSON.stringify({ jql, maxResults: max, fields: ["summary", "status", "assignee"] }),
      });
      if (!r.ok) continue;
      const j = await r.json<any>();
      const issues = (j.issues || []).map((i: any) => ({
        key: i.key,
        summary: i.fields?.summary || "",
        status: i.fields?.status?.name || "",
        assignee: i.fields?.assignee?.displayName || null,
        url: `${url}/browse/${i.key}`,
      }));
      if (issues.length) return issues;
    } catch {}
  }
  return [];
}
