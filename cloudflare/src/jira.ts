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

// 사용자가 담당자인 미완료 티켓 목록 (LLM 컨텍스트용)
export async function fetchAssignedOpen(c: JiraConn, max = 30): Promise<any[]> {
  try {
    const url = c.base_url.replace(/\/$/, "");
    const jql = encodeURIComponent('assignee = currentUser() AND statusCategory != Done ORDER BY updated DESC');
    const r = await fetch(`${url}/rest/api/3/search?jql=${jql}&maxResults=${max}&fields=summary,status`,
      { headers: authHeader(c) });
    if (!r.ok) return [];
    const j = await r.json<any>();
    return (j.issues || []).map((i: any) => ({
      key: i.key,
      summary: i.fields?.summary || "",
      status: i.fields?.status?.name || "",
      url: `${url}/browse/${i.key}`,
    }));
  } catch { return []; }
}
