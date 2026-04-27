# claude-tracker

전사 Claude Code 사용량을 자동 수집하는 Claude Code 플러그인 + Cloudflare 기반 중앙 서버.

- **Hooks plugin** — 모든 Claude Code 세션의 이벤트·메시지·토큰 사용량을 자동 전송
- **Cloudflare Worker** — D1(이벤트/메시지) + R2(대용량 페이로드) + Access SSO
- **Dashboard** — 팀별·모델별·사용자별 비용/토큰 시계열, CSV 내보내기
- **Session viewer** — CCHV 스타일 4-pane (사용자 → 세션 → 대화 → 메시지 인덱스)
- **Plan inference** — 사용 패턴으로 Claude Pro/Max/API 추천
- **PII/secret masking** on ingestion (이메일은 보존)
- **Per-user 토큰** + 팀 단위 권한 + 감사 로그

## 라이브 인스턴스

- API: https://claude-tracker.gsong.workers.dev (도메인 바인딩 후 `tracker.aptner.com`)
- 대시보드: same / `/`
- 세션 뷰어: same / `/browse`

## 동료 설치 (3분, 한 줄)

```bash
curl -fsSL https://claude-tracker.gsong.workers.dev/install.sh | bash
```

스크립트가 묻는 것: **이메일 / 이름 / 팀** (3개). 그게 다입니다.

자동으로 처리되는 것:
1. 토큰 자체 발급 (서버에 셀프 가입)
2. `~/.claude/tracker.json` 작성
3. 플러그인 GitHub clone → `~/.claude/plugins/claude-tracker`
4. (선택) 과거 transcript 백필

마지막에 안내된 두 줄을 Claude Code 안에서 실행:
```
/plugin marketplace add ~/.claude/plugins/claude-tracker
/plugin install claude-tracker
```

→ 이후 모든 세션이 자동 추적.

## 관리자 절차

### 토큰 발급

```bash
TRACKER=https://claude-tracker.gsong.workers.dev
ADMIN_TOKEN="<your admin token>"

curl -s -X POST "$TRACKER/api/admin/tokens" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"kim@aptner.com","name":"김동현","team":"Platform"}'
# → { "ok": true, "token": "...", ... }
# 이 토큰은 한 번만 표시됨
```

### 토큰 회수

```bash
curl -X DELETE "$TRACKER/api/admin/tokens/<hash_prefix>" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### 토큰 목록

```bash
curl "$TRACKER/api/admin/tokens" -H "Authorization: Bearer $ADMIN_TOKEN"
```

### Retention 수동 발동

```bash
curl -X POST "$TRACKER/api/admin/retention" -H "Authorization: Bearer $ADMIN_TOKEN"
```

(또는 GitHub Actions cron — `cloudflare/SETUP.md` 참고)

### 감사 로그

```bash
curl "$TRACKER/api/audit?limit=100" -H "Authorization: Bearer $ADMIN_TOKEN"
```

## 프로젝트 구조

```
claude-tracker/
├── .claude-plugin/         # 마켓플레이스 + 매니페스트
├── hooks/                  # SessionStart, UserPromptSubmit, Pre/PostToolUse, Stop, …
├── commands/               # /tracker-config, /tracker-stats
├── scripts/                # hook.js, configure.js, backfill.js, bootstrap.js, stats.js
├── server/                 # 로컬 개발용 Express + SQLite (legacy, 옵션)
├── cloudflare/             # ✨ 프로덕션
│   ├── wrangler.toml
│   ├── migrations/         # 0001_init.sql, 0002_tokens.sql
│   ├── public/             # dashboard.html, sessions.html (정적 자산)
│   ├── src/
│   │   ├── index.ts        # Hono 라우터 + cron handler
│   │   ├── auth.ts         # Access + per-user token + legacy bearer
│   │   ├── masking.ts      # PII/시크릿 마스킹
│   │   ├── pricing.ts      # 모델 단가
│   │   └── r2helpers.ts    # >50KB 페이로드 R2 오프로드
│   ├── README.md           # 셋업·인증·비용
│   └── SETUP.md            # SSO·도메인·락다운 절차
└── install.sh              # 동료 1줄 설치 스크립트
```

## 데이터 모델

| 테이블 | 용도 |
|---|---|
| `events` | hook 이벤트 (session_start, pre_tool, stop, …) + 토큰·모델·cwd·IP·도시 |
| `messages` | 대화 메시지 본문 (user/assistant/tool_use/tool_result) |
| `tokens` | per-user API 토큰 (sha256 해시만 저장) |
| `access_log` | 누가 누구의 데이터를 봤는지 |
| `retention_runs` | 자동 삭제 cron 기록 |

마스킹 룰: Anthropic/OpenAI/GitHub/AWS/Slack 키, JWT, Bearer, 한국 전화/주민/카드, 사설 키, ENV `*KEY=*`, 공인 IPv4, 홈 경로 → `~`. 이메일은 사용자 식별을 위해 보존.

## 라이선스

내부 사용 전용 (사내 비공개).
