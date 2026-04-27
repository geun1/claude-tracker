# 전사 셋업 (Cloudflare Access + Custom Domain)

이 문서는 라이브 배포된 Worker(`https://claude-tracker.gsong.workers.dev`)를
사내 정식 도구로 잠그는 절차입니다. 30분 분량.

## 0. 현재 상태

- ✅ Worker 배포됨
- ✅ D1, R2, 마이그레이션, 정적 자산 OK
- ✅ Per-user 토큰 시스템 (`/api/admin/tokens`)
- ⚠ 도메인은 `*.workers.dev` (사내 공식 도메인 권장)
- ⚠ Cloudflare Access 미적용 (현재 토큰만으로 인증)
- ⚠ `LEGACY_BEARER_ADMIN=true` (TRACKER_TOKEN이 admin)

## 1. 커스텀 도메인 바인딩

CF 대시보드 → Workers & Pages → `claude-tracker` → **Settings** → **Domains & Routes** → Add → **Custom Domain**.

- 도메인: `tracker.aptner.com`
- 자동으로 DNS A 레코드 + TLS 인증서 발급 (proxied=on)

확인:

```bash
curl -s https://tracker.aptner.com/health
# {"ok":true,...}
```

## 2. Cloudflare Access (SSO)

Zero Trust 대시보드 (`one.dash.cloudflare.com`) → **Access** → **Applications** → **Add application** → **Self-hosted**.

| 항목 | 값 |
|---|---|
| Application name | claude-tracker |
| Session Duration | 24h |
| Application domain | `tracker.aptner.com` |
| Path | `/api/*`, `/browse`, `/` (전체 정책 적용) — 또는 `*` |
| Identity provider | Google Workspace (or Okta/AzureAD) |

**Policy** (Allow):
- Action: Allow
- Rule: `Emails ending in @aptner.com`
- (선택) 추가 그룹 룰: AX팀, Platform팀 등

**Bypass policy** (선택, hook 자동화용):
- Action: Bypass
- Rule: `Service Token` (다음 절차)

## 3. Hook 자동화용 Service Token (선택)

CLI hook은 SSO 브라우저 흐름이 안 됨. 두 가지 방법:

### 방법 A: per-user 토큰 (간단)
각자 발급된 토큰을 `~/.claude/tracker.json`에 저장. Access를 우회하려면
Worker 자체에 토큰 헤더가 도달해야 하므로 Access 정책에서 ingestion 경로
(`/events`, `/messages/bulk`)는 Bypass.

### 방법 B: CF Service Token
Zero Trust → Access → Service Auth → Service Tokens → Create.
발급받은 `CF-Access-Client-Id`, `CF-Access-Client-Secret`을 hook 환경변수로.

Worker는 `Cf-Access-Authenticated-User-Email` 헤더를 신뢰하므로 service-token도
사용자 매핑이 필요 → 방법 A를 권장.

## 4. 마지막 락다운

SSO와 per-user 토큰이 완전히 자리 잡으면:

```bash
# 1) wrangler.toml에서:
LEGACY_BEARER_ADMIN = "false"

# 2) (선택) 레거시 토큰 회수
wrangler secret delete TRACKER_TOKEN

# 3) 재배포
npm run deploy
```

이제 `TRACKER_TOKEN` 보유자도 admin이 아닌 일반 사용자가 됨 (혹은 토큰
삭제 시 인증 자체 실패).

## 5. 운영 체크리스트

- [ ] 토큰 발급 워크플로 정해두기 (구두 vs 슬랙 DM vs 사내 1Password)
- [ ] 누가 admin이어야 하는가 (보안팀 + AX 리드)
- [ ] 매일 retention 호출 (GitHub Actions cron 추천 — 무료)
- [ ] D1 export 백업 (주 1회 R2 또는 외부 S3로)
- [ ] CF Access 감사 로그 → SIEM 전송 (선택)

## 6. Retention Cron (GitHub Actions 예시)

```yaml
# .github/workflows/retention.yml
name: tracker retention
on:
  schedule: [{ cron: "0 19 * * *" }]  # 04:00 KST = 19:00 UTC
  workflow_dispatch:
jobs:
  purge:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -fsSL -X POST \
            -H "Authorization: Bearer ${{ secrets.TRACKER_ADMIN_TOKEN }}" \
            https://tracker.aptner.com/api/admin/retention
```

## 7. 전사 사용자 온보딩

각 동료에게 다음 한 줄을 슬랙으로 전달:

```bash
curl -fsSL https://tracker.aptner.com/install.sh | bash
```

(이 스크립트는 다음 절(`installer/install.sh`)에 정의되어 있고 Worker `/install.sh`로 서빙됨.)

스크립트가:
1. 이메일·이름·팀 묻고
2. admin이 미리 발급한 1회용 부트스트랩 토큰으로 본인 토큰 자동 발급
3. `~/.claude/tracker.json` 작성
4. `/plugin install claude-tracker` 안내

## 8. 모니터링

- CF Workers 대시보드 → Analytics: 요청수·에러율·P50/P99 지연
- D1 → Metrics: 읽기/쓰기 쿼리 통계
- R2 → 사용량
- `/api/audit` (admin): 누가 누구의 데이터를 봤는지

## 9. 비상시 회수

- 특정 토큰 즉시 회수: `DELETE /api/admin/tokens/<hash_prefix>`
- 전체 SSO 차단: CF Access Application → Disable
- 전체 Worker 중지: `wrangler deployments rollback` 또는 `wrangler delete`
- D1 PITR (최근 30일): CF 대시보드에서 시점 복구
