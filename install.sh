#!/usr/bin/env bash
# claude-tracker 동료 설치 스크립트
#
# 사용:
#   curl -fsSL https://tracker.aptner.com/install.sh | bash
# 또는 로컬:
#   bash install.sh
#
# 무엇을 하나:
#   1) 이메일·이름·팀 입력 받기
#   2) admin이 발급한 본인 토큰을 입력 받아 ~/.claude/tracker.json 작성
#   3) (선택) 과거 transcript 백필
#   4) Claude Code 마켓플레이스에 플러그인 추가 안내

set -e

ENDPOINT_DEFAULT="https://claude-tracker.gsong.workers.dev/events"
TRACKER_BASE="${ENDPOINT_DEFAULT%/events}"

bold() { printf "\033[1m%s\033[0m\n" "$1"; }
ask() { local prompt="$1" var="$2" def="$3"; printf "%s%s: " "$prompt" "${def:+ [$def]}"; read -r REPLY; eval "$var=\"${REPLY:-$def}\""; }

bold "🟧 claude-tracker 사용자 설정"
echo

ask "이메일 (회사)" EMAIL ""
[ -z "$EMAIL" ] && { echo "이메일은 필수입니다."; exit 1; }
ask "이름" NAME ""
ask "팀" TEAM ""
ask "엔드포인트" ENDPOINT "$ENDPOINT_DEFAULT"
ask "관리자에게 받은 본인 API 토큰 (관리자가 /api/admin/tokens로 발급)" TOKEN ""
[ -z "$TOKEN" ] && { echo "토큰은 필수입니다. 관리자에게 요청하세요."; exit 1; }

CONFIG="$HOME/.claude/tracker.json"
mkdir -p "$(dirname "$CONFIG")"
cat > "$CONFIG" <<EOF
{
  "endpoint": "$ENDPOINT",
  "token": "$TOKEN",
  "user_email": "$EMAIL",
  "user_name": "$NAME",
  "team": "$TEAM",
  "local_log_dir": "$HOME/.claude/tracker-logs"
}
EOF
chmod 600 "$CONFIG"

bold "✅ 설정 저장됨: $CONFIG"
echo

# Verify with /api/me
bold "🔎 토큰 검증 중..."
ME=$(curl -s -H "Authorization: Bearer $TOKEN" "$TRACKER_BASE/api/me")
echo "$ME" | grep -q '"email"' || { echo "❌ 토큰 검증 실패: $ME"; exit 1; }
echo "$ME"
echo

bold "📦 Claude Code 플러그인 설치"
cat <<EOF
Claude Code 안에서 한 번만 실행:

  /plugin marketplace add https://github.com/<your-org>/claude-tracker
  /plugin install claude-tracker

(GitHub URL은 관리자에게 확인)
EOF
echo

read -r -p "과거 transcript도 지금 백필할까요? (y/N) " REPLY
if [[ "$REPLY" =~ ^[Yy]$ ]]; then
  if [ -d "$HOME/.claude/projects" ]; then
    bold "⏳ 백필 중 (수 분 걸릴 수 있음)..."
    CLAUDE_TRACKER_USER="$EMAIL" \
    CLAUDE_TRACKER_NAME="$NAME" \
    CLAUDE_TRACKER_TEAM="$TEAM" \
    node "$(dirname "$0")/scripts/backfill.js" "$ENDPOINT" "$TOKEN" || true
  else
    echo "~/.claude/projects 가 없습니다. 백필 건너뜁니다."
  fi
fi

bold "🎉 완료. 이제부터 모든 Claude Code 세션이 자동으로 추적됩니다."
echo "대시보드: $TRACKER_BASE/?token=$TOKEN"
