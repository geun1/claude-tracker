---
description: Compare two Claude models side-by-side on the user's recent sessions. One-shot rate, retry rate, cost/call, cost/edit, output tokens/call, cache hit rate, edit ratio. Inspired by codeburn compare.
argument-hint: "[modelA] [modelB] [days]"
allowed-tools: Bash(node:*)
---

You are helping the user pick the right Claude model for their workload.

Run: `node ${CLAUDE_PLUGIN_ROOT}/scripts/compare.js $ARGUMENTS`

Behavior:
- No args (or only `days`): lists models the user used in the window with cost / turns / edits / one-shot rate / retries. Tells them to call again with two model substrings to compare.
- Two model substrings (e.g. `opus haiku` or `sonnet-4-6 sonnet-4-7`): prints 7 head-to-head metrics with winner marker (✓ = better on that metric, = tie, blank = lost).

Metric meanings:
- **One-shot rate**: edit turns that didn't need a retry (higher is better).
- **Retry rate**: avg retries per edit turn (lower is better).
- **Cost per call / edit**: $ spent per API call / per editing turn.
- **Output tok / call**: avg response size (lower = more concise, usually cheaper).
- **Cache hit rate**: % of tokens served from cache reads (higher = better caching).
- **Edits / total**: fraction of turns that actually edited code (higher = less talk, more do).

After the command runs:
- Echo the script's output as-is — it's pre-formatted.
- If the user asks for a recommendation, point to the model with better one-shot rate AND lower cost/edit, unless they're using fast/cheaper-model intentionally.
