// Deterministic 13-category turn classifier. Port of codeburn classifier.ts
// (getagentseal/codeburn). No LLM. Input is shaped from the messages table:
// userMessage + flat list of tool names across assistant calls in the turn.
//
// Tie-break order in keyword matching uses first-match-wins (issue #196):
// the candidate whose regex matches earliest in the user message wins.

export type TaskCategory =
  | "coding" | "debugging" | "feature" | "refactoring" | "testing"
  | "exploration" | "planning" | "delegation"
  | "git" | "build/deploy"
  | "conversation" | "brainstorming" | "general";

const TEST_PATTERNS      = /\b(test|pytest|vitest|jest|mocha|spec|coverage|npm\s+test|npx\s+vitest|npx\s+jest)\b/i;
const GIT_PATTERNS       = /\bgit\s+(push|pull|commit|merge|rebase|checkout|branch|stash|log|diff|status|add|reset|cherry-pick|tag)\b/i;
const BUILD_PATTERNS     = /\b(npm\s+run\s+build|npm\s+publish|pip\s+install|docker|deploy|make\s+build|npm\s+run\s+dev|npm\s+start|pm2|systemctl|brew|cargo\s+build)\b/i;
const INSTALL_PATTERNS   = /\b(npm\s+install|pip\s+install|brew\s+install|apt\s+install|cargo\s+add)\b/i;
const DEBUG_KEYWORDS     = /\b(fix|bug|error|broken|failing|crash|issue|debug|traceback|exception|stack\s*trace|not\s+working|wrong|unexpected|status\s+code|404|500|401|403)\b/i;
const FEATURE_KEYWORDS   = /\b(add|create|implement|new|build|feature|introduce|set\s*up|scaffold|generate|make\s+(?:a|me|the)|write\s+(?:a|me|the))\b/i;
const REFACTOR_KEYWORDS  = /\b(refactor|clean\s*up|rename|reorganize|simplify|extract|restructure|move|migrate|split)\b/i;
const BRAINSTORM_KEYWORDS= /\b(brainstorm|idea|what\s+if|explore|think\s+about|approach|strategy|design|consider|how\s+should|what\s+would|opinion|suggest|recommend)\b/i;
const RESEARCH_KEYWORDS  = /\b(research|investigate|look\s+into|find\s+out|check|search|analyze|review|understand|explain|how\s+does|what\s+is|show\s+me|list|compare)\b/i;
const FILE_PATTERNS      = /\.(py|js|ts|tsx|jsx|json|yaml|yml|toml|sql|sh|go|rs|java|rb|php|css|html|md|csv|xml)\b/i;
const SCRIPT_PATTERNS    = /\b(run\s+\S+\.\w+|execute|scrip?t|curl|api\s+\S+|endpoint|request\s+url|fetch\s+\S+|query|database|db\s+\S+)\b/i;
const URL_PATTERN        = /https?:\/\/\S+/i;

const EDIT_TOOLS   = new Set(["Edit", "Write", "FileEditTool", "FileWriteTool", "NotebookEdit", "cursor:edit"]);
const READ_TOOLS   = new Set(["Read", "Grep", "Glob", "FileReadTool", "GrepTool", "GlobTool"]);
export const BASH_TOOLS   = new Set(["Bash", "BashTool", "PowerShellTool"]);
const TASK_TOOLS   = new Set(["TaskCreate", "TaskUpdate", "TaskGet", "TaskList", "TaskOutput", "TaskStop", "TodoWrite"]);
const SEARCH_TOOLS = new Set(["WebSearch", "WebFetch", "ToolSearch"]);

const hasAny = (tools: string[], set: Set<string>) => tools.some(t => set.has(t));
const hasMcp = (tools: string[]) => tools.some(t => t.startsWith("mcp__"));
const hasSkill = (tools: string[]) => tools.includes("Skill");
const hasAgent = (tools: string[]) => tools.includes("Agent") || tools.includes("Task");

function firstMatch(text: string, cands: ReadonlyArray<{ re: RegExp; cat: TaskCategory }>): TaskCategory | null {
  let best: { idx: number; order: number; cat: TaskCategory } | null = null;
  for (let i = 0; i < cands.length; i++) {
    const m = cands[i].re.exec(text);
    if (!m) continue;
    if (!best || m.index < best.idx || (m.index === best.idx && i < best.order)) {
      best = { idx: m.index, order: i, cat: cands[i].cat };
    }
  }
  return best?.cat ?? null;
}

function byToolPattern(userMessage: string, tools: string[], hasPlanMode: boolean): TaskCategory | null {
  if (tools.length === 0) return null;
  if (hasPlanMode) return "planning";
  if (hasAgent(tools)) return "delegation";

  const hasEdit   = hasAny(tools, EDIT_TOOLS);
  const hasRead   = hasAny(tools, READ_TOOLS);
  const hasBash   = hasAny(tools, BASH_TOOLS);
  const hasTask   = hasAny(tools, TASK_TOOLS);
  const hasSearch = hasAny(tools, SEARCH_TOOLS);

  if (hasBash && !hasEdit) {
    if (TEST_PATTERNS.test(userMessage))    return "testing";
    if (GIT_PATTERNS.test(userMessage))     return "git";
    if (BUILD_PATTERNS.test(userMessage))   return "build/deploy";
    if (INSTALL_PATTERNS.test(userMessage)) return "build/deploy";
  }
  if (hasEdit) return "coding";
  if (hasBash && hasRead) return "exploration";
  if (hasBash) return "coding";
  if (hasSearch || hasMcp(tools)) return "exploration";
  if (hasRead && !hasEdit) return "exploration";
  if (hasTask && !hasEdit) return "planning";
  if (hasSkill(tools)) return "general";
  return null;
}

function refineByKeywords(cat: TaskCategory, msg: string): TaskCategory {
  if (cat === "coding") {
    return firstMatch(msg, [
      { re: REFACTOR_KEYWORDS, cat: "refactoring" },
      { re: FEATURE_KEYWORDS,  cat: "feature" },
      { re: DEBUG_KEYWORDS,    cat: "debugging" },
    ]) ?? "coding";
  }
  if (cat === "exploration") {
    if (RESEARCH_KEYWORDS.test(msg)) return "exploration";
    if (DEBUG_KEYWORDS.test(msg))    return "debugging";
    return "exploration";
  }
  return cat;
}

function classifyConversation(msg: string): TaskCategory {
  if (BRAINSTORM_KEYWORDS.test(msg)) return "brainstorming";
  if (RESEARCH_KEYWORDS.test(msg))   return "exploration";
  const df = firstMatch(msg, [
    { re: FEATURE_KEYWORDS, cat: "feature" },
    { re: DEBUG_KEYWORDS,   cat: "debugging" },
  ]);
  if (df) return df;
  if (FILE_PATTERNS.test(msg))   return "coding";
  if (SCRIPT_PATTERNS.test(msg)) return "coding";
  if (URL_PATTERN.test(msg))     return "exploration";
  return "conversation";
}

export type TurnSig = {
  userMessage: string;
  // Flat ordered list of tool-call groups across assistant messages in the
  // turn. Each group represents one assistant message's tools (the bash/edit
  // ordering needed for retry counting).
  callsTools: string[][];
  hasPlanMode?: boolean;
};

// Edit → Bash → Edit pattern = one retry (codeburn countRetries).
export function countRetries(callsTools: string[][]): number {
  let sawEditBeforeBash = false;
  let sawBashAfterEdit = false;
  let retries = 0;
  for (const tools of callsTools) {
    const hasEdit = tools.some(t => EDIT_TOOLS.has(t));
    const hasBash = tools.some(t => BASH_TOOLS.has(t));
    if (hasEdit) {
      if (sawBashAfterEdit) retries++;
      sawEditBeforeBash = true;
      sawBashAfterEdit = false;
    }
    if (hasBash && sawEditBeforeBash) sawBashAfterEdit = true;
  }
  return retries;
}

export function turnHasEdits(callsTools: string[][]): boolean {
  return callsTools.some(g => g.some(t => EDIT_TOOLS.has(t)));
}

export function classifyTurn(sig: TurnSig): TaskCategory {
  const allTools = sig.callsTools.flat();
  if (allTools.length === 0) return classifyConversation(sig.userMessage);
  const t = byToolPattern(sig.userMessage, allTools, !!sig.hasPlanMode);
  if (t) return refineByKeywords(t, sig.userMessage);
  return classifyConversation(sig.userMessage);
}

export const TOOL_SETS = { EDIT_TOOLS, READ_TOOLS, BASH_TOOLS, TASK_TOOLS, SEARCH_TOOLS };
