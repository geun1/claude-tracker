/**
 * PII / secret masking for ingestion.
 *
 * Note: emails are intentionally NOT masked — they identify the user.
 * Everything else (API keys, tokens, phone, SSN, abs file paths under $HOME,
 * IP addresses inside text bodies) is redacted.
 */

type Replacement = string | ((match: string, ...args: any[]) => string);
const MASKS: Array<[RegExp, Replacement]> = [
  // Anthropic / OpenAI / GitHub / AWS / generic API keys
  [/sk-ant-api03-[A-Za-z0-9_-]{20,}/g, "<REDACTED:anthropic_key>"],
  [/sk-[A-Za-z0-9]{20,}/g, "<REDACTED:openai_key>"],
  [/ghp_[A-Za-z0-9]{30,}/g, "<REDACTED:github_pat>"],
  [/gho_[A-Za-z0-9]{30,}/g, "<REDACTED:github_oauth>"],
  [/AKIA[0-9A-Z]{16}/g, "<REDACTED:aws_access_key>"],
  [/aws_secret_access_key\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}['"]?/gi, "<REDACTED:aws_secret>"],
  [/xox[baprs]-[A-Za-z0-9-]{10,}/g, "<REDACTED:slack_token>"],
  [/Bearer\s+[A-Za-z0-9._\-+/=]{20,}/gi, "Bearer <REDACTED>"],
  [/Authorization:\s*[^\s\n]+/gi, "Authorization: <REDACTED>"],

  // Korean phone numbers
  [/(?:\+?82[-\s]?)?0?1[016-9][-\s]?\d{3,4}[-\s]?\d{4}/g, "<REDACTED:phone>"],
  // Korean SSN (주민번호)
  [/\b\d{6}[-\s]?[1-4]\d{6}\b/g, "<REDACTED:ssn>"],
  // Credit card-ish 13-19 digits
  [/\b(?:\d[ -]?){13,19}\b/g, (m: string) => (/^[\d\s-]+$/.test(m) && m.replace(/\D/g, "").length >= 13 ? "<REDACTED:card>" : m)],

  // Private keys
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----/g, "<REDACTED:private_key>"],

  // .env style assignments — keep key, redact value
  [/((?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|API_KEY)[A-Z0-9_]*)\s*=\s*['"]?([^'"\n]+)['"]?/gi, "$1=<REDACTED>"],

  // JWTs
  [/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, "<REDACTED:jwt>"],

  // Public IPv4 (keep private RFC1918 alone for debugging)
  [/\b(?!(?:10|127|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, "<REDACTED:ip>"],
];

// Home-dir absolute paths → ~/...
function normalizeHomePaths(s: string): string {
  return s.replace(/\/Users\/[^\/\s"']+/g, "~").replace(/\/home\/[^\/\s"']+/g, "~");
}

export function maskString(input: string | null | undefined): string | null {
  if (input == null) return null;
  let s = input;
  for (const [re, rep] of MASKS) s = s.replace(re, rep as any /* TS: union of string|fn */);
  s = normalizeHomePaths(s);
  return s;
}

export function maskJsonValue(v: unknown): unknown {
  if (typeof v === "string") return maskString(v);
  if (Array.isArray(v)) return v.map(maskJsonValue);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      // Drop known sensitive keys outright
      if (/^(password|api[_-]?key|secret|token|credential)$/i.test(k)) {
        out[k] = "<REDACTED>";
      } else {
        out[k] = maskJsonValue(val);
      }
    }
    return out;
  }
  return v;
}
