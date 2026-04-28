/**
 * AES-GCM helpers using a 32-byte hex key from INTEGRATION_KEY secret.
 * Used to encrypt user API tokens (Jira) at rest.
 */

async function getKey(secretHex: string): Promise<CryptoKey> {
  if (!secretHex || secretHex.length !== 64) {
    throw new Error("INTEGRATION_KEY must be 32 bytes (64 hex chars)");
  }
  const raw = new Uint8Array(secretHex.match(/.{2}/g)!.map((h) => parseInt(h, 16)));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

function b64(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function unb64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function encryptToken(secretHex: string, plaintext: string): Promise<{ iv: string; ct: string }> {
  const key = await getKey(secretHex);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
  return { iv: b64(iv), ct: b64(ct) };
}

export async function decryptToken(secretHex: string, iv: string, ct: string): Promise<string> {
  const key = await getKey(secretHex);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, key, unb64(ct));
  return new TextDecoder().decode(pt);
}
