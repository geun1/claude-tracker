/**
 * Offload large strings to R2 to keep D1 rows small (D1 has a 1MB row cap).
 * Anything > 50KB goes to R2; D1 keeps the key.
 */
const INLINE_THRESHOLD = 50 * 1024; // 50KB

export type Bucket = R2Bucket;

export async function maybeOffload(
  bucket: Bucket,
  prefix: string,
  value: string | null | undefined
): Promise<{ inline: string | null; key: string | null }> {
  if (!value) return { inline: null, key: null };
  if (value.length <= INLINE_THRESHOLD) return { inline: value, key: null };
  const key = `${prefix}/${crypto.randomUUID()}`;
  await bucket.put(key, value, { httpMetadata: { contentType: "text/plain; charset=utf-8" } });
  return { inline: value.slice(0, 4000) + "\n[…offloaded]", key };
}

export async function loadIfOffloaded(bucket: Bucket, key: string | null | undefined): Promise<string | null> {
  if (!key) return null;
  const obj = await bucket.get(key);
  if (!obj) return null;
  return await obj.text();
}

export async function deleteOffloaded(bucket: Bucket, keys: string[]): Promise<number> {
  let n = 0;
  for (const key of keys) {
    if (!key) continue;
    try { await bucket.delete(key); n++; } catch {}
  }
  return n;
}
