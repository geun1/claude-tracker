export type Pricing = { input: number; output: number; cache_read: number; cache_create: number };

export const PRICING: Record<string, Pricing> = {
  "claude-opus-4-7":           { input: 15, output: 75, cache_read: 1.5,  cache_create: 18.75 },
  "claude-opus-4-6":           { input: 15, output: 75, cache_read: 1.5,  cache_create: 18.75 },
  "claude-sonnet-4-6":         { input: 3,  output: 15, cache_read: 0.3,  cache_create: 3.75  },
  "claude-haiku-4-5-20251001": { input: 1,  output: 5,  cache_read: 0.1,  cache_create: 1.25  },
  default:                     { input: 3,  output: 15, cache_read: 0.3,  cache_create: 3.75  },
};

export function priceOf(model: string | null | undefined): Pricing {
  return (model && PRICING[model]) || PRICING.default;
}

export function costUsd(row: {
  model?: string | null;
  input_tokens?: number; output_tokens?: number;
  cache_read_tokens?: number; cache_create_tokens?: number;
}): number {
  const p = priceOf(row.model);
  return (
    ((row.input_tokens || 0) * p.input / 1e6) +
    ((row.output_tokens || 0) * p.output / 1e6) +
    ((row.cache_read_tokens || 0) * p.cache_read / 1e6) +
    ((row.cache_create_tokens || 0) * p.cache_create / 1e6)
  );
}
