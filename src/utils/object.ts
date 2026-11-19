export type Loose<T> = { [K in keyof T]: T[K] | undefined };

/** Drop undefined-valued keys so objects satisfy exactOptionalPropertyTypes. */
export function compact<T extends object>(obj: Loose<T>): T {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) if (value !== undefined) out[key] = value;
  return out as T;
}
