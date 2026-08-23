// Formatting, with the decisions that matter for money and time in one place.

/**
 * Integer minor units, rendered without ever going near a float.
 *
 * The exponent is per currency — kobo and cents have two, yen has none, the
 * Gulf dinars have three — so a divide-by-100 would misstate some currencies
 * by a hundredfold and JPY by exactly that. The digits are shifted instead,
 * which is the same arithmetic the server does and cannot round.
 */
const EXPONENT: Record<string, number> = {
  NGN: 2, USD: 2, EUR: 2, GBP: 2, GHS: 2, KES: 2, ZAR: 2, TZS: 2, EGP: 2,
  UGX: 0, RWF: 0, XOF: 0, XAF: 0, JPY: 0, KRW: 0, VND: 0,
  BHD: 3, IQD: 3, JOD: 3, KWD: 3, LYD: 3, OMR: 3, TND: 3,
};

export function money(minor: number, currency?: string): string {
  if (!currency) return minor === 0 ? "—" : String(minor);
  const exp = EXPONENT[currency] ?? 2;
  const negative = minor < 0;
  const digits = String(Math.abs(minor)).padStart(exp + 1, "0");
  const whole = digits.slice(0, digits.length - exp) || "0";
  const frac = exp > 0 ? "." + digits.slice(digits.length - exp) : "";
  const grouped = Number(whole).toLocaleString("en-US");
  return `${negative ? "-" : ""}${grouped}${frac} ${currency}`;
}

/**
 * A timestamp, always UTC, always the same width.
 *
 * Never localised. An operator reading a column of these during an incident
 * is comparing them against a provider's dashboard and a customer's logs, and
 * a browser that helpfully converted to local time would be the one thing in
 * that comparison telling a different story.
 */
export function when(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().replace("T", " ").slice(0, 19) + "Z";
}

export function ago(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const s = (Date.now() - d.getTime()) / 1000;
  if (s < 60) return `${Math.round(s)}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function ms(v?: number): string {
  if (v === undefined || v === null) return "—";
  return v < 1000 ? `${v}ms` : `${(v / 1000).toFixed(1)}s`;
}

/**
 * Escapes a value for insertion into HTML.
 *
 * Everything user-controlled goes through this. Provider names, status
 * values, adapter names and response bodies are all data somebody else chose,
 * and a dashboard that renders them as markup is a stored-XSS bug in an
 * operations console that holds a key able to read every event a tenant has.
 */
export function esc(v: unknown): string {
  return String(v ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/** Truncates for a table cell, marking that it was truncated. */
export function clip(v: unknown, n: number): string {
  const s = String(v ?? "");
  return s.length > n ? s.slice(0, n) + "…" : s;
}
