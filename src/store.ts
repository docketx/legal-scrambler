// Encrypted, private storage for the scrambler: the per-matter entity graph and a content-addressed cache.
//
// Founder 2026-09-15: "encrypted and private and scrambled." Concretely:
//   PRIVATE   — a matter belongs to the caller that created it. The encryption key for a matter is derived from
//               the caller id AND the matter id (HKDF), so one API key cannot decrypt another's graph even with
//               the file in hand. The mapping is never returned by any route; only this module reads it.
//   ENCRYPTED — AES-256-GCM under a master key from the environment (SCRAMBLER_MASTER_KEY, 32 bytes), the same
//               envelope discipline as DocketRouter's key store: no plaintext fallback, loud failure at call time, the
//               owner+matter bound in as AAD so an envelope moved between matters will not decrypt.
//   SCRAMBLED — the cache stores only the SCRAMBLED text and counts, keyed by sha256(owner, matter, document).
//               Re-submitting a document costs nothing and never re-runs the model. The cache never holds the
//               mapping; the graph file does, and the two are separate envelopes.
// Files live under data/store/ (SCRAMBLER_DATA_DIR overrides, for tests). Names are hashes, never ids.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { MatterGraph } from "./graph";
import type { MatterGraphJSON, ScrambleResult } from "./types";

export class ScramblerConfigError extends Error { constructor(m: string) { super(m); this.name = "ScramblerConfigError"; } }

const KEY_BYTES = 32, IV_BYTES = 12, TAG_BYTES = 16, VERSION = "s1";
const HOWTO = "Generate one with: npx tsx -e 'console.log(require(\"node:crypto\").randomBytes(32).toString(\"base64\"))'";

function masterKey(): Buffer {
  const raw = process.env.SCRAMBLER_MASTER_KEY;
  if (!raw) throw new ScramblerConfigError(`SCRAMBLER_MASTER_KEY is not set; refusing to store or read a matter graph. ${HOWTO}`);
  const key = /^[0-9a-f]{64}$/i.test(raw) ? Buffer.from(raw, "hex") : Buffer.from(raw, "base64");
  if (key.length !== KEY_BYTES) throw new ScramblerConfigError(`SCRAMBLER_MASTER_KEY must decode to exactly ${KEY_BYTES} bytes; got ${key.length}. ${HOWTO}`);
  return key;
}

const dir = () => process.env.SCRAMBLER_DATA_DIR || path.join(process.cwd(), "data", "store");
const sha = (s: string) => crypto.createHash("sha256").update(s, "utf8").digest("hex");
const derive = (owner: string, matter: string) =>
  Buffer.from(crypto.hkdfSync("sha256", masterKey(), Buffer.from(owner, "utf8"), Buffer.from(`docketrouter:scrambler:${VERSION}:${matter}`, "utf8"), KEY_BYTES));
const aad = (owner: string, matter: string, kind: string) => Buffer.from(`${VERSION}|${owner}|${matter}|${kind}`, "utf8");

export function seal(owner: string, matter: string, kind: string, plaintext: string): string {
  const iv = crypto.randomBytes(IV_BYTES);
  const c = crypto.createCipheriv("aes-256-gcm", derive(owner, matter), iv, { authTagLength: TAG_BYTES });
  c.setAAD(aad(owner, matter, kind));
  const ct = Buffer.concat([c.update(Buffer.from(plaintext, "utf8")), c.final()]);
  return [VERSION, iv.toString("base64"), c.getAuthTag().toString("base64"), ct.toString("base64")].join(":");
}

export function open(owner: string, matter: string, kind: string, envelope: string): string {
  const [v, iv, tag, ct] = envelope.split(":");
  if (v !== VERSION || !iv || !tag || !ct) throw new ScramblerConfigError("not a scrambler envelope");
  const d = crypto.createDecipheriv("aes-256-gcm", derive(owner, matter), Buffer.from(iv, "base64"), { authTagLength: TAG_BYTES });
  d.setAAD(aad(owner, matter, kind));
  d.setAuthTag(Buffer.from(tag, "base64"));
  return Buffer.concat([d.update(Buffer.from(ct, "base64")), d.final()]).toString("utf8");
}

const graphPath = (owner: string, matter: string) => path.join(dir(), "graphs", sha(`${owner}\n${matter}`) + ".enc");
const cachePath = (owner: string, matter: string, doc: string) => path.join(dir(), "cache", sha(`${owner}\n${matter}\n${doc}`) + ".enc");
// the ledger is keyed by the SCRAMBLED text, because that is what the caller holds when they want the document back
const ledgerPath = (owner: string, matter: string, scrambled: string) => path.join(dir(), "ledgers", sha(`${owner}\n${matter}\n${scrambled}`) + ".enc");

/** The matter's graph, decrypted for this owner, or a fresh one. A file that exists but will not decrypt for
 *  this owner is treated as ABSENT and reported — never as an error message that confirms the matter exists. */
export function loadGraph(owner: string, matter: string): { graph: MatterGraph; existed: boolean } {
  const p = graphPath(owner, matter);
  if (!fs.existsSync(p)) return { graph: new MatterGraph(matter), existed: false };
  try { return { graph: new MatterGraph(matter, JSON.parse(open(owner, matter, "graph", fs.readFileSync(p, "utf8"))) as MatterGraphJSON), existed: true }; }
  catch (e) { if (e instanceof ScramblerConfigError) throw e; return { graph: new MatterGraph(matter), existed: false }; }
}

export function saveGraph(owner: string, matter: string, graph: MatterGraph): void {
  const p = graphPath(owner, matter); fs.mkdirSync(path.dirname(p), { recursive: true });
  const tmp = p + "." + crypto.randomBytes(4).toString("hex") + ".tmp";
  fs.writeFileSync(tmp, seal(owner, matter, "graph", JSON.stringify(graph.toJSON())), { mode: 0o600 });
  fs.renameSync(tmp, p);
}

export type CachedScramble = { scrambled: string; stats: ScrambleResult["stats"]; rejected: Record<string, number>; degraded: string[]; at: string; restore_basis?: "raw" | "normalized" };
export type Ledger = { occurrences: ScrambleResult["occurrences"]; restore_basis: "raw" | "normalized"; at: string };

/** The substitution ledger of one scrambled document, sealed like the graph: the exact original bytes behind
 *  every placeholder, never in a prompt, never in a response body -- only ever applied by restoreDocument(). */
export function ledgerGet(owner: string, matter: string, scrambled: string): Ledger | null {
  const p = ledgerPath(owner, matter, scrambled);
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(open(owner, matter, "ledger", fs.readFileSync(p, "utf8"))) as Ledger; }
  catch (e) { if (e instanceof ScramblerConfigError) throw e; return null; }
}
export function ledgerPut(owner: string, matter: string, scrambled: string, value: Ledger): void {
  const p = ledgerPath(owner, matter, scrambled); fs.mkdirSync(path.dirname(p), { recursive: true });
  const tmp = p + "." + crypto.randomBytes(4).toString("hex") + ".tmp";
  fs.writeFileSync(tmp, seal(owner, matter, "ledger", JSON.stringify(value)), { mode: 0o600 });
  fs.renameSync(tmp, p);
}

export function cacheGet(owner: string, matter: string, doc: string): CachedScramble | null {
  const p = cachePath(owner, matter, doc);
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(open(owner, matter, "cache", fs.readFileSync(p, "utf8"))) as CachedScramble; }
  catch (e) { if (e instanceof ScramblerConfigError) throw e; return null; }
}

export function cachePut(owner: string, matter: string, doc: string, value: CachedScramble): void {
  const p = cachePath(owner, matter, doc); fs.mkdirSync(path.dirname(p), { recursive: true });
  const tmp = p + "." + crypto.randomBytes(4).toString("hex") + ".tmp";
  fs.writeFileSync(tmp, seal(owner, matter, "cache", JSON.stringify(value)), { mode: 0o600 });
  fs.renameSync(tmp, p);
}

/** Delete everything held for a matter: the graph and every cached document. Idempotent. Returns what was removed —
 *  counts, never contents. */
export function forgetMatter(owner: string, matter: string): { graph: boolean; cached: number; ledgers: number } {
  const g = graphPath(owner, matter); const hadGraph = fs.existsSync(g); if (hadGraph) fs.unlinkSync(g);
  // cache and ledger files are keyed by document too, so the matter's entries cannot be enumerated from the name
  // alone; they are found by trying to open each one for this owner+matter, which fails fast for every other matter
  const sweep = (sub: string, kind: string) => {
    let n = 0; const d = path.join(dir(), sub);
    if (fs.existsSync(d)) for (const f of fs.readdirSync(d)) {
      if (!f.endsWith(".enc")) continue; const p = path.join(d, f);
      try { open(owner, matter, kind, fs.readFileSync(p, "utf8")); fs.unlinkSync(p); n++; } catch (e) { if (e instanceof ScramblerConfigError) throw e; }
    }
    return n;
  };
  return { graph: hadGraph, cached: sweep("cache", "cache"), ledgers: sweep("ledgers", "ledger") };
}
