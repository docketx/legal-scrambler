// The per-matter entity graph: one node per real-world entity, many alias edges into it, one placeholder out.
//
// Why a graph and not a map. The failure every home-built scrambler has is inconsistency: John Doe is CLIENT_1
// in the complaint and CLIENT_5 in the deposition, and the frontier model loses the thread. A flat
// name -> placeholder table cannot fix that, because the name is spelled six ways. A node with alias edges can:
// resolve any alias to the node, and the node owns the placeholder. New aliases attach to existing nodes when the
// model says they co-refer; otherwise they mint a new node with the next counter for that type.
import type { EntityNode, EntityType, MatterGraphJSON, Span } from "./types";

const norm = (s: string) => s.replace(/[‘’‚′]/g, "'").replace(/[“”„″]/g, '"').replace(/\s+/g, " ").trim().toLowerCase();

/** Structured identifiers are substituted by the regex pass before any model runs, so they must never be handed
 *  to a model as a hint either — a red-team finding of 2026-09-15: the SSN was entering the pass-1 prompt through
 *  aliasHints(). */
export const REGEX_TYPES: ReadonlySet<EntityType> = new Set(["SSN", "EMAIL", "PHONE", "DOB", "DOCKET", "ACCOUNT"]);

/** Two types may share a node only if they are the same, or one of them is the generic PERSON. A JUDGE is never
 *  the CLIENT however hard a hijacked model's coref claims it (red-team 7a). */
export const compatible = (a: EntityType, b: EntityType) => a === b || a === "PERSON" || b === "PERSON";

export class MatterGraph {
  readonly matter_id: string;
  private counters: Partial<Record<EntityType, number>>;
  private nodes: EntityNode[];
  /** placeholders of nodes merged away by link(); they may already sit in scrambled text of an earlier document,
   *  so they keep restoring to the surviving node's canonical alias. */
  private retired: Record<string, string>;
  private byAlias = new Map<string, EntityNode>();

  constructor(matter_id: string, from?: MatterGraphJSON) {
    this.matter_id = matter_id;
    this.counters = { ...(from?.counters ?? {}) };
    this.nodes = (from?.nodes ?? []).map((n) => ({ ...n, aliases: [...n.aliases] }));
    this.retired = { ...(from?.retired ?? {}) };
    for (const n of this.nodes) for (const a of n.aliases) this.byAlias.set(norm(a), n);
  }

  /** Resolve an alias to its node, or null. Case- and whitespace-insensitive, quote-normalised. */
  find(alias: string): EntityNode | null { return this.byAlias.get(norm(alias)) ?? null; }

  /** Attach a span to the graph. `sameAs` lets the caller say this alias belongs to an existing node; the claim is
   *  honoured only if the types are compatible. An existing node with this exact alias is always reused. Never
   *  re-types an existing node. Returns the node. */
  add(span: Span, sameAs?: string, now = new Date().toISOString().slice(0, 10)): EntityNode {
    const key = norm(span.text);
    const existing = this.byAlias.get(key);
    if (existing) return existing;
    const target = sameAs ? this.find(sameAs) : null;
    if (target && compatible(target.type, span.type)) { target.aliases.push(span.text); this.byAlias.set(key, target); return target; }
    const n = (this.counters[span.type] ?? 0) + 1; this.counters[span.type] = n;
    const node: EntityNode = { id: `${span.type}_${n}`, type: span.type, placeholder: `[${span.type}_${n}]`, aliases: [span.text], first_seen: now };
    this.nodes.push(node); this.byAlias.set(key, node);
    return node;
  }

  /** Declare two aliases co-referent. Both must already be in the graph; if they sit on different compatible
   *  nodes the later node is merged into the earlier one and its placeholder is retired (still restorable).
   *  Cycles and self-references are no-ops by construction: linking a node to itself changes nothing, and once
   *  merged there is one node. Returns whether anything changed. */
  link(a: string, b: string): boolean {
    const na = this.find(a), nb = this.find(b);
    if (!na || !nb || na === nb) return false;
    if (!compatible(na.type, nb.type)) return false;
    const [keep, drop] = this.nodes.indexOf(na) <= this.nodes.indexOf(nb) ? [na, nb] : [nb, na];
    // a specific type wins over the generic PERSON so the surviving placeholder keeps the more informative label
    if (keep.type === "PERSON" && drop.type !== "PERSON") { const t = keep.type; keep.type = drop.type; drop.type = t; }
    for (const al of drop.aliases) { keep.aliases.push(al); this.byAlias.set(norm(al), keep); }
    this.retired[drop.placeholder] = keep.id;
    this.nodes.splice(this.nodes.indexOf(drop), 1);
    return true;
  }

  /** Move an alias off its node onto a new node of its own (same type). A bare surname that joined the only
   *  person of that surname is no longer anyone's when a second person of the surname arrives ("SPEER" had
   *  joined "John H. Speer"; then "Donnie Lou Speer" -- real docket 2026-09-16): from here it is its own node,
   *  restoring verbatim, and the final pass re-substitutes every document with the complete graph. A node's
   *  last alias is never detached. Returns the new node, or null when nothing moved. */
  detach(alias: string, now = new Date().toISOString().slice(0, 10)): EntityNode | null {
    const node = this.find(alias); if (!node || node.aliases.length < 2) return null;
    const i = node.aliases.findIndex((a) => norm(a) === norm(alias)); if (i < 0) return null;
    const [text] = node.aliases.splice(i, 1); this.byAlias.delete(norm(text));
    const n = (this.counters[node.type] ?? 0) + 1; this.counters[node.type] = n;
    const fresh: EntityNode = { id: `${node.type}_${n}`, type: node.type, placeholder: `[${node.type}_${n}]`, aliases: [text], first_seen: now };
    this.nodes.push(fresh); this.byAlias.set(norm(text), fresh);
    return fresh;
  }

  /** Every (alias, placeholder) pair, longest alias first. */
  substitutions(): { alias: string; placeholder: string; type: EntityType }[] {
    const out: { alias: string; placeholder: string; type: EntityType }[] = [];
    for (const n of this.nodes) for (const a of n.aliases) out.push({ alias: a, placeholder: n.placeholder, type: n.type });
    return out.sort((x, y) => y.alias.length - x.alias.length);
  }

  /** placeholder -> the alias to restore. The FIRST alias a node was seen under is the canonical restore form,
   *  and retired placeholders restore to their surviving node's canonical alias. */
  restorations(): Map<string, string> {
    const m = new Map(this.nodes.map((n) => [n.placeholder, n.aliases[0]]));
    for (const [ph, id] of Object.entries(this.retired)) { const n = this.nodes.find((x) => x.id === id); if (n) m.set(ph, n.aliases[0]); }
    return m;
  }

  get size(): number { return this.nodes.length; }
  toJSON(): MatterGraphJSON { return { matter_id: this.matter_id, version: 1, counters: { ...this.counters }, nodes: this.nodes.map((n) => ({ ...n, aliases: [...n.aliases] })), retired: { ...this.retired } }; }
  /** What the model may be told about the matter so far: aliases and placeholders of NAMED entities only, so it
   *  reuses them. Regex-class identifiers are excluded — they were substituted before the model saw anything and
   *  must not re-enter a prompt as a hint. This is the ONLY form of the graph that ever enters a prompt, and it
   *  is still local-model-only. */
  aliasHints(): { alias: string; placeholder: string }[] {
    const out: { alias: string; placeholder: string }[] = [];
    for (const n of this.nodes) if (!REGEX_TYPES.has(n.type)) for (const a of n.aliases) out.push({ alias: a, placeholder: n.placeholder });
    return out.sort((x, y) => y.alias.length - x.alias.length);
  }
}
