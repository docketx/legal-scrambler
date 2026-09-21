// The scrambler's vocabulary. See docs/SCRAMBLER.md for the graph this implements.
//
// THE ONE DESIGN RULE everything below follows: the local model never writes text that anyone reads. It
// proposes SPANS — "these characters of the input are a person" — and code does every substitution, both
// directions. That is what makes prompt injection inside a client document survivable: the worst an injected
// instruction can do is propose a bad span, and every span is checked against the input before it is used.

export const ENTITY_TYPES = ["CLIENT", "PERSON", "ATTORNEY", "JUDGE", "ORG", "ADDRESS", "PHONE", "EMAIL", "DOCKET", "DOB", "ACCOUNT", "SSN", "OTHER"] as const;
export type EntityType = (typeof ENTITY_TYPES)[number];

/** A proposal from the model or the regex pass: this exact string in the input is an entity of this type. */
export type Span = { text: string; type: EntityType };

/** A node in the per-matter entity graph. All aliases of one real-world entity share one placeholder — that is
 *  the whole point of the graph over a flat table: "John Doe", "Doe" and "Mr. Doe" are edges into one node. */
export type EntityNode = { id: string; type: EntityType; placeholder: string; aliases: string[]; first_seen: string };

/** Serialised matter graph. Lives on our hardware only; is never sent anywhere; is never returned by an API. */
export type MatterGraphJSON = { matter_id: string; version: 1; counters: Partial<Record<EntityType, number>>; nodes: EntityNode[]; retired?: Record<string, string> };

/** Why a proposed span was refused. Each is a named, countable reason so the ledger can report them. */
export type Rejection = { span: Span; reason: "not-in-input" | "is-citation" | "is-case-party" | "is-public" | "is-placeholder" | "bad-type" | "too-long" | "too-short" | "injection-marker" | "duplicate" | "over-limit" | "not-an-identifier" };

export type ScrambleResult = {
  /** The substitution ledger of `scrambled`: placeholder, exact original, position. Byte-exact restore; sealed at rest. */
  occurrences: { placeholder: string; original: string; start: number; end: number }[];
  /** "raw": `scrambled` + ledger restore the document's own bytes. "normalized": the input carried invisible or
   *  confusable characters that were folded first, and the restore is exact to the folded text. */
  restore_basis: "raw" | "normalized";
  /** How many pass-1 calls the chunk took: more than one means a proposal came back full (80 spans) and pass 1 ran again on the re-scrubbed text. */
  pass1_rounds: number;
  scrambled: string;
  accepted: Span[];
  rejected: Rejection[];
  /** counts by type — what the ledger records. Never the values. */
  stats: Partial<Record<EntityType, number>>;
};
