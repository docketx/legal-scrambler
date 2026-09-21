# Scrambler graph-engineering review — 2026-09-15

Founder-authorized upstream calls (2026-09-15). 4 models, 3 returned. **Total cost: $0.0195**. No client document, battery text or secret left the box: the brief is docs/SCRAMBLER.md plus three problem statements (scripts/scrambler-arch-review.ts). Raw responses below, unedited; the synthesis and what was adopted go in docs/SCRAMBLER.md.

## deepseek/deepseek-v4-flash  (in 8307, out 3500, $0.0012)

# Problem 1 — Whole Case Files

## Graph Design

**Data structure:**
```
MatterGraph {
  nodes: Map<EntityId, EntityNode>
  aliases: Map<NormalizedForm, EntityId>  // case-insensitive, whitespace-normalized
  placeholders: Map<EntityId, Placeholder>
  retiredPlaceholders: Map<OldPlaceholder, EntityId>  // for merge cycles
  counter: { client: number, person: number, org: number, ... }
  version: number
  created: timestamp
}
EntityNode {
  id: EntityId
  type: EntityType
  canonicalAlias: string  // first seen, for restore
  allAliases: Set<string>  // surface forms
  firstSeenChunk: number
  isCaseParty: boolean
  isJudge: boolean
}
```

**Processing order:**
1. **Regex pass** (deterministic, per chunk) — SSN, email, phone, DOB, docket, account
2. **Model pass 1** — propose spans on regex-scrubbed text
3. **Guard** — validate each span against input
4. **Graph update** — add new nodes/aliases, merge if coref resolved
5. **Substitution** — longest alias first, interval-based
6. **Model pass 2** — audit scrambled text
7. **Release gate** — verify no residual aliases

**Cross-document consistency:**
- Graph persisted per matter as encrypted envelope
- On reload, all existing nodes/placeholders preserved
- New entities get next available placeholder number
- Late-learned entities: after substitution, re-scan earlier chunks with new aliases

**Surname disambiguation:**
```
deriveSurname(fullName: string): string | null
// Only for PERSON type, only if contains space
// Must be whole-word match, not substring
// Skip if matches legal jargon list
// Skip if within 120 chars of " v. " + reporter citation
```

**Coreference resolution (rule-based, deterministic):**
1. Defined terms: `("Bob" or "Mr. Evans")` → both aliases same node
2. Initials: `K.J.T.` → match against known names with same initials
3. Title+name: `Dr. Thorne` → match against `Thorne` if exists
4. Role: `the Decedent`, `Respondent` → only if single entity of that role exists
5. Surname-only: `Thorne` → attach to existing node if unique match

## Invariants

| Invariant | Test |
|-----------|------|
| Every placeholder maps to exactly one entity | Unit test: create graph, verify bijection |
| No two entities share a placeholder | Integration: add two persons with same surname, verify different placeholders |
| Same entity across chunks gets same placeholder | E2E: split document, process chunks, verify placeholder consistency |
| Retired placeholders still restore correctly | Unit: merge two nodes, verify old placeholder restores |
| Graph size bounded by unique entities | Stress: 10k entities, verify memory < 50MB |
| Cross-document consistency | Integration: process doc1, persist, load, process doc2, verify shared entities |

## Failure Modes

1. **Graph corruption on crash** — MUST: write-ahead log for graph mutations
2. **Placeholder collision** — MUST: counter never resets, even on reload
3. **Memory exhaustion** — MUST: cap at 10k nodes per matter, refuse new entities
4. **Merge cycle** — MUST: detect cycles, no-op on merge, retire old placeholder
5. **Late entity discovered after substitution** — MUST: re-scan earlier chunks with new alias

## Recommendations

1. **MUST** — Use interval-based substitution (not sequential replacement) to prevent alias-in-placeholder corruption. *Reason: prevents "T_1]" inside "[CLIENT_1]" bug found in red-team.*

2. **MUST** — Persist graph per matter as encrypted envelope with version number. *Reason: enables cross-document consistency and backward compatibility.*

3. **MUST** — Implement write-ahead log for all graph mutations. *Reason: crash recovery without losing entity-to-placeholder mapping.*

4. **MUST** — Cap graph at 10k nodes per matter with explicit refusal beyond. *Reason: memory bound guarantee.*

5. **SHOULD** — Derive surnames only for PERSON type, skip legal jargon list. *Reason: prevents "Young v. State" surname derivation.*

6. **SHOULD** — Re-scan earlier chunks when late entity discovered. *Reason: same entity gets same placeholder across all chunks.*

7. **SHOULD** — Use case-insensitive, whitespace-normalized alias matching. *Reason: "John\nDoe" variant found in red-team.*

8. **COULD** — Implement role-based coreference only when single candidate exists. *Reason: reduces false merges, but low priority.*

# Problem 2 — Seamless Swap-Back

## Placeholder Grammar

```
Placeholder ::= '[' Type '_' Number ']'
Type ::= 'CLIENT' | 'PERSON' | 'ORG' | 'JUDGE' | 'ATTORNEY' | 'SSN' | 'PHONE' | 'EMAIL' | 'DOB' | 'DOCKET' | 'ACCOUNT' | 'ADDRESS'
Number ::= [1-9][0-9]*
```

**Grammar rules:**
- No nested brackets: `[[CLIENT_1]]` → inner `[CLIENT_1]` restored, outer brackets preserved
- No partial matches: `[CLIENT_1_2]` → reported as unknown, never guessed
- Case-sensitive: `[client_1]` → reported as unknown
- No special characters: `[CLIENT_1's]` → possessive handled by rendering, not grammar

## Per-Occurrence Surface-Form Ledger

```
LedgerEntry {
  placeholder: string
  originalForm: string      // exact surface form from document
  position: { chunk: number, start: number, end: number }
  context: {
    precedingChar: string   // for capitalization detection
    followingChar: string
    isSentenceStart: boolean
    hasHonorific: boolean
    honorificType: 'Mr.' | 'Ms.' | 'Dr.' | 'Judge' | null
  }
}
```

**Ledger invariants:**
- Every substitution creates exactly one ledger entry
- Ledger entries are immutable after creation
- Ledger is serialized with graph, never leaves host

## Rendering Rules for Answers

**Priority order (deterministic):**

1. **Exact match** — if placeholder appears verbatim in ledger, use `originalForm`
2. **Possessive** — `[CLIENT_1]'s` → `originalForm + "'s"` (or `originalForm + "'"` if ends in 's')
3. **Sentence start** — if placeholder is first token after period/question mark/exclamation, capitalize first letter of `originalForm`
4. **Honorific context** — if `[CLIENT_1]` preceded by "Mr.", "Ms.", "Dr.", "Judge", use `canonicalAlias` (not `originalForm`) to prevent "Mr. Robert T. Evans"
5. **Plural** — `[ORG_2]s` → `originalForm + "s"` (or `originalForm + "es"` for certain endings)
6. **Unknown placeholder** — report as `[UNKNOWN_PLACEHOLDER_X]`, never guess
7. **Mangled placeholder** — `[CLIENT_1_2]` → report as unknown, never attempt restoration

**Restore algorithm:**
```
function restoreAnswer(answer: string, graph: MatterGraph, ledger: Ledger): string {
  // Phase 1: Find all placeholder-like tokens
  const tokens = findPlaceholderTokens(answer)
  
  // Phase 2: Sort by position (longest first for nested cases)
  tokens.sort((a, b) => b.length - a.length)
  
  // Phase 3: Restore each token
  for (const token of tokens) {
    if (isValidPlaceholder(token)) {
      const entry = ledger.find(token)
      if (entry) {
        answer = answer.replace(token, renderWithContext(entry, token, answer))
      } else {
        // Unknown placeholder — report
        answer = answer.replace(token, `[UNKNOWN_${token}]`)
      }
    } else {
      // Near-miss — report
      answer = answer.replace(token, `[UNKNOWN_${token}]`)
    }
  }
  
  return answer
}
```

## Tests

**Byte-exact restore (document):**
```
test('document restores byte-exact', () => {
  const original = "Bob said Mr. Evans is EVANS's lawyer"
  const scrambled = scramble(original, graph)
  const restored = restore(scrambled, graph, ledger)
  expect(restored).toBe(original)  // exact byte match
})
```

**Natural answer restore:**
```
test('possessive restores naturally', () => {
  const answer = "[CLIENT_1]'s motion"
  const restored = restore(answer, graph, ledger)
  expect(restored).toBe("Evans's motion")  // not "Robert Evans's motion"
})

test('honorific uses canonical', () => {
  const answer = "Mr. [CLIENT_1]"
  const restored = restore(answer, graph, ledger)
  expect(restored).toBe("Mr. Robert T. Evans")  // not "Mr. Bob"
})

test('sentence start capitalizes', () => {
  const answer = "[CLIENT_1] filed a motion."
  const restored = restore(answer, graph, ledger)
  expect(restored).toBe("Evans filed a motion.")  // capitalized
})

test('unknown placeholder reported', () => {
  const answer = "[CLIENT_1_2] is unknown"
  const restored = restore(answer, graph, ledger)
  expect(restored).toBe("[UNKNOWN_CLIENT_1_2] is unknown")
})
```

## What Cannot Be Seamless

1. **Model-invented entities** — if frontier model creates `[CLIENT_99]` that never existed, cannot restore
2. **Ambiguous possessives** — `[CLIENT_1]s` could be plural or possessive; heuristic only
3. **Model-mangled placeholders** — `[CLIEN_1]` or `[CLIENT1]` — cannot reliably map
4. **Cross-sentence coreference in answer** — model might refer to `[CLIENT_1]` then `he` — pronoun resolution beyond scope

## Recommendations

1. **MUST** — Store per-occurrence surface form in ledger, not just canonical alias. *Reason: enables byte-exact document restore.*

2. **MUST** — Implement honorific detection: if placeholder preceded by title, use canonical alias. *Reason: prevents "Mr. Bob" from "Mr. [CLIENT_1]".*

3. **MUST** — Report unknown/near-miss placeholders, never guess. *Reason: guessing could leak information or create false content.*

4. **MUST** — Use longest-match-first for nested placeholders like `[[CLIENT_1]]`. *Reason: inner placeholder restored first, brackets preserved.*

5. **SHOULD** — Implement sentence-start capitalization detection. *Reason: natural reading of restored answers.*

6. **SHOULD** — Handle possessive forms deterministically: `'s` suffix for non-s-ending, `'` suffix for s-ending. *Reason: covers common legal writing patterns.*

7. **COULD** — Implement plural detection for ORG types. *Reason: "the [ORG_2]s" → "the companies", but low frequency.*

# Problem 3 — Stress Test on Real Dockets

## Stress Harness Design

```
StressHarness {
  docket: DocketMetadata
  documents: Document[]
  groundTruth: GroundTruth  // from RECAP party/attorney/judge list
  
  measurements: {
    leakPer1000: Map<EntityType, { leaked: number, present: number, rate: number, ci: [number, number] }>
    crossDocConsistency: { sameEntityDifferentPlaceholder: number, differentEntitySamePlaceholder: number }
    overScrub: { falsePositives: number, candidates: string[] }
    citationPreservation: { original: number, preserved: number, destroyed: string[] }
    refusalRate: { refused: number, total: number, reasons: Map<string, number> }
    restoreExactness: { byteExact: boolean, mismatches: { position: number, expected: string, got: string }[] }
    throughput: { modelTime: number, totalTime: number, chunks: number, passes: number }
  }
  
  failures: Failure[]
}
```

## Measurements Per Docket

| Metric | Definition | Failure Threshold |
|--------|------------|-------------------|
| Leak per 1,000 by type | (leaked / present) * 1000, Wilson 95% CI | > 50 for any type |
| Cross-document consistency | Same entity gets different placeholder across docs | Any occurrence |
| Over-scrub | Capitalized phrases removed that aren't ground-truth names | > 10% of candidates |
| Citation preservation | Citations destroyed during scrambling | Any occurrence |
| Refusal rate | Documents refused by release gate | > 5% |
| Restore exactness | Byte-exact match of restored document | Any mismatch |
| Throughput | Model time per chunk | > 60s per chunk |

## Failure Classification

```
FailureType ::= 
  | 'LEAK'           // ground-truth entity survived in output
  | 'INCONSISTENCY'  // same entity, different placeholder
  | 'OVER_SCRUB'     // non-secret removed
  | 'CITATION_LOSS'  // citation destroyed
  | 'REFUSAL'        // document refused by gate
  | 'RESTORE_FAIL'   // restore not byte-exact
  | 'TIMEOUT'        // model timeout
  | 'TRANSPORT'      // network failure (excluded from rate)
```

## Finding Model Misses at Scale

**Algorithm:**
```
for each docket in RECAP:
  groundTruth = extractParties(docket)  // from docket's own list
  for each document in docket:
    scrambled = scramble(document)
    missed = groundTruth.filter(name => 
      name appears in scrambled.text && 
      !isInCitedCaption(name, scrambled) &&
      !isLegalJargon(name)
    )
    if missed.length > 0:
      reportMiss(missed, document, chunk)
      // Analyze shape of each miss
      for each miss:
        shape = classifyShape(miss)  // 'defined_term', 'initials', 'surname_only', etc.
        addToShapeCount(shape)
```

**Shape classification:**
- `defined_term`: `("Bob" or "Mr. Evans")` pattern
- `initials`: `K.J.T.` pattern
- `surname_only`: `Thorne` after full name introduced
- `numeric_twin`: `December 12, 1970 (12/12/1970)`
- `announced_docket`: `the cause number will be CV-2025-0789`
- `bar_number_context`: `counsel beside bar number`
- `honorific`: `Judge Garcia`
- `corporate_form`: `ORG wearing Inc./LLC`

## Keeping Measurement Honest

1. **No fabricated ground truth** — only RECAP's own party/attorney/judge lists
2. **Transport failures excluded** — if model unreachable, document excluded from rate
3. **Intervals reported** — Wilson 95% CI for all rates
4. **Refusals reported separately** — not counted as leaks
5. **Cited caption entities reported under own heading** — not counted as pipeline leaks
6. **Over-sc

## google/gemini-2.5-pro  (in 0, out 0, $0.0000)

FAILED: Failed after 3 attempts. Last error: AI_APICallError: Reasoning is mandatory for this endpoint and cannot be disabled.

## qwen/qwen3-235b-a22b  (in 8670, out 885, $0.0056)

# Recommendations for Scrambler Architecture Improvements

## Problem 1: Whole Case Files Processing

**MUST 1.1:** Use a persistent, append-only entity graph with globally unique identifiers  
*Reason:* Ensures consistent placeholder assignment across documents and sessions while allowing late additions.

**MUST 1.2:** Implement strict type checking for entity merging  
*Reason:* Prevents surname-based merging of different entities by enforcing type compatibility during coreference resolution.

**SHOULD 1.3:** Add coreference resolution rules for legal document patterns  
*Reason:* Handles common legal references like "the Decedent", "Respondent", and name variations through deterministic pattern matching.

**MUST 1.4:** Use interval trees for efficient span management across documents  
*Reason:* Enables efficient overlap resolution and maintains memory bounds when processing large document sets.

**MUST 1.5:** Implement versioned graph snapshots  
*Reason:* Allows adding new documents without renumbering while maintaining consistency with previous versions.

**Invariant Testing:**
- Entity consistency: Test that same entity gets same placeholder across all documents
- Type separation: Test that different people with same surname never merge
- Coreference resolution: Test that legal reference patterns resolve correctly
- Memory bounds: Measure memory usage against document count and size

## Problem 2: Seamless Swap-Back

**MUST 2.1:** Use context-sensitive placeholder grammar with metadata  
*Reason:* Enables exact restoration of surface forms and proper handling of possessives, capitalization, etc.

**MUST 2.2:** Maintain per-occurrence surface-form ledger with context metadata  
*Reason:* Ensures exact document restoration and provides necessary context for natural answer rendering.

**SHOULD 2.3:** Implement context-aware rendering rules for frontier answers  
*Reason:* Handles possessives, capitalization at sentence start, honorific context, and other linguistic nuances.

**COULD 2.4:** Add fuzzy matching for malformed placeholders in answers  
*Reason:* Improves robustness against frontier model placeholder variations while maintaining security.

**MUST 2.5:** Implement strict validation of unknown placeholders  
*Reason:* Prevents guessing or fabricating values for unknown placeholders while maintaining security.

**Testing Requirements:**
- Document exactness: Byte-level comparison of original and restored documents
- Answer naturalness: Linguistic checks for possessives, capitalization, honorifics
- Edge cases: Test sentence-start possessives, embedded honorifics, complex plural forms
- Unknown placeholder handling: Validate rejection of unrecognizable placeholders

**Limitations:**
- Cannot perfectly restore context-dependent forms when context is ambiguous
- Cannot handle completely novel placeholder variations from frontier models
- Cannot maintain exact formatting in complex document structures

## Problem 3: Stress Test on Real Dockets

**MUST 3.1:** Implement comprehensive measurement framework  
*Reason:* Measures leak rate by type, cross-document consistency, over-scrubbing, citation preservation, etc.

**MUST 3.2:** Define clear failure criteria for each metric  
*Reason:* Establishes unambiguous thresholds for acceptable system behavior.

**SHOULD 3.3:** Implement pattern discovery mechanism for model misses  
*Reason:* Identifies systematic model failures at scale to inform rule-based improvements.

**MUST 3.4:** Use honest measurement methodology  
*Reason:* Excludes transport failures, avoids fabricated ground truth, and reports confidence intervals.

**SHOULD 3.5:** Add interval reporting with confidence bounds  
*Reason:* Provides statistically valid representation of system performance.

**Failure Detection:**
- Leak detection: Ground truth comparison against RECAP filings
- Cross-document inconsistency: Entity mapping comparison across documents
- Over-scrubbing: Comparison against docket party/attorney/judge lists
- Citation destruction: Citation structure validation
- Refusal analysis: Detailed logging of gate rejections
- Restore exactness: Byte-level comparison of original and restored documents

**Pattern Discovery Process:**
1. Cluster common leak patterns from real dockets
2. Prioritize patterns by frequency and impact
3. Develop deterministic rules to address each pattern
4. Add tests to validate rule effectiveness
5. Integrate rules into processing pipeline

This approach ensures systematic improvement of the system while maintaining the security and accuracy requirements specified in the design document.

## moonshotai/kimi-k2  (in 8205, out 3500, $0.0127)

I'll review this architecture as a graph-engineering problem and address the three concrete design challenges.

---

## PROBLEM 1 — WHOLE CASE FILES

### 1.1 MUST — Graph structure: node identity by stable key, not by alias content
**Reason:** Prevents surname collision merges and enables late-joining entities without renumbering.

**Data structure:**
```typescript
// Node key: deterministic hash of (canonical alias, type, disambiguation context)
type NodeKey = string; // base64url(sha256(type + "\0" + canonical + "\0" + disambiguator))

interface EntityNode {
  key: NodeKey;           // stable across all chunks and sessions
  type: 'PERSON' | 'ORG' | 'JUDGE' | ...;
  placeholder: string;    // [CLIENT_1], assigned monotonically per type at first node creation
  aliases: Set<string>;   // all surface forms seen, normalized for matching
  canonicalAlias: string; // first alias seen, used for restore when no surface form specified
  createdAtChunk: number; // for debugging cross-chunk learning
  mergedFrom?: NodeKey[]; // audit trail for coref merges
}

interface AliasEdge {
  nodeKey: NodeKey;
  normalizedForm: string; // lowercase, whitespace-collapsed, quotes normalized
  originalForms: string[]; // preserve exact casing for restore ledger
  source: 'regex' | 'model_span' | 'model_coref' | 'derived_surname' | 'defined_term';
  confidence: 'deterministic' | 'model_proposed';
}
```

**Invariant:** `placeholder` is assigned once at node creation and never changes. Nodes are never deleted, only merged (with one survivor keeping its placeholder).

**Test:** `tests/scrambler-graph.test.ts` — create node with alias "John Doe", add chunk with "Doe", add chunk months later with "J. Doe", verify all three aliases map to `[CLIENT_1]`, verify placeholder unchanged after merge.

---

### 1.2 MUST — Disambiguation: surname + type + context hash, not surname alone
**Reason:** Two different people sharing "Smith" must never merge.

**Algorithm:**
```typescript
function disambiguationContext(alias: string, surroundingText: string, documentId: string): string {
  // Extract: (a) other names in same sentence, (b) role indicators, (c) document type
  const cooccurring = extractOtherCapitalizedNames(surroundingText, 200);
  const role = detectRoleIndicator(surroundingText, alias); // "plaintiff", "defendant", "witness", "counsel for"
  const docType = documentTypeFromId(documentId); // petition, answer, motion...
  return hashSorted([...cooccurring, role, docType]);
}
```

**Invariant:** Two nodes may merge only if `type` matches AND `disambiguationContext` overlaps significantly (Jaccard > 0.5 on cooccurring names) OR one alias is a strict substring of the other with compatible role.

**Test:** Battery case with "Smith" as plaintiff and "Smith" as defendant's witness — verify `[CLIENT_1]` and `[CLIENT_2]` created, never merged.

---

### 1.3 MUST — Processing order: two-phase chunking with lookbehind buffer
**Reason:** Entities learned in chunk N must apply to chunks 1..N-1 without reprocessing.

**Algorithm:**
```
Phase 1 (discovery): Process chunks 1..N in order. For each chunk:
  - Run regex pass (deterministic, no graph needed)
  - Run model pass, propose spans
  - Guard validates, adds to graph
  - DO NOT substitute yet; emit (chunkId, proposedSpans)

Phase 2 (substitution): After all chunks processed:
  - Build interval tree of all alias occurrences across all chunks
  - For each chunk in order:
    - Apply longest-match substitution using complete graph
    - Emit scrambled chunk with final placeholders

Phase 3 (retroactive): If new nodes added in chunk N:
  - Re-substitute chunks 1..N-1 using updated graph
  - Cache invalidation: content-addressed by graph state hash
```

**Invariant:** At release gate time, every chunk has been substituted with the same graph version.

**Test:** `tests/scrambler-cross-chunk.test.ts` — entity appears first in chunk 3, verify chunks 1-2 re-substituted, all four occurrences of same person use `[CLIENT_1]`.

---

### 1.4 MUST — Coref resolution: typed, acyclic, deferred to Phase 2
**Reason:** "The Decedent" → "Dr. Thorne" → "Thorne" → "K.J.T." must resolve transitively without cycles.

**Data structure:**
```typescript
interface CorefEdge {
  fromNode: NodeKey;
  toNode: NodeKey;        // points to more canonical form
  source: 'model_proposed' | 'defined_term_rule' | 'caption_pattern';
  evidence: string;        // text that triggered coref
}

// Coref graph must be DAG; cycles broken by: (a) deterministic tie-breaker (longer alias), 
// (b) type compatibility enforced, (c) model confidence threshold
```

**Algorithm:**
```typescript
function resolveCoref(nodes: EntityNode[]): Map<NodeKey, NodeKey> {
  // Build adjacency, detect cycles via DFS
  // For each cycle: break at lowest-confidence edge
  // Return: map each node to its root (most canonical)
  
  // Rules applied before model coref:
  // - Defined term patterns: `(hereinafter "the Company")` → edge to full name
  // - Caption patterns: `Robert T. Evans, individually and d/b/a Evans Construction` → edges to each form
  // - Signature blocks: `/s/ [name]` → edge to typed name above
}
```

**Invariant:** After `resolveCoref`, every alias maps to exactly one placeholder; the coref graph is a forest.

**Test:** Battery case with 4-way coref chain, verify all resolve to `[CLIENT_1]`; inject cycle via hijacked model, verify broken deterministically.

---

### 1.5 MUST — Persistence: graph as append-only log with snapshot
**Reason:** Document added months later joins without renumbering; bounded memory.

**Data structure:**
```typescript
interface MatterLog {
  matterId: string;
  logEntries: LogEntry[]; // append-only, never rewrite
  snapshots: Map<number, GraphSnapshot>; // periodic, keyed by entry index
}

type LogEntry = 
  | { op: 'ADD_NODE', node: EntityNode, chunkId: string, timestamp: Date }
  | { op: 'ADD_ALIAS', nodeKey: NodeKey, alias: AliasEdge }
  | { op: 'MERGE_NODES', survivor: NodeKey, merged: NodeKey[], reason: string }
  | { op: 'ADD_DOCUMENT', docId: string, chunkIds: string[] };

interface GraphSnapshot {
  entryIndex: number;
  nodeIndex: Map<NodeKey, EntityNode>; // denormalized for fast load
  aliasIndex: Map<string, NodeKey[]>; // normalized form → nodes
  placeholderCounters: Map<string, number>; // per-type counter
}
```

**Algorithm for late document:**
```typescript
function loadGraph(matterId: string): EntityGraph {
  const log = readLog(matterId);
  const latestSnapshot = findLatestSnapshot(log);
  let graph = hydrate(latestSnapshot);
  for (const entry of log.entries.slice(latestSnapshot.entryIndex)) {
    graph = applyEntry(graph, entry); // deterministic replay
  }
  return graph;
}
```

**Memory bound:** Snapshot every 100 entries; truncate log after snapshot confirmed. Working set: current graph + recent log entries only.

**Invariant:** `placeholderCounters` monotonic per type; no placeholder reuse even after node merge.

**Test:** Create matter, add 50 documents over simulated months, verify placeholder `[CLIENT_50]` exists; crash and recover, verify replay produces identical graph.

---

### 1.6 SHOULD — Chunk overlap: 200-character shared boundary with cross-boundary alias detection
**Reason:** Names split across chunks ("Robert\nT. Evans") must not leak.

**Algorithm:**
```typescript
function chunkWithOverlap(text: string, chunkSize: number, overlap: number): Chunk[] {
  const chunks = [];
  let pos = 0;
  while (pos < text.length) {
    const end = Math.min(pos + chunkSize, text.length);
    const chunk = {
      id: `${docId}-${chunks.length}`,
      text: text.slice(pos, end),
      // Include overlap from previous for context, but mark as "shadow" (no new spans proposed)
      shadowPrefix: pos > 0 ? text.slice(pos - overlap, pos) : '',
      // Include overlap to next for alias detection
      shadowSuffix: end < text.length ? text.slice(end, end + overlap) : '',
    };
    chunks.push(chunk);
    pos = end - overlap; // advance with overlap
  }
  return chunks;
}

// In Phase 1, when processing chunk N:
// - Search shadowPrefix + text + shadowSuffix for aliases already in graph
// - If alias found spanning boundary, record occurrence in both chunks' interval trees
```

**Test:** Battery case "Evans" at end of chunk 1, "Construction" at start of chunk 2, verify both chunks substitute `[CLIENT_1]` for full span.

---

## PROBLEM 2 — SEAMLESS SWAP-BACK

### 2.1 MUST — Placeholder grammar: unambiguous, non-nestable, character-safe
**Reason:** Prevents collision with legal text and enables reliable parsing.

**Grammar:**
```
placeholder ::= '[' TYPE '_' INDEX suffix? ']'
TYPE        ::= 'CLIENT' | 'OPPONENT' | 'WITNESS' | 'JUDGE' | 'ORG' | 'COURT' | ...  // closed enum
INDEX       ::= [1-9][0-9]*  // no leading zero
suffix      ::= "'" | 'S' | 's'  // possessive marker, not part of identity

// Examples: [CLIENT_1], [CLIENT_1's], [ORG_2'S]
// Invalid and refused: [client_1], [CLIENT_01], [CLIENT_1_2], [[CLIENT_1]], [CLIENT_1]text
```

**Invariant:** Placeholder identity is `[TYPE_INDEX]`; suffix is parse-time decoration only.

**Test:** Red-team test with every near-miss variant, verify all refused at guard or reported as unknown at restore.

---

### 2.2 MUST — Per-occurrence surface-form ledger: exact original preserved
**Reason:** Document restore (i) must be byte-exact.

**Data structure:**
```typescript
interface Occurrence {
  occurrenceId: string;      // uuid, stable across restore operations
  placeholder: string;       // [CLIENT_1]
  originalSurface: string;  // EXACT as in input: "Bob", "Mr. Evans", "EVANS", "employeeVance's"
  normalizedSurface: string; // for deduplication: "evans"
  position: { docId: string, chunkId: string, start: number, end: number };
  context: {
    sentenceStart: boolean;
    precededByHonorific: string | null;  // "Mr.", "Dr.", "Judge"
    followedByPossessive: boolean;       // original had 's or s'
    casing: 'lower' | 'title' | 'upper' | 'mixed';
  };
}

interface SurfaceLedger {
  // Map: occurrenceId -> Occurrence
  // Index: placeholder -> occurrenceId[] (chronological)
  // Index: docId -> occurrenceId[] (for document-level restore)
}
```

**Invariant:** `originalSurface` is never modified; restore (i) is identity lookup.

**Test:** `tests/scrambler-exact-restore.test.ts` — round-trip 167 battery documents, byte-compare input and restored output.

---

### 2.3 MUST — Answer rendering: surface form selection with grammatical rules
**Reason:** "[CLIENT_1]'s motion" → "Evans's motion" or "Robert Evans's motion", never "Mr. [CLIENT_1]".

**Algorithm:**
```typescript
function renderForAnswer(placeholder: string, occurrenceId: string | null, grammaticalContext: Context): string {
  const node = graph.getNode(placeholder);
  
  if (!occurrenceId) {
    // Frontier invented or mangled placeholder — use canonical with grammatical repair
    return applyGrammaticalRules(node.canonicalAlias, grammaticalContext);
  }
  
  const occ = ledger.getOccurrence(occurrenceId);
  
  // Honorific rule: never restore "Mr. [CLIENT_1]" as "Mr. Robert Evans"
  if (occ.context.precededByHonorific) {
    // Use short form or drop honorific
    const shortForm = extractShortForm(node, occ.originalSurface);
    if (shortForm) return shortForm;
    // Else: drop honorific, use full form
    return applyGrammaticalRules(node.canonicalAlias, grammaticalContext);
  }
  
  // Sentence start: match casing of original occurrence
  if (grammaticalContext.sentenceStart) {
    return capitalizeMatch(occ.originalSurface, node.canonicalAlias);
  }
  
  // Possessive: original had "Evans's" or "Evans'" → preserve pattern
  if (grammaticalContext.needsPossessive) {
    return applyPossessive(occ.originalSurface, grammaticalContext.possessiveForm);
  }
  
  // Default: original surface form with grammatical repair for number agreement
  return applyGrammaticalRules(occ.originalSurface, grammaticalContext);
}

// Helper: extract "Bob" from "Robert "Bob" A. Evans" when honorific present
function extractShortForm(node: EntityNode, originalSurface: string): string | null {
  const definedTerms = node.aliases.filter(a => a.source === 'defined_term');
  const nicknames = definedTerms.map(t => extractQuoted(t));
  return nicknames.find(n => n.length < node.canonicalAlias.length) || null;
}
```

**Grammatical rules (deterministic):**
| Pattern | Rule |
|--------|------|
| `[X] and [X]'s parent` | Same occurrence → same surface form; second needs possessive |
| `[ORG_1] and [ORG_2]` | Plural if different nodes, singular if same (shouldn't happen) |
| Sentence start | Capitalize first letter of chosen form |
| `Mr. [CLIENT_1]` | Prefer short form; if none, drop honorific |
| `[CLIENT_1]'s` vs `[CLIENT_1]s'` | Match original apostrophe position |

**Invariant:** No placeholder in answer renders with honorific prefix unless original occurrence had it without placeholder.

**Test:** `tests/scrambler-answer-render.test.ts` — 50 constructed cases covering each rule, human evaluation of naturalness (binary pass/fail).

---

### 2.4 MUST — Unknown placeholder handling: report, never guess
**Reason:** Prevents hallucinated restores.

**Algorithm:**
```typescript
function restoreAnswer(answerText: string, ledger: SurfaceLedger, graph: EntityGraph): RestoredResult {
  const tokens = tokenize(answerText);
  const restored: string[] = [];
  const unknown: UnknownPlaceholder[] = [];
  
  for (const token of tokens) {
    const parsed = parsePlaceholder(token);
    if (!parsed) {
      restored.push(token);
      continue;
    }
    
    const node = graph.getNodeByPlaceholder(parsed.identity);
    if (!node) {
      unknown.push({ token, position: token.position, reason: 'unknown_placeholder' });
      restored.push(`[UNKNOWN:${parsed.identity}]`);
      continue;
    }
    
    // Find best occurrence or use canonical
    const occurrenceId = findBestOccurrence(parsed, ledger, token.context);
    const rendered = renderForAnswer(parsed.identity, occurrenceId, token.context);
    restored.push(rendered);
  }
  
  return { text: restored.join(''), unknown, confidence: unknown.length === 0 ? 'full' : 'partial' };
}
```

**Test:** Inject "[CLIENT_999]" and



## google/gemini-2.5-pro  (in 8780, out 3996, $0.0509)

Here are the recommendations for the three problems, based on the provided design document.

---

### PROBLEM 1 -- WHOLE CASE FILES

This problem requires designing the graph and processing order to ensure consistency across a whole case file, even when documents are added incrementally over time.

1.  **MUST** Implement a two-pass process for batch-scrambling a docket. The first pass builds the graph; the second performs substitution.
    *   **Reason:** This is the only way to ensure an entity learned in the last document is correctly pseudonymised in the first, achieving cross-document consistency within a batch.
    *   **Algorithm:**
        1.  **Pass 1 (Graph Build):** For each document in the docket, process it in chunks

