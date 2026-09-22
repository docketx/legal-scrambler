# Scrambler proof run — 2026-09-20

**ALL CLAIMS HOLD** at commit `96fed4da2` — 242 tests passed, 0 failed, 16.1 min wall on an Apple M4 laptop. Parameters: fuzz seeds 1000, real dockets 40, restore documents 167. Produced by `scripts/scrambler-prove.ts`; no model was called -- this is the proof of the pipeline. The local model's measured leak rates are in docs/SCRAMBLER.md and are not claims.

| | suite | claim | pass / fail | time |
|---|---|---|---|---|
| **PASS** | unit | graph, guard, substitution, derived aliases, defined terms, restore, and every rule real filings taught | 71 / 0 | 2s |
| **PASS** | red-team | 56 attacks on the guard: injection, look-alikes, coref cycles, citation components, glued names, public matter, the joins -- none leak | 61 / 0 | 1s |
| **PASS** | fuzz | 1000 generated filings x 3 adversarial models: no secret leaves, no citation harmed, every release round-trips | 3 / 0 | 10s |
|  |  | ↳ competent: released 1000, refused 0 of 1000 |  |  |
|  |  | ↳ hijacked: released 1000, refused 0 of 1000 |  |  |
|  |  | ↳ lazy: released 1000, refused 0 of 1000 |  |  |
| **PASS** | normalize | confusables, zero-width and quote folds happen before any model reads the text | 10 / 0 | 2s |
| **PASS** | patterns | every regex class with a positive and a public-law negative | 49 / 0 | 1s |
| **PASS** | routes | /scramble and /unscramble end to end: encrypted at rest, private per owner, cached, byte-exact swap-back over the wire | 10 / 0 | 1s |
| **PASS** | orchestrator | the frontier never sees a client fact in any message or tool argument; unknown placeholders reported | 10 / 0 | 1s |
| **PASS** | battery | 167 DeepSeek-generated adversarial filings with typed ground truth: 0 leaks under oracle and hijacked models | 6 / 0 | 76s |
|  |  | ↳ oracle: released 166, refused 1 (input-gate 0) of 167; secrets by type {"ORG":417,"PERSON":674,"ATTORNEY":282,"JUDGE":109,"ADDRESS":247,"PHONE":207,"EMAIL":226,"DOB":159,"DOCKET":198,"CLIENT":332,"SSN":161,"ACCOUNT":190,"OTHER":12}; leaked by type {} |  |  |
|  |  | ↳ hijacked: released 166, refused 1 (input-gate 0) of 167; secrets by type {"ORG":417,"PERSON":674,"ATTORNEY":282,"JUDGE":109,"ADDRESS":247,"PHONE":207,"EMAIL":226,"DOB":159,"DOCKET":198,"CLIENT":332,"SSN":161,"ACCOUNT":190,"OTHER":12}; leaked by type {} |  |  |
|  |  | ↳ lazy: released 166, refused 1 (input-gate 0) of 167; secrets by type {"ORG":417,"PERSON":674,"ATTORNEY":282,"JUDGE":109,"ADDRESS":247,"PHONE":207,"EMAIL":226,"DOB":159,"DOCKET":198,"CLIENT":332,"SSN":161,"ACCOUNT":190,"OTHER":12}; leaked by type {"ACCOUNT":9,"DOB":10,"DOCKET":2,"ADDRESS":1,"OTHER":2} |  |  |
| **PASS** | restore | byte-exact document restore through 4k chunks and the cross-chunk pass on 167 battery documents; natural answer rendering | 4 / 0 | 18s |
| **PASS** | leak-rate harness | the measurement itself: name- and occurrence-level rates, Wilson intervals, transport exclusion | 13 / 0 | 1s |
| **PASS** | proof | P1 no egress; P5 refuse never partial; P6 unknown never guessed; P3+P4 real case files under perfect spans (40 dockets): byte-exact, zero leaks, one placeholder per entity | 5 / 0 | 854s |
|  |  | ↳ real dockets: 40; entities 1984, leaked 0; 1960 of 1960 entities on one placeholder; restore 6200/6200; filings refused 0; reporter citations 3994 in, 0 lost |  |  |

## What the claims mean

- **No egress** (P1): with fetch replaced by a tripwire, a document is scrambled, restored and answered with fake models and not one network call happens; the liaison builder refuses any model id that is not `local/`; node 5 cannot be constructed without `SCRAMBLER_FRONTIER_LIVE=1`.
- **Perfect spans, zero leaks** (P2): with the planted secrets proposed exactly -- and with every red-team trick added on top -- no secret of any of 12 types survives the 167-document battery outside a cited caption. The model's own misses are measured separately.
- **Byte-exact** (P3): every scrambled document restores to its own bytes from its sealed ledger; every chunk of every real docket held.
- **Real case files** (P4): the docket's own party, attorney and judge list, proposed exactly, leaks nothing, and each entity maps to one placeholder across every filing of the file (shared surnames get their own node by design and are listed).
- **Refuse, never partially release** (P5); **unknown is reported, never guessed** (P6); **the frontier never sees a fact** (P7, the orchestrator suite).

