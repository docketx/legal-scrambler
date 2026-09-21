// The headline numbers of the 2026-09-16 scrambler proof run (docs/SCRAMBLER-PROOF.md, re-runnable with
// scripts/scrambler-proof.ts). Every public surface that states a scrambler number imports THIS object, and
// tests/scramble-docs-page.test.ts pins each figure to the proof document. Change the proof, then this.
export const SCRAMBLER_PROOF = {
  dockets: 40,
  entities: 1_984,
  leaked: 0,
  restores: "6,200/6,200",
  citations_in: 3_994,
  citations_lost: 0,
  adversarial_filings: 167,
  fuzz_filings: 1_000,
} as const;
