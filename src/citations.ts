// Reporter-citation extraction. The scrambler must never take a citation component ("Horowitz", "435 U.S. 86") as
// a secret: public law stays public, and a damaged citation is a harm of its own. Standalone edition of the
// extractor in DocketRouter's src/lib/rag/courtlistener.ts; the regex is the same so the measurements carry.

// "556 U.S. 662", "925 F.3d 1339", "88 Cal. App. 5th 1402"
export const CITE_RE = /\b(\d{1,4})\s+((?:[A-Z][A-Za-z.]*\.?\s?){1,5}?(?:2d|3d|4th|5th)?)\s+(\d{1,5})\b/g;
export const extractCitations = (text: string) =>
  [...text.matchAll(CITE_RE)].map((m) => `${m[1]} ${m[2].trim()} ${m[3]}`).filter((c) => /U\.S\.|F\.|S\. ?Ct\.|Cal\.|N\.Y\.|P\.|A\.|So\.|N\.E\.|N\.W\.|S\.E\.|S\.W\.|L\. ?Ed\./.test(c));
