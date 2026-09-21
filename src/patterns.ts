// Pass 1 of the graph: deterministic identifiers. No model is involved, so these are never missed and never
// hallucinated, which is why they run FIRST and why the model is told they are already handled.
//
// Deliberately narrow. A date is only a DOB when the text says so ("DOB", "born", "date of birth"): a filing
// date or a deadline is not an identifier and scrubbing it would destroy the legal analysis. Street addresses
// are left to the model, because a regex broad enough to catch them eats statute section numbers.
import type { Span } from "./types";
import { inCaptionAt } from "./apply";
import { extractCitations } from "./citations";

/** Luhn checksum over 13–19 digits (separators already uniform by the regex). Rejects a run of one digit, which
 *  passes Luhn trivially and is a Bates pad, not a card. One in ten random digit strings passes Luhn, so the
 *  regex shape (4-4-4-4[-3], 4-6-5 or unbroken) carries most of the precision; this carries the rest. */
export function luhnValid(s: string): boolean {
  const d = s.replace(/[ -]/g, "");
  if (d.length < 13 || d.length > 19 || /^(\d)\1+$/.test(d)) return false;
  let sum = 0, dbl = false;
  for (let i = d.length - 1; i >= 0; i--) { let n = d.charCodeAt(i) - 48; if (dbl) { n *= 2; if (n > 9) n -= 9; } sum += n; dbl = !dbl; }
  return sum % 10 === 0;
}

/** ISO 13616 mod-97 check: move the first four characters to the end, letters become 10–35, remainder must be 1. */
export function ibanValid(s: string): boolean {
  const c = s.replace(/ /g, "");
  if (c.length < 15 || c.length > 34) return false;
  let rem = 0;
  for (const ch of c.slice(4) + c.slice(0, 4)) { const v = ch >= "A" ? ch.charCodeAt(0) - 55 : ch.charCodeAt(0) - 48; rem = (rem * (v > 9 ? 100 : 10) + v) % 97; }
  return rem === 1;
}

// Countries that issue IBANs (the SWIFT registry). "TX78..." or "CA12..." never reaches the checksum.
const IBAN_CC = "AD|AE|AL|AT|AZ|BA|BE|BG|BH|BI|BR|BY|CH|CR|CY|CZ|DE|DJ|DK|DO|EE|EG|ES|FI|FO|FR|GB|GE|GI|GL|GR|GT|HR|HU|IE|IL|IQ|IS|IT|JO|KW|KZ|LB|LC|LI|LT|LU|LV|LY|MC|MD|ME|MK|MN|MR|MT|MU|NI|NL|NO|OM|PK|PL|PS|PT|QA|RO|RS|RU|SA|SC|SD|SE|SI|SK|SM|SO|ST|SV|TL|TN|TR|UA|VA|VG|XK|YE";

/** A role, a firm or a caption line is not a person's name, whatever precedes the bar number. */
const ROLE_LINE = /\b(?:Attorney|Attorneys|Counsel|Plaintiff|Plaintiffs|Defendant|Defendants|Respondent|Petitioner|Appellant|Appellee|Firm|Group|LLP|LLC|PLLC|P\.C\.|Inc\.?|Corp\.?|Company|Court|District|County|State|Texas|Bar|Submitted|Respectfully|By)\b/i;
/** Courts, legislatures and reporters wear organisation suffixes too, and are public. */
const ORG_PUBLIC = /\b(?:Court|Courts|Supreme|Appeals|District|County|State|Texas|United States|Federal|Congress|Legislature|Senate|House|Commission|Department|Agency|Bureau|Administration|Board of|Reporter|Code|Rules|Statutes)\b/;
const NOT_INITIALS = new Set(["U.S.", "U.S.C.", "C.F.R.", "F.R.D.", "S.W.", "N.A.", "P.C.", "L.P.", "L.L.C.", "L.L.P.", "D.C.", "N.E.", "N.W.", "S.E.", "P.A.", "U.K.", "I.D.", "A.M.", "P.M.", "E.G.", "I.E.", "N.Y.S."]);
// `check` runs on the captured text and can veto a match (checksums). `cite` skips a match inside a cited case, the
// way DOCKET already does, for shapes that a court could also stamp on a public docket.
const P: { type: Span["type"]; re: RegExp; capture?: number; check?: (t: string) => boolean; cite?: boolean }[] = [
  { type: "SSN", re: /\b\d{3}-\d{2}-\d{4}\b/g },
  // A street address is a structured identifier the model skips on a "TO:" line: the live battery (2026-09-15,
  // 41 documents) had every ADDRESS leak in the shape "1203 Elmview Drive, Houston, Texas 77002". Number, up to
  // four capitalised words, a street type, an optional unit, an optional "City, ST 77002". Over-scrubbing a
  // courthouse address is the safe direction.
  // (a number, an optional direction and a street type with NO street name -- "1 Dr. Margaret McNeese" is a
  // footnote mark before an honorific, "…21\nSt. Paul Mercury" a table-of-contents page number before a cited
  // party, "133 S. Ct. at 1147" a reporter -- is dropped by NO_STREET_NAME below; live run on Shurb v. UT Health,
  // 2026-09-16)
  { type: "ADDRESS", re: /\b\d{1,6}[A-Z]?\s+(?:[NSEW]\.?\s+)?(?:(?:[A-Z][\w'.-]*|\d{1,3}(?:st|nd|rd|th))\s+){0,4}?(?:Street|St|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Road|Rd|Lane|Ln|Way|Court|Ct|Place|Pl|Highway|Hwy|Parkway|Pkwy|Trail|Trl|Circle|Cir|Loop|Terrace|Ter|Plaza|Square|Sq|Expressway|Freeway|Fwy|Row|Run|Pass|Path|Bend|Crossing|Cove|Cv)\b(?!\.?\s*\d)\.?(?:,?\s+(?:Suite|Ste\.?|Apt\.?|Apartment|Unit|Floor|Fl\.?|Bldg\.?|Building|#)\s*[\w-]+)?(?:,?[ \t]*\n?[ \t]*[A-Z][a-zA-Z.]+(?:\s[A-Z][a-zA-Z.]+){0,2},?[ \t]*\n?[ \t]*(?:Texas|TX|[A-Z]{2})[ \t]*\n?[ \t]*\d{5}(?:-\d{4})?(?!\d))?/g, cite: true, check: (t) => !/^\d{1,4}\s+[NSEW]\.?\s+(?:Ct|St|Pl|Dr|Ave|Rd|Ln)\.?$/i.test(t) },
  // ("133 S. Ct. at 1147", the pinpoint form, has no page number right after the reporter: a number, a bare
  // direction and a street type with NO street name between them is a reporter, never an address -- real
  // docket 2026-09-15, ten Supreme Court citations lost)
  // ("141 S. Ct. 1183" is a volume, a direction and a Court: a street type followed by a page number is a reporter,
  // and the match is also skipped inside a cited case -- battery seed 18, the first run of this pattern)
  // "500 Broadway, Houston, Texas 77008": no street type, but a number, a name and the City, ST ZIP tail
  { type: "ADDRESS", re: /\b\d{1,6}[A-Z]?\s+[A-Z][\w'.-]*(?:\s+[A-Z][\w'.-]*){0,3},[ \t]*\n?[ \t]*[A-Z][a-zA-Z.]+(?:\s[A-Z][a-zA-Z.]+){0,2},?[ \t]*\n?[ \t]*(?:Texas|TX|[A-Z]{2})[ \t]*\n?[ \t]*\d{5}(?:-\d{4})?(?!\d)/g, cite: true },
  // A minor's initials, anchored to the word that makes them a person: "the minor A.B.", "A.B., a minor",
  // "your minor son, A.B., aged 15". 17 of the first 31 PERSON leaks on the live battery were this one string.
  { type: "PERSON", re: /\b(?:minor|child|son|daughter|dependent|infant|juvenile|ward)[^.\n]{0,25}?\b([A-Z]\.[A-Z]\.(?:[A-Z]\.)?)(?![A-Za-z]|\s*§|\s*\d)/g, capture: 1, check: (t) => !NOT_INITIALS.has(t) },
  { type: "PERSON", re: /\b([A-Z]\.[A-Z]\.(?:[A-Z]\.)?),?\s+(?:a|the)\s+minor\b/g, capture: 1, check: (t) => !NOT_INITIALS.has(t) },
  // The signature block names counsel next to the bar number, and the model skipped it: "Steven A. Parker (Bar
  // No. 22334)", "/s/ Deborah Harper", "Attorney Sarah Johnson of ..." (live battery, 2026-09-15)
  { type: "ATTORNEY", re: /((?:[A-Z][\w'’.-]+[ \t]{1,2}){1,4}[A-Z][\w'’-]+)(?:,[ \t]*|[ \t]*\()(?:State\s+|Texas\s+)?Bar\s+(?:Card\s+)?(?:No\.?|Number|#)/g, capture: 1, check: (t) => !ROLE_LINE.test(t) },
  // (name tokens carry no underscore and the signature line may end in a rule of underscores: "/s/ Drew L.
  // Harris_______" took the rule into the alias and "/s/ Drew L. Harris _____" matched nothing -- the one attorney
  // the live model leaked on its first real docket, 2026-09-16)
  { type: "ATTORNEY", re: /\/s\/[ \t]*((?:[A-Z][\p{L}\p{N}'’.-]+[ \t]+){1,4}[A-Z][\p{L}\p{N}'’-]+)(?=,|[ \t_]*\n|[ \t]*\(|[ \t]*_|$)/gu, capture: 1, check: (t) => !ROLE_LINE.test(t) },
  { type: "ATTORNEY", re: /\bAttorney[ \t]+((?:[A-Z][\w'’.-]+[ \t]+){1,3}[A-Z][\w'’-]+)(?=[ \t]+(?:of|for|with|at|,)|\.|,|\n)/g, capture: 1, check: (t) => !ROLE_LINE.test(t) && !/^General\b/.test(t) },
  // The "By:" line of a signature block names the signer: "By: Michael S. Rivera, Vice President" (live battery)
  { type: "PERSON", re: /\bBy:[ \t]*(?:\/s\/[ \t]*)?((?:[A-Z][\p{L}\p{N}'’.-]+[ \t]+){1,4}[A-Z][\p{L}\p{N}'’-]+)(?=,|[ \t_]*\n|[ \t]*\(|[ \t]*_)/gu, capture: 1, check: (t) => !ROLE_LINE.test(t) },
  // An organisation wears its corporate form: "Johnson & Lee LLP", "Capitol Corporate Services, Inc." -- the live
  // battery had the model skip 21 of 239 organisations, and most carried one. Only the corporate-form suffixes
  // (not "Group", "Services", "Bank": too many public bodies and too many fixtures re-numbered); a party of a
  // cited case ("Ethyl Corp. v. Daniel Constr. Co.") is public law and is skipped by the " v. " on either side.
  // (a role word before the name is not the name: "Plaintiff TechBridge Solutions, Inc." made an alias the bare
  // company never matched -- third reading, 2026-09-15)
  { type: "ORG", re: /\b(?:(?:Plaintiffs?|Defendants?|Respondents?|Petitioners?|Appellants?|Appellees?|Claimants?|Intervenors?|Movants?|Debtors?|Creditors?|Relators?|Garnishees?|Cross-Plaintiffs?|Cross-Defendants?|Counter-Plaintiffs?|Counter-Defendants?|Third-Party[ \t]+(?:Plaintiffs?|Defendants?)|Insureds?|Insurers?|Employers?|Employees?|Lessors?|Lessees?|Landlords?|Tenants?|Buyers?|Sellers?|Lenders?|Borrowers?|Contractors?|Subcontractors?|Guarantors?|Trustees?)[ \t]+)?((?:(?:[A-Z][\w'’.-]*|&)[ \t]+){1,6}(?:[A-Z][\w'’.-]*,?[ \t]+)?(?:LLP|L\.L\.P\.|LLC|L\.L\.C\.|PLLC|Inc\.|Inc\b|Corp\.|Corp\b|Co\.|P\.C\.|L\.P\.|Ltd\.|N\.A\.))(?![\w'’-])/g, capture: 1, cite: true, check: (t) => !/^(?:The|A|An|Of|In|For|By|To|And|Or|See|Cf\.|Accord|Compare|Citing|Contra|Also|But|E\.g\.|Id\.)\b/.test(t) && !ORG_PUBLIC.test(t) && !/^(?:Inc|Corp|Co|Ltd)\b/.test(t) },
  // "Smith & Associates", "Jones & Sons": a firm named after its founder with an ampersand and a partner word
  { type: "ORG", re: /\b((?:[A-Z][\w'’.-]+[ \t]+){1,2}&[ \t]+(?:Associates|Partners|Sons|Daughters|Brothers|Company|Co\.))(?![\w'’-])/g, capture: 1, cite: true },
  // "referred to as Judge Garcia": an honorific followed by a capitalised name is a judge whatever the model said
  { type: "JUDGE", re: /\b((?:Judge|Justice|Magistrate|Hon\.|Honorable|Chief Justice|Presiding Judge)[ \t]+[A-Z](?:[\p{L}-]|['’](?=[A-Za-z]{2}))*(?:[ \t]+[A-Z](?:[\p{L}.-]|['’](?=[A-Za-z]{2}))*){0,3})(?![\w'’-])/gu, capture: 1, check: (t) => !ROLE_LINE.test(t) && !/^(?:Judge|Justice|Magistrate|Hon\.|Honorable)\s+(?:Advocate|Department|of|for|the|Trial|Court|Pro|Tem|System|Center|Case|Cases|Counts?|Data|Program|Reform|Act|Code)\b/.test(t) && !/\d/.test(t) && looksLikeName(t.replace(/^(?:Chief Justice|Presiding Judge|Judge|Justice|Magistrate|Hon\.|Honorable)\s+/, "")) },
  // "456 78 1234": the battery wrote SSNs with spaces (as asked) and nine of them walked past the dashed pattern
  { type: "SSN", re: /\b\d{3} \d{2} \d{4}\b(?![-.]\d)/g },
  { type: "EMAIL", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  // The separator must repeat ("713-555-0142", "713.555.0142"), never mix: "101-261.1055" is a statute section
  // range, and it matched the first version of this pattern (red-team 10a).
  { type: "PHONE", re: /(?:\+1[\s.-]?)?(?:\(\d{3}\)\s?|\b\d{3}([\s.-]))\d{3}(?:\1|(?<=\)\s?\d{3})[\s.-])\d{4}\b/g },
  // "date of birth is March 14, 1971" / "was April 17, 1935": the battery wrote it that way 32 times (2026-09-15)
  { type: "DOB", re: /\b(?:DOB|D\.O\.B\.|date of birth|born(?: on)?)(?:\s+(?:is|was|of))?[:\s]+((?:\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4})|(?:[A-Z][a-z]+ \d{1,2}, \d{4}))/gi, capture: 1 },
  // the date FIRST: "On March 14, 1971, James Michael Harrison was born" (live battery, doc 1-1, 2026-09-15) and
  // the pleading ordinal, "born on the 14th day of March, 1971"
  { type: "DOB", re: /\b((?:\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4})|(?:[A-Z][a-z]+ \d{1,2}, \d{4})),\s+(?:[A-Z][\p{L}.'’-]+,?\s+){1,5}(?:was|is) born\b/gu, capture: 1 },
  { type: "DOB", re: /\bborn(?: on)?\s+the\s+(\d{1,2}(?:st|nd|rd|th) day of [A-Z][a-z]+,? \d{4})/gi, capture: 1 },
  // Live battery (2026-09-15, 75 documents): "date of birth is December 12, 1970 (12/12/1970)" -- the numeric
  // twin in parentheses; "date of birth is listed in the petition as July 11, 1978" -- prose between the anchor
  // and the date; "on her date of birth, March 3, 1985" -- a comma. Up to 60 chars of one clause after the anchor.
  // The clause window admits a period only after an initial ("Thomas R. Whitfield"): "Date of Birth of Thomas R.
  // Whitfield: January 14, 1978" did not match on the INPUT, matched on the OUTPUT once the name was [PERSON_8],
  // and the gate refused three documents for a regex hit that exists only in the output (after-run, 2026-09-15).
  { type: "DOB", re: /\b(?:DOB|D\.O\.B\.|date of birth)\b(?:[^.;\n]|(?<=\b[A-Z])\.){0,60}?((?:[A-Z][a-z]+ \d{1,2}, \d{4})|(?:\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4}))/gi, capture: 1 },
  { type: "DOB", re: /\b(?:DOB|D\.O\.B\.|date of birth|born)\b(?:[^.;\n]|(?<=\b[A-Z])\.){0,60}?\(\s*(\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4})\s*\)/gi, capture: 1 },
  // an SSN already redacted to its last four is still the last four: "***-**-9012", "XXX-XX-9012"
  { type: "SSN", re: /(?<![\w*])(?:\*{3}|[Xx]{3})-(?:\*{2}|[Xx]{2})-\d{4}\b/g },
  // Texas-style and federal-style docket / cause numbers. Public, but they identify a matter instantly.
  { type: "DOCKET", re: /\b(?:\d{2}-\d{2}-\d{5}-(?:CV|CR)|\d{2}-[A-Z]{2,4}-\d{4,7}|\d{1,2}:\d{2}-[a-z]{2}-\d{3,6}(?:-[A-Z]+)?|No\. \d{2}-\d{4,6}|[A-Z]{1,3}-\d{2}-\d{3,6}|\d{4}-[A-Z]{2,3}-\d{3,6}|[A-Z]-\d-[A-Z]{2}-\d{2}-\d{4,6}|\d{4}-\d{4}-[A-Z]{2,4})\b/g },
  // Delaware Chancery "C.A. No. 2025-0417-KSJM"
  { type: "DOCKET", re: /\bC\.?A\.?\s*No\.?\s*:?\s*(\d{4}-\d{3,5}(?:-[A-Z]{2,4})?)\b/g, capture: 1 },
  // Announced in prose, with words between the anchor and the value: "the cause number will be CV-2025-0789",
  // "cause number for any legal action you may file is CC-2024-0789", "case number is OSHA-2024-09876",
  // "APPEAL NO. 14-24-00567-CV", "File No.: A-098-765-432" (live battery, 2026-09-15: 9 of 10 DOCKET leaks)
  { type: "DOCKET", re: /\b(?:cause|case|docket|file|appeal|claim|matter|reference)\s+(?:no\.?|number|#)\b[^.;\n]{0,60}?\b(?:is|was|will be|as|of)\s+((?=[A-Z0-9-]*\d)[A-Z]{0,6}-?[A-Z0-9][A-Z0-9-]{4,})(?![\w-])/gi, capture: 1 },
  { type: "DOCKET", re: /\b(?:appeal|file|case|cause|docket|claim|matter)\s+no\.?\s*:?\s*((?=[A-Z0-9-]*\d)[A-Z]{0,6}-?[A-Z0-9][A-Z0-9-]{4,})(?![\w-])/gi, capture: 1 },
  // Announced cause / case numbers in every Texas county style the battery threw at us (2026-09-15): Harris
  // "2024-45678-H", Travis "D-1-GN-24-00392", probate "PR-24-00088", "2024-CV-01234", "24-001123", "24-9876".
  // The announcing words carry the meaning; the token must hold a digit and be at least 6 chars, so "Case No. 25"
  // and "Rule 91a" stay out.
  { type: "DOCKET", re: /\b(?:cause|case|matter|docket|adversary|civil action|criminal action)\s*(?:no\.?|number|#)?(?:\s+for\s+this\s+(?:matter|proceeding|case))?\s*(?:is\s+|:\s*)?\s*((?=[A-Z0-9-]*\d)[A-Z]{0,3}-?[A-Z0-9][A-Z0-9-]{4,24})(?=[\s,;.)\]]|$)/gi, capture: 1, check: (t: string) => !/^\d{4}$/.test(t) },
  // ^ the digit lookahead is load-bearing: without it "matter cause number 24-9876" matched "matter" + token
  //   "cause", the check rejected it AFTER the engine had consumed the text, and the real announcer was never tried
  // The captured token must contain a digit: "policy considerations" and "loan agreement" are words (red-team 10b).
  { type: "ACCOUNT", re: /\b(?:acct|account|policy|loan|card)(?: no\.?| number| #)?[:\s]+([A-Z0-9-]*\d[A-Z0-9-]{5,})\b/gi, capture: 1 },
  // "account ending in 4567", "card ending 1234", "last four digits 9876": the digits identify only with the
  // phrase, and the guard is right to refuse a bare 4-digit span, so the phrase is the anchor (battery seed 35)
  { type: "ACCOUNT", re: /\b(?:ending(?:\s+in)?|last\s+(?:four|4)(?:\s+digits)?(?:\s+(?:are|is|of))?)[\s:#]*(\d{4})\b/gi, capture: 1 },
  // announced through a phrase: "policy number for this incident is POL-2024-8876" (battery, 14 misses)
  { type: "ACCOUNT", re: /\b(?:acct|account|policy|loan|card|claim)\s+(?:no\.?|number|#)[^\n:]{0,40}?\s(?:is|was|of)\s+([A-Z]{1,6}-?\d[A-Z0-9-]{4,})\b/gi, capture: 1 },

  // ---- identifier classes real filings carry (review 2026-09-15, "New, and adopted", item 1) ---------------------
  // Every one is typed ACCOUNT on purpose: it is the one regex-class type the graph keeps out of the local model's
  // alias hints (REGEX_TYPES in graph.ts), and to the frontier each of these reads as "an identifier". Each is
  // anchored by a context word or by a shape no statute section, reporter cite, year, ZIP or Rule number has.
  // Bar numbers: signature blocks and appearances. "State Bar No. 24012345", "Bar Card No.", "SBOT 24012345", "TBN:".
  { type: "ACCOUNT", re: /\b(?:(?:(?:State|Texas|Tex\.|Delaware|California|New York|Florida|Michigan|Illinois|Ohio|Georgia|Louisiana|Oklahoma|Arizona|Colorado|Virginia|Pennsylvania|Washington|Oregon|Nevada|Utah)\s+)?Bar\s+(?:Card\s+)?(?:No\.?|Number|#)|(?:SBOT|SBN|TBN)(?:\s*(?:No\.?|Number|#))?|Fed(?:eral|\.)\s+(?:I\.?D\.?|Bar)\s+(?:No\.?|Number|#))[\s:#]*(?:\([^)\n]{0,60}\)\s*)?(?:is\s+)?([A-Z]?\d{5,8})\b/gi, capture: 1 },
  // Bates, announced: "Bates No. 000123", "Bates-stamped ABC000123", "Bates range DEF_00045–DEF_00051".
  // "Bates range AHS-100-250": a prefix and two short runs (the battery's third reading, 2026-09-15: two ACCOUNT leaks)
  { type: "ACCOUNT", re: /\bBates(?:[ -](?:stamped|labell?ed|numbered))?(?:\s+(?:Nos?\.?|Numbers?|#|range))?[\s:#]*\(?([A-Z]{2,12}-\d{2,8}-\d{2,8})(?![A-Za-z0-9])/g, capture: 1 },
  { type: "ACCOUNT", re: /\bBates(?:[ -](?:stamped|labell?ed|numbered))?(?:\s+(?:Nos?\.?|Numbers?|#|range))?[\s:#]*((?:[A-Z]{1,12}[_-]?)?\d{4,8}(?:\s?[-–]\s?(?:[A-Z]{1,12}[_-]?)?\d{3,8})?)(?![A-Za-z0-9])/g, capture: 1 },
  // word-segment Bates prefixes and "X to Y" ranges: "Bates Range: HARPER-ANSWER-001 to HARPER-ANSWER-010" (battery)
  { type: "ACCOUNT", re: /(?<![A-Za-z0-9])([A-Z]{2,}(?:-[A-Z]{2,})+-\d{3,8})(?![A-Za-z0-9])/g, capture: 1, cite: true },
  // Bates, bare: an upper-case prefix glued (or joined by _ or -) to a zero-padded run, e.g. "ABC000123", "DEF_00045",
  // optionally a range. NOT preceded by a digit-dash: "DCV-358159" inside the docket "25-DCV-358159" is not Bates.
  { type: "ACCOUNT", re: /(?<![A-Za-z0-9])(?<!\d-)([A-Z]{2,6}[_-]?\d{5,8}(?:\s?[-–]\s?[A-Z]{2,6}[_-]?\d{5,8})?)(?![A-Za-z0-9])/g, capture: 1, cite: true },
  // EIN / TIN. The bare shape 2-7 is shared by nothing else here: SSN is 3-2-4, ZIP+4 is 5-4, phone 3-3-4, and a
  // section range ("261.101-261.1055") breaks on the dot. Announced form also takes the 9 digits unhyphenated.
  { type: "ACCOUNT", re: /(?<![-.$€£])\b\d{2}-\d{7}\b(?![-.]\d)/g },
  { type: "ACCOUNT", re: /\b(?:EIN|FEIN|TIN|ITIN|(?:Federal\s+)?Tax(?:payer)?\s+(?:ID|I\.D\.|Identification)(?:\s+(?:No\.?|Number))?|Employer\s+Identification\s+(?:No\.?|Number))[\s:#]*(\d{2}-?\d{7})\b/gi, capture: 1 },
  // Passport, only when the word is there: 9 digits, or a letter and 8 (the post-2021 US book).
  // "medical license number is L-4567", "serial number is VIN 4U7AA12345" (a short VIN the 17-char rule cannot
  // take), "member ID: 88-1234-Q" -- any announced identifier with a digit in it (live battery, 2026-09-15)
  { type: "ACCOUNT", re: /\b(?:licen[cs]e|permit|registration|certificate|member(?:ship)?|serial|reference|confirmation|tracking|invoice|order|file|claim|customer|subscriber|group|contract|agreement|lot|parcel|badge|employee)\s+(?:ID|I\.D\.|no\.?|number|#)(?:\s+(?:is|was|of)|:)?\s+(?:VIN\s+)?([A-Z0-9][A-Z0-9-]*\d[A-Z0-9-]{2,})\b/gi, capture: 1 },
  { type: "ACCOUNT", re: /\b(?:U\.?S\.?\s+)?Passport(?:\s+(?:No\.?|Number|#|ID))?[\s:#]*([A-Z]?\d{8,9})\b/gi, capture: 1 },
  // VIN: 17 characters from the alphabet that has no I, O or Q, with at least one digit, after "VIN" (case matters:
  // a person can be called Vin) or the spelled-out form, "(VIN)" included.
  { type: "ACCOUNT", re: /\b(?:VIN|Vehicle\s+Identification\s+(?:No\.?|Number))(?:\s*(?:No\.?|Number|#))?[^\n:]{0,40}?[\s:#)]*((?=[A-HJ-NPR-Z0-9]{0,16}\d)[A-HJ-NPR-Z0-9]{17})\b/g, capture: 1 },
  // Licence plate: "plate TX ABC-1234", "license plate no. ABC1234", "Texas plates 7XYZ123". The token is letters
  // then digits, or a mixed run carrying both a letter and a digit, so "plate 2024" (a year) and "steel plate No. 4"
  // are not plates. An optional state code before the token is consumed, never captured.
  { type: "ACCOUNT", re: /\b(?:(?:[Ll]icen[cs]e|[Rr]egistration|Texas|TX)\s+)?(?:[Pp]lates?|[Tt]ags?\s+(?:[Nn]o\.?|[Nn]umber|#))(?:\s+(?:[Nn]os?\.?|[Nn]umbers?|#))?[\s:#]*(?:(?:TX|Texas|[A-Z]{2})\s+)?([A-Z]{1,3}[- ]?\d{3,5}|(?=[A-Z0-9-]*\d)(?=[A-Z0-9-]*[A-Z])[A-Z0-9]{2,4}-?[A-Z0-9]{2,4})(?![A-Za-z0-9])/g, capture: 1 },
  // Medical record numbers, in context: "MRN 12345678", "Medical Record No.", "Patient ID", "Chart No.".
  { type: "ACCOUNT", re: /\b(?:MRN\b|MR\s*#|Medical\s+Record\s+(?:No\.?|Number|#)|Patient\s+(?:ID|I\.D\.|Account|Acct\.?)(?:\s+(?:No\.?|Number))?|Chart\s+(?:No\.?|Number|#))[\s:#]*([A-Z0-9-]*\d[A-Z0-9-]{3,})\b/gi, capture: 1 },
  // Payment cards: 4-4-4-4(-3) or 4-6-5 with ONE repeated separator, or 13–19 unbroken digits; then Luhn. Not after a
  // currency sign or inside a longer number ("$1,234,567,890,123.45").
  { type: "ACCOUNT", re: /(?<![$€£\d.,-])\b(?:\d{4}([ -])\d{4}\1\d{4}\1\d{4}(?:\1\d{1,3})?|\d{4}([ -])\d{6}\2\d{4,5}|\d{13,19})\b(?![.,-]?\d)/g, check: luhnValid },
  // IBAN: issuing country, two check digits, 11–30 alphanumerics in optional groups of four; then mod-97.
  { type: "ACCOUNT", re: new RegExp(`\\b(?:${IBAN_CC})\\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\\b`, "g"), check: ibanValid },
  // Driver's licence, in context: "DL No. 12345678", "TDL 12345678", "Texas Driver's License No.", "DPS ID".
  { type: "ACCOUNT", re: /\b(?:(?:TX|Texas)\s+)?(?:TDL|DL|D\.L\.|Driver'?s?\s+Licen[cs]e|Operator'?s?\s+Licen[cs]e|DPS\s+ID)(?:\s*(?:No\.?|Number|#|ID))?[\s:#]*([A-Z0-9-]*\d[A-Z0-9-]{4,})\b/gi, capture: 1 },
];

/** A docket number that is part of a CITED case — "In re Doe, No. 24-0301 (Tex. 2025)", "Smith v. Jones, 4:21-cv-01234
 *  (S.D. Tex. 2023)" — is public law, not the client's matter (red-team 10c). Caption behind it, court-year
 *  parenthetical after it. */
export function inCitationContext(text: string, start: number, end: number): boolean {
  const before = text.slice(Math.max(0, start - 90), start); const after = text.slice(end, end + 80);
  // up to 40 characters before the court-year parenthetical: "No. CCB-08-550, 2008 WL 5243517 (D. Md. Dec. 16, 2008)"
  if (!/(?:\bv(?:s)?\.\s|\bIn re\b|\bEx parte\b)[^\n]*$/i.test(before)) return false;
  if (/^[^\n(]{0,40}\(\s*[A-Z][^)]{0,40}\d{4}\s*\)/.test(after)) return true;
  // (a Westlaw cite "2004 WL 2375543" right after the docket number is the same signal)
  if (/^,?\s*\d{4}\s+WL\s+\d{3,}/.test(after)) return true;
  // ...or a reporter citation follows in the next 80 characters, read across line wraps: "Shannon v. Henderson, No.
  // 01-10346, slip op. at 8, 275 F.3d\n\n42" -- the parenthetical sat 60 characters and a blank line away, and the
  // cited case's docket number was scrubbed (live box run, 2026-09-16)
  return extractCitations(after.replace(/\s+/g, " ")).length > 0;
}

// A name token whose apostrophe is part of the name ("O'Brien"), never a possessive ("Doe's")
const NAME_TOK = "[A-Z](?:[\\w-]|['’](?=[A-Za-z]{2}))*";
// a leading token of a name: the same class plus a trailing period for an initial -- never a possessive ("Prible's
// Due Process" was taken as a person on a real docket, 2026-09-15)
const LEAD_TOK = "(?:[A-Z]\\.|(?:St|Ste|Dr|Mt|Ft|Jr|Sr)\\.|[A-Z](?:[\\w-]|['’](?=[A-Za-z]{2}))*)";
/** LATE name anchors: an honorific, a role apposition, a counsel anchor. These run AFTER the model's pass, not in
 *  the regex pass: found first, "Mr. Doe" made a surname-only node before the model proposed "John Doe", and the
 *  two could never merge (five fixtures, 2026-09-15). index.ts attaches each to the node that owns the surname. */
const LATE: { type: Span["type"]; re: RegExp; check?: (t: string) => boolean }[] = [
  // "TO: Ms. Sarah L. Peterson", "Dear Ms. Peterson", "Mr. James A. Wilson of Wilson & Hart": the after-run had one
  // document where the model proposed nothing for the addressee and six secrets walked out, every one after "Ms."
  { type: "PERSON", re: new RegExp(`\\b(?:Mr|Ms|Mrs|Mx|Dr|Prof)\\.?[ \\t]+((?:${LEAD_TOK}[ \\t]{1,2}){0,3}${NAME_TOK})(?![\\w-]|['’][A-Za-z]{2})`, "g"), check: (t) => !ROLE_LINE.test(t) && !/^(?:President|Chairman|Speaker|Secretary|Justice|Judge)\b/.test(t) },
  // a rank is an honorific: "Police Officer Kevin M. O’Brien", "Sgt. Derek J. Simmons" (third reading, 2026-09-15)
  { type: "PERSON", re: new RegExp(`\\b(?:Officer|Sergeant|Sgt|Detective|Det|Captain|Capt|Lieutenant|Lt|Trooper|Deputy|Agent|Investigator|Nurse|Paramedic|Coach|Pastor|Reverend|Rev|Rabbi|Imam)\\.?[ \\t]+((?:${LEAD_TOK}[ \\t]{1,2}){0,3}${NAME_TOK})(?![\\w-]|['’][A-Za-z]{2})`, "g"), check: (t) => !ROLE_LINE.test(t) && !/^(?:General|Assistant|Deputy|Chief|of|for|the)\b/i.test(t) },
  // corporate roles in apposition: "the defendant’s president, Thomas White, was born"; "The plaintiff’s
  // representative is John White"
  { type: "PERSON", re: new RegExp(`\\b(?:president|vice president|chief executive officer|CEO|CFO|COO|manager|director|owner|representative|agent|employee|custodian|adjuster|officer|principal|partner|member|secretary|treasurer|supervisor|foreman|contact person)(?:[ \\t]+(?:is|was))?,?[ \\t]+((?:${LEAD_TOK}[ \\t]{1,2}){1,3}${NAME_TOK})(?=,|\\.|;|[ \\t]*\\(|[ \\t]*\\n|[ \\t]+(?:was|is|who|and|of|at)\\b)`, "g"), check: (t) => !ROLE_LINE.test(t) && !/^(?:Of|The|For|And|Is|Was|Who|In|At|On|By|To)\b/.test(t) },
  // "the Decedent, Margaret Louise Hartwell, died"
  { type: "PERSON", re: new RegExp(`\\b(?:Decedent|Deceased|Testator|Testatrix|Debtor|Ward|Grantor|Grantee|Settlor|Beneficiary|Insured|Movant|Applicant|Affiant|Declarant|Deponent|Witness|Guarantor|Borrower|Employee|Tenant|Buyer|Seller|Patient|Claimant),[ \\t]+((?:${LEAD_TOK}[ \\t]{1,2}){1,3}${NAME_TOK}),`, "g"), check: (t) => !ROLE_LINE.test(t) },
  // The signature block: a name on its own line right above the bar number or the role line ("David L. Chen, Esq.\n
  // Texas Bar No. 24091234"; "Lydia M. Hargrave\nAttorney for Plaintiff"), and counsel named in apposition
  // ("counsel for Plaintiff, Sarah Mitchell of Mitchell & Perez"; "his attorney of record, Patricia L. Henderson,")
  // -- 12 of the 16 ATTORNEY leaks of the battery after-run (2026-09-15)
  // ...the name may sit after a merged column ("ABBOTT          DREW L. HARRIS"), and the role line below may be an
  // office ("Attorney General of Texas", "Assistant Attorney General", "Attorney-in-Charge") -- live model, 2026-09-16
  { type: "ATTORNEY", re: new RegExp(`(?:^|\\n)[ \\t_]*((?:${LEAD_TOK}[ \\t]{1,2}){1,4}${NAME_TOK})(?:,[ \\t]*Esq\\.?)?(?:[ \\t]{3,}[^\\n]*)?[ \\t]*\\n[ \\t]*(?:(?:Texas|State|Tex\\.)[ \\t]+)?(?:Bar[ \\t]+(?:No\\.?|Card|Number)|SBOT|SBN|TBN|Attorneys?[ \\t]+for\\b|Counsel[ \\t]+for\\b|Of[ \\t]+Counsel\\b|Lead[ \\t]+Counsel\\b|(?:Assistant|Deputy|First[ \\t]+Assistant|Acting)[ \\t]+Attorney[ \\t]+General\\b|Attorney[ \\t]+General[ \\t]+of\\b|Attorney[- ]+[Ii]n[- ]+Charge\\b|Assistant[ \\t]+(?:United[ \\t]+States|U\\.S\\.)[ \\t]+Attorney\\b)`, "g"), check: (t) => !ROLE_LINE.test(t) },
  { type: "ATTORNEY", re: new RegExp(`\\b(?:counsel|attorney(?:s)?(?:[ \\t]+of[ \\t]+record)?|lawyer)(?:[ \\t]+for[ \\t]+(?:the[ \\t]+)?[A-Z][\\w'’-]+(?:[ \\t]+[A-Z][\\w'’-]+)?)?,[ \\t]+((?:${LEAD_TOK}[ \\t]{1,2}){1,3}${NAME_TOK})(?=,|[ \\t]+(?:of|at|with|and)\\b|\\.)`, "g"), check: (t) => !ROLE_LINE.test(t) },
  // the SECOND column of a signature block: a name after a column gap whose next line carries an office role anywhere
  // ("GREG ABBOTT          DREW L. HARRIS\nAttorney General of Texas          Assistant Attorney General"). A bare
  // "State Bar No." on the next line belongs to the first column (the two-column fixture of 2026-09-15), an office
  // role does not.
  { type: "ATTORNEY", re: new RegExp(`[ \\t]{3,}((?:${LEAD_TOK}[ \\t]{1,2}){1,4}${NAME_TOK})[ \\t]*\\n[^\\n]*?(?:(?:Assistant|Deputy|First[ \\t]+Assistant|Acting)[ \\t]+Attorney[ \\t]+General\\b|Attorney[ \\t]+General[ \\t]+of\\b|Attorney[- ]+[Ii]n[- ]+Charge\\b|Assistant[ \\t]+(?:United[ \\t]+States|U\\.S\\.)[ \\t]+Attorney\\b)`, "g"), check: (t) => !ROLE_LINE.test(t) },
  // ...and the name on the line BELOW a role line ending in a colon: "Attorney for Defendant:\nThomas R. Baker"
  // (both ATTORNEY leaks of the battery's third reading, 2026-09-15)
  { type: "ATTORNEY", re: new RegExp(`\\b(?:Attorneys?|Counsel)[ \\t]+(?:for|of[ \\t]+record[ \\t]+for)[ \\t]+[^\\n:]{1,40}:[ \\t]*\\n[ \\t]*(?:\\/s\\/[ \\t]*)?((?:${LEAD_TOK}[ \\t]{1,2}){1,4}${NAME_TOK})(?:,[ \\t]*Esq\\.?)?(?=[ \\t]*\\n|[ \\t]*$|[ \\t]{3,})`, "g"), check: (t) => !ROLE_LINE.test(t) },
  // "Attn: Robert M. Harrison", "served on Rebecca Chen"
  { type: "ATTORNEY", re: new RegExp(`\\b(?:Attn|Attention|c\\/o)[:.]?[ \\t]+((?:${LEAD_TOK}[ \\t]{1,2}){1,3}${NAME_TOK})(?=,|\\n|[ \\t]+(?:at|of|phone|by)\\b)`, "g"), check: (t) => !ROLE_LINE.test(t) },
  { type: "ATTORNEY", re: new RegExp(`\\bserved (?:on|upon)[ \\t]+((?:${LEAD_TOK}[ \\t]{1,2}){1,3}${NAME_TOK})(?=,|\\.|[ \\t]+(?:on|at|by|via|of)\\b)`, "g"), check: (t) => !ROLE_LINE.test(t) },
];
/** English words that a Title-Case heading or a sentence start puts next to a name: a run containing one is a
 *  heading or a sentence, not a name ("Mr. Schooley Testified That That Basis", "Roman. Because Dr. Roman", real
 *  docket 2026-09-15). Connectors a name may carry ("de", "van", "of") are not here. */
const NOT_NAME_WORD = new Set(["a", "an", "the", "this", "that", "these", "those", "there", "here", "then", "than", "when", "where", "which", "what", "who", "whom", "whose", "why", "how", "because", "since", "while", "although", "though", "if", "unless", "until", "whether", "neither", "nor", "either", "or", "and", "but", "so", "yet", "not", "no", "nor", "is", "are", "was", "were", "be", "been", "being", "has", "have", "had", "do", "does", "did", "will", "would", "shall", "should", "may", "might", "must", "can", "could", "its", "his", "her", "their", "our", "your", "my", "it", "he", "she", "they", "we", "you", "i", "in", "on", "at", "by", "to", "from", "with", "without", "into", "onto", "upon", "under", "over", "after", "before", "during", "between", "among", "against", "about", "above", "below", "through", "per", "via", "as", "see", "cf", "id", "also", "accord", "compare", "contra", "e.g", "i.e", "testified", "testify", "stated", "states", "said", "says", "argues", "argued", "contends", "claims", "alleges", "admits", "denies", "abused", "misused", "failed", "moved", "filed", "granted", "denied", "held", "found", "ruled", "ordered", "affirmed", "reversed", "remanded", "dismissed", "entered", "issued", "signed", "served", "noted", "concluded", "basis", "motion", "order", "petition", "brief", "reply", "response", "exhibit", "ex", "pet", "resp", "def", "pl", "aff", "dep", "tr", "vol", "page", "line", "lines", "three-year", "one-year", "two-year", "year", "years", "day", "days", "month", "months", "case", "cases", "manager", "clerk", "coordinator", "assistant", "secretary", "chambers", "courtroom", "deputy"]);
export function looksLikeName(t: string): boolean {
  const toks = t.trim().split(/\s+/);
  for (const tok of toks) {
    const bare = tok.replace(/[,]$/, "");
    // (an initial "A." is not the article "a")
    if (!bare.endsWith(".") && NOT_NAME_WORD.has(bare.toLowerCase())) return false;
    // a period ends an initial ("J.") or an abbreviation we know ("Jr.", "St."); "Eldridge." is a sentence end
    if (bare.endsWith(".") && !/^(?:[A-Z]\.|[A-Z]\.[A-Z]\.|Jr\.|Sr\.|St\.|Dr\.|Mr\.|Ms\.|Mrs\.|Esq\.|II\.|III\.)$/.test(bare)) return false;
    if (/\d/.test(bare)) return false;
  }
  return true;
}
export function lateNameSpans(text: string): Span[] {
  const out: Span[] = []; const seen = new Set<string>();
  for (const { type, re, check } of LATE) { re.lastIndex = 0; for (const m of text.matchAll(re)) { const t = m[1].trim(); if (seen.has(t) || t.length < 3 || (check && !check(t)) || /\[[A-Z]+_\d+\]/.test(t) || !looksLikeName(t)) continue; seen.add(t); out.push({ text: t, type }); } }
  return out;
}

/** "1 Dr", "21\nSt", "12 N. Ct", "133 S. Ct": a number, an optional direction and one word -- the street type itself --
 *  with no street name and no city tail is never an address (a real one has a name; a courthouse one has a tail). */
const NO_STREET_NAME = /^\d{1,6}[A-Z]?\s+(?:[NSEW]\.?\s+)?[A-Za-z]{1,10}\.?$/;
export function regexSpans(text: string): Span[] {
  const out: Span[] = []; const seen = new Set<string>();
  for (const { type, re, capture, check, cite } of P) {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) {
      if ((type === "DOCKET" || cite) && inCitationContext(text, m.index!, m.index! + m[0].length)) continue;
      // a cited party ("Prudential Ins. Co. of Am. v. Fin. Review Assocs., 29 F.3d 153") is public law: the
      // caption GRAMMAR decides, not a character window -- a window slid past " v. " once a neighbouring name
      // became a longer placeholder, and the same span then fired on the output only (real docket, 2026-09-15)
      if (type === "ORG" && inCaptionAt(text, m.index!, m.index! + m[0].length)) continue;
      const t = (capture ? m[capture] : m[0]).trim();
      if (type === "ADDRESS" && NO_STREET_NAME.test(t)) continue;
      const k = `${type}:${t}`; if (seen.has(k) || t.length < 4 || (check && !check(t))) continue;
      seen.add(k); out.push({ text: t, type });
    }
  }
  return out;
}
