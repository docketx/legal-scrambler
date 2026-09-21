// The pipeline graph, executed. See docs/SCRAMBLER.md for the picture; this is the code under each node.
//
// The model is injected as a function so the whole pipeline is testable with a fake — and so that the real one
// can only ever be the local liaison: `callLocal` is the single place a model is invoked, and it is handed
// exactly one string and a schema. It gets no tools, no history, no system role, no network. On our machine.
import { regexSpans, lateNameSpans } from "./patterns";
import { normalizeInput } from "./normalize";
import { MatterGraph, REGEX_TYPES } from "./graph";
import { parseProposal, validateSpans, isSovereign, FILING_LABEL } from "./guard";
import { scramble, scrambleWithLedger, residualAliases, placeholderLookalikes, inputLookalikes, LEFT_SINGLE, camelMatches, inCaptionAt, type Occurrence } from "./apply";
import { PROPOSAL_SCHEMA, VERDICT_SCHEMA, nonce, pass1Prompt, pass2Prompt } from "./prompts";
import type { Rejection, ScrambleResult, Span } from "./types";

import { HONORIFIC } from "./names";
const PERSON_TYPES = new Set(["CLIENT", "PERSON", "ATTORNEY", "JUDGE"]);
/** Surnames that are also ordinary words of legal English. A derived alias is applied wherever the word appears,
 *  so "Justice Rules" must not scrub "Texas Rules of Civil Procedure" (red-team 10f). The model-proposed full
 *  name is still scrubbed; only the bare-surname derivation is withheld. */
const COMMON_GIVEN_WORDS = new Set(["old", "new", "north", "south", "east", "west", "big", "little", "upper", "lower", "great", "grand", "saint", "san", "santa", "los", "las", "el", "la", "de", "van", "von", "fort", "port", "lake", "mount", "sea", "high", "low", "first", "second", "third", "united", "general", "national", "american", "texas", "central", "southern", "northern", "eastern", "western", "mark", "bill", "will", "grace", "hope", "sue", "art", "rob", "pat", "rich", "frank", "chase", "chuck", "dawn", "faith", "gene", "guy", "jack", "june", "may", "max", "ray", "rose", "ruth", "sandy", "wade", "victor", "lance", "miles", "pearl", "penny", "carol", "holly", "jean", "don", "al", "bud", "cliff", "clay", "dean", "earl", "flora", "forest", "glen", "hazel", "iris", "ivy", "jade", "jay", "joy", "kay", "lee", "lily", "major", "marshall", "olive", "page", "reed", "rex", "rusty", "sky", "star", "summer", "violet", "wells", "west", "young", "van", "king", "prince", "duke", "bishop", "dick", "randy", "ken", "ben", "ed", "tom", "tim", "sam", "dan", "jim", "joe", "bob", "ann", "eve", "gay", "herb", "jimmy", "lane", "march", "melody", "mercy", "merit", "nick", "norm", "paige", "patience", "peg", "polly", "ram", "read", "rock", "rod", "sol", "stew", "tab", "trip", "wick", "wolf"]);
const COMMON_SURNAME_WORDS = new Set(["rules","rule","code","state","court","courts","justice","judge","order","act","law","laws","board","bank","trust","case","motion","county","city","commission","department","office","company","corporation","association","district","school","university","hospital","insurance"]);

/** The surname of an accepted multi-token person name is an alias of the same node when it appears on its own —
 *  "Doe appealed", "Mr. Doe's counsel". MEASURED 2026-09-15 on the first live qwen3:8b run: the model proposed
 *  "John Doe" and "Judge Ramirez" and both passes then left the bare "Doe" in the output. A surname alias is
 *  derived in code, deterministically, from a name the guard already accepted; it inherits every check that
 *  name passed, and it is attached only if it actually occurs as a whole word in the text. */
export const ORG_SHAPED = /\b(?:Landfill|Site|Facility|Plant|Refinery|Mine|Field|Well|Pipeline|Terminal|Warehouse|Store|Shop|Market|Restaurant|Hotel|Motel|Apartments|Estates|Park|Ranch|Farm|Dairy|Bakery|Auto|Motors|Repair|Cleaners|Laundry|Salon|Pharmacy|Grocery|Station|Depot|Yard|Tower|Building|Complex|Mall|Plaza|Center|Centre|Administration|Council|Foundation|Institute|Society|Union|Federation|Bureau|Office|Committee|Center|Centre|Alliance|Coalition|Consortium|League|University|College|Fund|Hospital|Church|Ministry|Task Force|Consortium|Corps|Service|Services|Chamber|Coalition|Registry|Exchange|Cooperative|Guild|Network|Assembly|Congress|Senate|Tribunal|Inc|LLC|L\.L\.C|LLP|L\.P|LP|PLLC|P\.C|Ltd|Co|Corp|Corporation|Company|Companies|Association|Associates|Insurance|Department|Board|Commission|Authority|District|Agency|Bank|Trust|Group|Holdings|Partners|Partnership|Firm|Enterprises|Industries|Services|Systems|International|University|Hospital|Church|City|County|State|d\/b\/a|Underwriters)\b\.?/i;
export function derivedAliases(span: Span, text: string): string[] {
  return [...new Set([...personDerived(span, text), ...definedTerms(span, text)])];
}

/** Legal drafting DEFINES its short names: `Robert T. Evans (“Bob” or “Mr. Evans”)`, `(hereinafter "Vivian")`,
 *  `Southwest Global Logistics, Inc. (“SGL” or the “Company”)`, `(also known as “Maggie” and as “M.E.H.”)`,
 *  `(maiden name: Maria Isabel Rodriguez)`, `“Johnny” Brawley`. The live battery (2026-09-15, 41 documents) had
 *  15 leaks in exactly these shapes: the model proposed the full name and never the defined term. The definition
 *  is deterministic -- a parenthetical right after the entity -- so the terms become aliases of that entity here.
 *  Role words ("Company", "Defendant") are not names and are skipped. */
const ROLE_WORDS = new Set(["university", "college", "school", "institute", "academy", "seminary", "clinic", "center", "centre", "practice", "office", "store", "plant", "facility", "site", "relator", "relators", "intervenor", "intervenors", "garnishee", "counter-defendant", "counter-plaintiff", "counterclaimant", "cross-claimant", "cross-defendant", "cross-plaintiff", "third-party", "movants", "respondents", "petitioners", "appellants", "appellees", "claimants", "debtors", "creditors", "trustees", "witnesses", "defendant-intervenor", "plaintiff-intervenor", "government", "agency", "employer", "contractor", "subcontractor", "grantee", "grantor", "licensee", "licensor", "assignee", "assignor", "obligor", "obligee", "indemnitor", "indemnitee", "payor", "payee", "mortgagor", "mortgagee", "vendor", "vendee", "carrier", "operator", "manufacturer", "distributor", "retailer", "supplier", "purchaser", "consumer", "user", "users", "customer", "customers", "member", "members", "participant", "participants", "beneficiaries", "shareholders", "stockholders", "investors", "lenders", "borrowers", "tenants", "landlords", "owners", "parties", "signatories", "authors", "sellers", "buyers", "company", "corporation", "defendant", "defendants", "plaintiff", "plaintiffs", "respondent", "petitioner", "appellant", "appellee", "movant", "employer", "employee", "insurer", "insured", "carrier", "landlord", "tenant", "buyer", "seller", "purchaser", "lender", "borrower", "lessor", "lessee", "licensor", "licensee", "contractor", "owner", "agreement", "policy", "property", "premises", "contract", "lease", "note", "trust", "estate", "board", "bank", "city", "county", "state", "district", "court", "debtor", "creditor", "trustee", "husband", "wife", "mother", "father", "parent", "parents", "child", "children", "minor", "decedent", "executor", "executrix", "guardian", "firm", "partnership", "fund", "association", "hoa", "district", "authority", "agency", "department", "the", "a", "an", "party", "parties", "claimant", "obligor", "obligee", "guarantor", "assignee", "assignor", "settlor", "beneficiary", "successor", "vendor", "customer", "client", "manager", "member", "members", "shareholder", "stockholder", "director", "officer", "physician", "doctor", "hospital", "provider", "patient", "worker", "principal", "surety", "issuer", "holder", "seller", "spouse", "deceased", "will", "instrument", "deed", "mortgage"]);
/** A defined term whose owner is public law or a contract part ("Texas Property Code (“Code”)", "the Lease (“Premises”)") is not a name. */
const PUBLIC_OWNER = /\b(?:Letter|Letters|Email|E-mail|Memo|Memos|Correspondence|Invoice|Receipt|Permit|License|Warrant|Form|Forms|Code|Court|Rules?|Act|Statutes?|Agreement|Lease|Contract|Policy|Plan|Exhibit|Section|Article|Chapter|Title|Ordinance|Regulation|Constitution|Amendment|Note|Deed|Mortgage|Order|Motion|Petition|Complaint|Brief|Report|Schedule|Appendix|Term|Terms|Effective Date|Closing|Judgment|Ruling|Opinion|Decision|Findings|Memorandum|Notice|Stipulation|Declaration|Affidavit|Response|Reply|Objection|Application|Request|Claims?|Damages|Verdict|Award|Settlement|Release|Waiver|Consent|Certificate|Summons|Subpoena|Discovery|Interrogatories|Admissions|Production|Deposition|Transcript|Hearing|Trial|Appeal|Mandate|Docket|Case|Cause|Matter|Proceeding|Action|Suit|Dispute|Program|Project|Standard|Specification|Requirements?|Protocol|Survey|Publication|Guidelines?|Procedures?|Process|System|Method|Property|Premises|Product|Device|Software|Data|Service|Services|Funds?|Account|Loan|Benefits?|Forms?|Table|Figure|Chart|Attachment|Enclosure|Item|Line|Field|Box|Column|Row|Page|Volume|Part|Phase|Step|Level|Type|Class|Category|Series|Model|Version|Edition|Batch|Lot|Unit|Grade|Tier|Invoice|Receipt|Statement|Bill|Check|Wire|Transfer|Notices|Orders|Judgments|Motions|Petitions|Findings|Liability|Liabilities|Apparent|Forfeiture|Penalty|Penalties|Fine|Fines|Assessment|Assessments|Violation|Violations|Citation|Citations|Warning|Warnings)\b/i;
/** Words a defined TERM may not be or end in, beyond role words: filing and instrument names. */
const FILING_TERM = /\b(?:motion|petition|complaint|order|judgment|brief|agreement|contract|lease|policy|plan|exhibit|notice|report|claim|claims|response|reply|declaration|affidavit|stipulation|settlement|release|program|project|protocol|standard|survey|property|premises|product|device|software|data|service|services|fund|funds|account|loan|benefit|benefits|rule|rules|code|act|section|depo|dep|depos|tr|aff|decl|ex|exh|ans|compl|mot|resp|br|op|supp|app|doc|dkt|transcript|deposition|testimony|hearing|trial)\.?$/i;
const NOT_A_NICKNAME = new Set(["texas", "usa", "us", "uk", "california", "florida", "delaware", "york", "jr", "sr", "ii", "iii", "iv", "esq", "january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday", "emphasis", "sic", "id", "ibid", "supra", "infra", "cont", "continued", "reserved", "redacted", "sealed", "draft", "proposed", "amended", "original", "exhibit", "attached", "enclosed", "optional", "required", "approximately", "collectively", "individually", "together", "hereinafter", "defendant", "plaintiff", "respondent", "petitioner", "appellant", "appellee", "claimant", "employer", "employee", "insurer", "insured", "landlord", "tenant", "buyer", "seller", "lender", "borrower", "company", "corporation", "firm", "bank", "trust", "estate", "board", "city", "county", "state", "court", "agreement", "policy", "property", "premises", "contract", "lease", "deceased", "decedent", "minor", "child", "parent", "husband", "wife"]);
const DEFINED_TYPES = new Set(["CLIENT", "PERSON", "ATTORNEY", "JUDGE", "ORG"]);
export function definedTerms(span: Span, text: string): string[] {
  if (!DEFINED_TYPES.has(span.type)) return [];
  const out = new Set<string>();
  const name = span.text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\s+/g, "\\s+");
  // a term starts with a capital: "Brian Kolfage (\u201cthe subject statements\u201d)" defines the statements, not the man (real docket, 2026-09-16)
  const keep = (t: string) => { const v = t.trim().replace(/^(?:the|a|an)\s+/i, ""); const lastWord = (v.split(/\s+/).pop() ?? "").replace(/[,.;:()"']+$/, "").toLowerCase(); if (FILING_TERM.test(lastWord)) return; if (/^\p{Lu}/u.test(v) && v.length >= 2 && v.length <= 40 && /\p{L}/u.test(v) && !ROLE_WORDS.has(v.toLowerCase()) && v.toLowerCase() !== span.text.toLowerCase()) out.add(v); };
  // the parenthetical right after the name, up to 160 chars
  for (const m of text.matchAll(new RegExp(`${name}[,.]?\\s*\\(([^()\\n]{2,160})\\)`, "giu"))) {
    const inner = m[1];
    for (const q of inner.matchAll(/[“"‘']([^”"’'\n]{1,40})[”"’']/gu)) keep(q[1]);
    for (const q of inner.matchAll(/\b(?:maiden name|f\/k\/a|formerly known as|formerly|n\/k\/a|now known as|a\/k\/a|also known as|known as|called|hereinafter|d\/b\/a)\s*:?\s*([A-Z][^,;()"“”]{1,50}?)\s*(?=[,;)]|$| or | and )/g)) keep(q[1]);
  }
  // the same definitions in prose, within the clause: "Hector R. Delgado-Morales, and was formerly known as
  // Hector Ramirez." / "HealthCorp Group, Inc., d/b/a Methodist Health System." The name is a run of capitalised
  // tokens and initials, so "Claire M. Simpson. Ron" stops at "Simpson" and keeps the initial.
  for (const m of text.matchAll(new RegExp(`${name}[^.;\\n]{0,80}?\\b(?:formerly known as|f\\/k\\/a|a\\/k\\/a|also known as|now known as|n\\/k\\/a|d\\/b\\/a|maiden name(?: is|:)?)\\s+([A-Z][\\w'’-]+(?:[ \\t]+(?:[A-Z]\\.|[A-Z][\\w'’-]+|&|of|the)){0,5})`, "gu"))) keep(m[1]);
  // `“Johnny” Brawley`: a quoted given name glued to the surname of a person
  if (PERSON_TYPES.has(span.type)) {
    const last = span.text.replace(/[,.;:()"]/g, " ").split(/\s+/).filter((t) => t.length >= 3 && /^[A-Z]/.test(t) && !HONORIFIC.test(t)).pop();
    if (last) for (const q of text.matchAll(new RegExp(`[“"]([A-Z][\\p{L}'’-]{1,20})[”"]\\s+${last.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\p{L}\\p{N}])`, "gu"))) keep(q[1]);
  }
  return [...out];
}

/** Defined terms at DOCUMENT level: the model never proposed "ESTATE OF MARY LOUISE HARRIS", so nothing owned the
 *  parenthetical "(formerly known as Mary Louise Patterson)" and the former name walked out (live battery
 *  after-run, doc 2-3, 2026-09-15). Every name run followed by a defining parenthetical yields its terms; a term
 *  joins the node that owns the run exactly, else it becomes its own node and restores verbatim. */
export function docDefinedTerms(text: string): { owner: string; terms: string[] }[] {
  const out: { owner: string; terms: string[] }[] = [];
  // nicknames given in prose with no owner nearby: "Defendant, known to many as Cindy", "Bob, as his colleagues
  // call him" (the battery's third reading, 2026-09-15). Own node, verbatim restore.
  for (const m of text.matchAll(/\b(?:known (?:to (?:many|all|some|most|friends|colleagues|family|everyone) )?as|goes by|nicknamed|referred to as)\s+"?([A-Z][a-z]{2,20})"?(?![\w'’-])/g)) if (!NOT_A_NICKNAME.has(m[1].toLowerCase()) && !ROLE_WORDS.has(m[1].toLowerCase())) out.push({ owner: "", terms: [m[1]] });
  for (const m of text.matchAll(/\b([A-Z][a-z]{2,20}), as (?:his|her|their) (?:colleagues|friends|family|clients|coworkers|co-workers|associates) call (?:him|her|them)\b/g)) if (!NOT_A_NICKNAME.has(m[1].toLowerCase()) && !ROLE_WORDS.has(m[1].toLowerCase())) out.push({ owner: "", terms: [m[1]] });
  // a collective defined term ("Federal Government Defendants", "the State Plaintiffs", "the Parties") ends in a
  // role word and names nobody; it is not an alias of whatever preceded the parenthetical
  // (a term's last word is checked without its punctuation: "Depo." is "depo")
  const keepInto = (terms: string[], t: string) => { const v = t.trim().replace(/^(?:the|a|an)\s+/i, ""); const last = (v.split(/\s+/).pop() ?? "").replace(/[,.;:()"']+$/, "").toLowerCase(); if (/^\p{Lu}/u.test(v) && v.replace(/[^\p{L}\p{N}]/gu, "").length >= 3 && v.length <= 40 && /\p{L}/u.test(v) && !ROLE_WORDS.has(v.toLowerCase()) && !ROLE_WORDS.has(last) && !FILING_TERM.test(v) && !STOP_ALIAS.has(v.toLowerCase())) terms.push(v); };
  // the owner run admits connectors, as the caption grammar does: "National Telecommunications and Information
  // Administration (NTIA)" is one name, not "Information Administration" (real docket, 2026-09-15)
  for (const m of text.matchAll(/((?:(?:[A-Z][\p{L}\p{N}'’.&,-]*|and|of|the|for|&)[ \t]+){0,8}[A-Z][\p{L}\p{N}'’.-]*)[,.]?[ \t]*\(([^()\n]{2,160})\)/gu)) {
    const inner = m[2]; const terms: string[] = [];
    for (const q of inner.matchAll(/[“"‘']([^”"’'\n]{1,40})[”"’']/gu)) keepInto(terms, q[1]);
    for (const q of inner.matchAll(/\b(?:maiden name|f\/k\/a|formerly known as|formerly|n\/k\/a|now known as|a\/k\/a|also known as|known (?:to (?:many|all|some|friends|colleagues|family) )?as|called|hereinafter|d\/b\/a)\s*:?\s*([A-Z][^,;()"“”]{1,50}?)\s*(?=[,;)]|$| or | and )/g)) keepInto(terms, q[1]);
    // "Deborah Harper (Debbie)": a lone capitalised word in the parenthetical is a nickname, unless it is a place,
    // a month, a suffix or a role
    if (/^[A-Z][a-z]{1,20}$/.test(inner.trim()) && !NOT_A_NICKNAME.has(inner.trim().toLowerCase())) keepInto(terms, inner.trim());
    const owner = m[1].replace(/\.$/, "").replace(/^(?:and|of|the|for|&|these|this|that|those|such|said|each|every|any|all)\s+/i, "").replace(/^(?:Plaintiffs?|Defendants?|Respondents?|Petitioners?|Appellants?|Appellees?|Claimants?|Intervenors?|Movants?|Debtors?|Creditors?|Relators?|Garnishees?|Witness|Deponent|Affiant|Declarant|Applicant|Insureds?|Insurers?|Employers?|Employees?)\s+/i, "").replace(/^[A-Z]?\.?\d+(?:\.\d+)*\s+/, "").replace(/[,.]$/, "").trim();
    if (!/^[A-Z]/.test(owner) || owner.split(/\s+/).length > 8 || /\d/.test(owner)) continue;
    // "Judge Gilmore's Case Manager.", "Scarlott Depo.", "Times Now, and Zoom (collectively, the "Protected
    // Channels")": a possessive inside, a citation abbreviation at the end, a comma list, or a group definition is
    // not an entity's name (real dockets, 2026-09-15)
    if (/['’]s\b/.test(owner) && !ORG_SHAPED.test(owner)) continue;
    if (/\b(?:Depo|Dep|Tr|Aff|Decl|Ex|Exh|Ans|Compl|Mot|Resp|Br|Op|Supp|App|Pet|Def|Pl|Doc|Dkt|No|Nos|Vol|Ch|Sec|Para|Id|Ibid|Supra|Infra)\.?$/.test(owner) || /,\s+(?:and|or)\s+/.test(owner)) continue;
    if (/^\s*(?:collectively|together|jointly|individually|each|all)\b/i.test(inner)) continue;
    // "(NTIA)" after "National Telecommunications and Information Administration": an acronym whose letters are
    // the owner's initials (connectors skipped) is the owner's short name (real docket, 2026-09-15)
    // ...and only for an organisation-shaped owner: "Root Zone Key Signing Key (KSK)" and "Contracting Officer
    // (CO)" are terms of art in a government contract, not entities (real docket, 2026-09-15). Three letters at least.
    const acro = /^([A-Z]{3,8})$/.exec(inner.trim());
    // the acronym must be the owner's initials exactly ("NAL" is not "Apparent Liability", real docket 2026-09-15)
    if (acro && ORG_SHAPED.test(owner)) { const initials = owner.split(/\s+/).filter((w) => /^[A-Z]/.test(w)).map((w) => w[0]).join(""); if (initials === acro[1] || initials.replace(/[^A-Z]/g, "") === acro[1]) keepInto(terms, acro[1]); }
    if (terms.length) out.push({ owner, terms: terms.filter((t) => t.toLowerCase() !== owner.toLowerCase()) });
  }
  return out;
}

function personDerived(span: Span, text: string): string[] {
  if (!PERSON_TYPES.has(span.type)) return [];
  // a model (or the oracle) can type an organisation as PERSON; deriving "Vapor" from "RJR Vapor Co., LLC" then
  // half-substitutes "RJR Vapor Company" elsewhere and the gate refuses the whole opinion (oracle run, 2026-09-15)
  if (ORG_SHAPED.test(span.text) || span.text.split(/\s+/).length > 4) return [];
  // apostrophes and hyphens are PART of a surname ("O'Brien", "Al-Sayed"): stripping them split "O'Brien" into
  // "O" and "Brien" and derived the wrong surname (battery seed 14, 2026-09-15)
  const raw = span.text.replace(/[,.;:()"]/g, " ").split(/\s+/).filter(Boolean);
  const toks = raw.filter((t) => t.length >= 3 && /^[A-Z]/.test(t) && !HONORIFIC.test(t) && !HONORIFIC.test(t[0] + t.slice(1).toLowerCase()));
  const out0: string[] = [];
  // "Officer Kevin M. O'Brien" proposed with the rank, "Kevin M. O'Brien" written elsewhere: without the
  // rank-stripped variant only the surname matched there, "Kevin M. [PERSON_1]" was left, and the fragment rule
  // refused the document (battery seed 14, 2026-09-15). The leading honorifics come off as a variant.
  let lead = 0; const words = span.text.trim().split(/\s+/);
  while (lead < words.length - 1 && HONORIFIC.test(words[lead].replace(/[,.]$/, ""))) lead++;
  if (lead > 0) {
    const stripped = words.slice(lead).join(" ");
    // a single-token remainder is the surname itself and takes the surname's own rules below (common-word check,
    // caption check); only a multi-token remainder is a distinct variant worth adding here
    if (stripped.split(/\s+/).length > 1 && new RegExp(`(?<![\\p{L}\\p{N}])${stripped.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\s+/g, "\\s+")}(?![\\p{L}\\p{N}])`, "iu").test(text)) out0.push(stripped);
  }
  // "Judge Ramirez" is two tokens and one surname; "Cher" is one token and no surname. The honorific counts
  // toward the name having more than one part, but never becomes the alias itself.
  if (raw.length < 2 || toks.length < 1) return out0;
  const last = toks[toks.length - 1];
  const out: string[] = out0;
  // "Deborah E. Bryant" is also written "Deborah Bryant": a middle name or initial is the part writers drop, and
  // a document that does so left "Deborah [PERSON_1]" behind on the oracle run (2026-09-15, opinion 25-0131 —
  // refused by the fragment rule, which was right, but the variant should simply be an alias)
  if (raw.length >= 3 && toks.length >= 2 && toks[0] !== last) {
    const short = `${toks[0]} ${last}`;
    if (new RegExp(`(?<![\\p{L}\\p{N}])${short.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/ /g, "\\s+")}(?![\\p{L}\\p{N}])`, "iu").test(text)) out.push(short);
  }
  // The given name on its own -- "Dear Jonathan and Linda", "To: Mr. Jonathan P. Hargrove ... Jonathan" -- when the
  // text uses it standalone (not followed by another capitalised token). Live battery, 2026-09-15: 12 CLIENT
  // leaks were exactly this. Given names that are English words ("Mark", "Bill", "Grace") are not derived: the
  // substitution is case-insensitive and would take the verb with the name.
  if (toks.length >= 2 && toks[0] !== last && toks[0].length >= 3 && !COMMON_GIVEN_WORDS.has(toks[0].toLowerCase())
    && (new RegExp(`${LEFT_SINGLE}${toks[0].replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\p{L}])(?![ \\t]+[A-Z])`, "u").test(text) || camelMatches(text, toks[0]).length > 0)) out.push(toks[0]);
  if (COMMON_SURNAME_WORDS.has(last.toLowerCase())) return out;
  // a surname that is also a party of a cited case ("Justice Young" / "Young v. State") IS derived — the
  // substitution step leaves caption occurrences alone (apply.ts inCaptionAt), so the judge is scrubbed and the
  // citation survives (red-team 10e)
  // (the same left edge the substitution uses, so a glued "ExhibitBenson" derives "Benson" and is then reached)
  // case-insensitive, as the substitution is: "REL. MICHAEL N. SWETNAM, JR." spells the surname in caps
  const re = new RegExp(`${LEFT_SINGLE}${last.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\p{L}\\p{N}])`, "iu");
  if (re.test(text) || camelMatches(text, last).length > 0) out.push(last);
  return [...new Set(out)];
}

/** Attach a derived alias to its person's node — UNLESS the same token belongs to another person in the matter.
 *  Found by the property tests 2026-09-15 (seeds 11 and 100): with "Deborah Bryant" the client and "Priya Bryant"
 *  the judge, the bare "Bryant" attached to the client and "Judge Bryant" was RESTORED as "Judge Deborah Bryant" —
 *  a mis-attribution, which is worse than a leak because it reads as fact. A shared surname is still scrubbed,
 *  but as its own PERSON node, so it restores to exactly the text it was. */
/** Words that are never a name on their own, whatever derived them ("This" became a person on a real docket). */
const STOP_ALIAS = new Set(["old", "new", "north", "south", "east", "west", "big", "little", "upper", "lower", "great", "grand", "high", "low", "first", "second", "third", "this", "that", "these", "those", "the", "and", "for", "with", "from", "into", "dear", "see", "also", "here", "there", "then", "than", "when", "where", "which", "what", "who", "whom", "whose", "such", "said", "each", "every", "any", "all", "some", "none", "both", "either", "neither", "other", "another", "same", "very", "more", "most", "less", "least", "much", "many", "several", "certain", "various", "further", "however", "moreover", "therefore", "thus", "hence", "whereas", "wherefore", "now", "comes", "before", "after", "under", "upon", "within", "without", "between", "among", "against", "regarding", "concerning", "pursuant", "according", "notwithstanding", "exhibit", "exhibits", "attachment", "appendix", "schedule", "section", "article", "paragraph", "page", "pages", "line", "lines", "item", "items", "count", "counts", "claim", "claims", "cause", "causes", "action", "actions", "matter", "matters", "case", "cases", "court", "courts", "judge", "justice", "honorable", "state", "county", "city", "district", "united", "states", "america", "texas", "government", "department", "office", "agency", "board", "commission", "committee", "council", "bureau", "administration", "service", "services", "company", "corporation", "association", "bank", "trust", "estate", "fund", "group", "partners", "partnership", "firm", "law", "legal", "attorney", "attorneys", "counsel", "plaintiff", "plaintiffs", "defendant", "defendants", "respondent", "petitioner", "appellant", "appellee", "movant", "relator", "witness", "deponent", "affiant", "declarant", "decedent", "trustee", "guardian", "executor", "administrator", "process", "application", "petition", "motion", "order", "judgment", "opinion", "brief", "response", "reply", "notice", "report", "record", "transcript", "testimony", "evidence", "statement", "affidavit", "declaration", "agreement", "contract", "lease", "policy", "plan", "program", "project", "data", "dna", "covid"]);
/** A bare surname proposed AFTER its full name joins that person's node -- "Jason E. Sweet" from the signature
 *  block, then "Sweet" from the model -- when exactly ONE node owns the surname; with several owners it is its
 *  own node, as attachDerived requires (shared surnames restore verbatim). The forty-docket oracle run of
 *  2026-09-16 listed "Jason E. Sweet" on two ATTORNEY placeholders and "James Molina, Jr." on two: the second was
 *  the bare surname minted as a new node because add() only reuses an EXACT alias. */
const PERSON_LIKE = new Set(["CLIENT", "PERSON", "ATTORNEY", "JUDGE"]);
/** Returns the span as kept (a filing label on its end dropped -- "Glenn Aff" -> "Glenn" -- so the caller derives
 *  aliases from the name, not the label). */
function addSpan(graph: MatterGraph, s: Span): Span {
  if (PERSON_LIKE.has(s.type)) {
    const toks = s.text.trim().split(/\s+/);
    while (toks.length > 1 && FILING_LABEL.test(toks[toks.length - 1].replace(/[,.;:()"']+$/, ""))) toks.pop();
    if (toks.length !== s.text.trim().split(/\s+/).length) { if (!/\p{Lu}/u.test(toks.join(" "))) return s; s = { ...s, text: toks.join(" ") }; if (graph.find(s.text)) return s; }
  }
  // the same name under another honorific is the same person: "Hon. Keith P. Ellison", "Honorable Keith P.
  // Ellison", "Judge Keith P. Ellison", "Keith P. Ellison" share one node whichever arrives first
  if (PERSON_LIKE.has(s.type) && !graph.find(s.text)) {
    const core = nameCore(s.text);
    const same = graph.substitutions().find((sub) => PERSON_LIKE.has(sub.type) && nameCore(sub.alias) === core);
    if (same) { graph.add(s, same.alias); return s; }
    // the same person with the middle name spelt out, initialled, or dropped: "Darren G. Gibson" / "Darren Glenn
    // Gibson" / "Darren Gibson" -- when exactly ONE node carries such a form (two would be two people). Under the
    // regex-only model view (lesson XXIII) every spelling reaches the graph, and each had been its own node, so the
    // bare surname saw two owners and became a third (real dockets, 2026-09-16).
    const kin = new Set<string>(); let kinAlias: string | null = null;
    for (const sub of graph.substitutions()) if (PERSON_LIKE.has(sub.type) && sameName(core, nameCore(sub.alias))) { const ph = graph.find(sub.alias)!.placeholder; if (!kin.has(ph)) { kin.add(ph); kinAlias = sub.alias; } }
    if (kin.size === 1 && kinAlias) { graph.add(s, kinAlias); return s; }
  }
  // a bare surname, or an honorific and a surname ("Judge Ellison" from the JUDGE rule, "Dr. Behar"), joins the
  // one node that owns the surname under a fuller name
  // ...or a multi-word surname ("Al Hardan", "De La Cruz") that is the tail of one node's fuller name
  const sur = nameCore(s.text);
  if (PERSON_LIKE.has(s.type) && !graph.find(s.text) && sur && /^\p{Lu}/u.test(s.text.trim())) {
    const owners = new Set<string>();
    for (const sub of graph.substitutions()) { const c = nameCore(sub.alias); if (c !== sur && c.endsWith(" " + sur) && PERSON_LIKE.has(sub.type)) owners.add(sub.alias); }
    if (owners.size >= 1 && new Set([...owners].map((a) => graph.find(a)!.placeholder)).size === 1) { graph.add(s, [...owners][0]); return s; }
  }
  const node = graph.add(s);
  // A FULL name arriving after "Judge Ellison" / "Ellison" (a node whose every alias is that surname, with or
  // without an honorific) absorbs it -- when it is the only other node on the surname. With two people on the
  // surname nothing merges: a shared surname is its own node by design.
  if (PERSON_LIKE.has(s.type) && /\s/.test(s.text.trim()) && node.aliases.length === 1) {
    const sur = lastNameToken(s.text.replace(/[,.;:()"']/g, " ").trim().split(/\s+/).map((t) => t.toLowerCase()));
    if (!sur || sur.length < 3) return s;
    const byPh = new Map<string, { type: string; aliases: string[] }>();
    for (const sub of graph.substitutions()) { if (sub.placeholder === node.placeholder) continue; const e = byPh.get(sub.placeholder) ?? { type: sub.type, aliases: [] }; e.aliases.push(sub.alias); byPh.set(sub.placeholder, e); }
    const onSurname = [...byPh.values()].filter((e) => PERSON_LIKE.has(e.type) && e.aliases.some((a) => lastNameToken(a.replace(/[,.;:()"']/g, " ").trim().split(/\s+/).map((t) => t.toLowerCase())) === sur));
    // every other node on the surname is a surname-only node -> all of them are this person ("Judge Ellison" and
    // the bare "Ellison" had each been minted before the full name arrived, real docket 2026-09-16)
    if (onSurname.length && onSurname.every((e) => e.aliases.every((a) => nameCore(a) === sur))) { for (const e of onSurname) graph.link(s.text, e.aliases[0]); return s; }
    // ...and when another FULL name already owns the surname, the surname is shared from here: a bare or
    // honorific-led surname alias that had joined that person ("SPEER" on "John H. Speer") is detached onto a
    // node of its own, as a shared surname would have been from the start (three Speers on a real docket, 2026-09-16)
    if (onSurname.some((e) => e.aliases.some((a) => nameCore(a) !== sur))) {
      let bare: string | null = null;
      for (const e of onSurname) for (const a of e.aliases) if (nameCore(a) === sur && e.aliases.length > 1) { const fresh = graph.detach(a); if (fresh) { if (bare) graph.link(bare, a); else bare = a; } }
    }
  }
  return s;
}
/** Two name cores are the same person when the first and last tokens agree and every middle token agrees, is the
 *  other's initial, or is absent on one side. Single-token cores never match (a surname is handled elsewhere). */
function sameName(a: string, b: string): boolean {
  const x = a.split(" "), y = b.split(" ");
  if (x.length < 2 || y.length < 2 || x[x.length - 1] !== y[y.length - 1]) return false;
  // the shorter name's tokens appear in the longer one's, in order, each equal or an initial of the other --
  // "Faraj Al Hardan" of "Omar Faraj Saeed Al Hardan", "Darren G. Gibson" of "Darren Glenn Gibson", "Douglas
  // Swetnam" of "Douglas Scott Swetnam"; the first token need not agree ("Faraj" is a middle name used as a given
  // name on a signature block, real docket 2026-09-16), the surname always must
  const [short, long] = x.length <= y.length ? [x, y] : [y, x];
  const same = (p: string, q: string) => p === q || (p.length === 1 && q[0] === p) || (q.length === 1 && p[0] === q);
  let j = 0; for (const t of short) { while (j < long.length && !same(t, long[j])) j++; if (j >= long.length) return false; j++; }
  return true;
}
/** the comparable core of a person alias: no leading honorific, no trailing generational or professional suffix,
 *  no punctuation, one case -- "Hon. Keith P. Ellison" = "Keith P. Ellison", "James Molina, Jr." = "James Molina",
 *  "ROBERT A. BEHAR, M.D." = "Robert A. Behar" */
function nameCore(alias: string): string {
  const toks = honorificFree(alias).replace(/\./g, "").replace(/[,;:()"']/g, " ").trim().split(/\s+/).map((t) => t.toLowerCase());
  while (toks.length > 1 && /^(?:jr|sr|ii|iii|iv|esq|md|phd|dds|cpa|jd|rn|pe)$/.test(toks[toks.length - 1])) toks.pop();
  return toks.join(" ");
}
/** The alias hints a chunk needs: only aliases sharing a name token (3+ letters, not a stop word) with the text the
 *  model is reading, longest first, capped. MEASURED 2026-09-16 on the box run: with the whole graph as hints, a
 *  1,023-node matter made the pass-1 prompt 51,000 characters around a 4,000-character chunk (92% hints), per-chunk
 *  model time rose with the matter's size, and a 1,494-party docket would push the prompt past the model's 32k-token
 *  context. A hint whose tokens are nowhere in the chunk can neither be reused nor linked by coref in it. */
export const MAX_HINTS = 200;
export function relevantHints(graph: MatterGraph, text: string): { alias: string; placeholder: string }[] {
  const present = new Set((text.match(/\p{L}[\p{L}'’-]{2,}/gu) ?? []).map((t) => t.toLowerCase()));
  return graph.aliasHints().filter((h) => (h.alias.match(/\p{L}[\p{L}'’-]{2,}/gu) ?? []).some((t) => { const k = t.toLowerCase(); return present.has(k) && !STOP_ALIAS.has(k); })).slice(0, MAX_HINTS);
}
/** the name without its leading honorifics: "Hon. Keith P. Ellison" -> "Keith P. Ellison"; "Judge Ellison" -> "Ellison" */
function honorificFree(alias: string): string {
  const toks = alias.trim().split(/\s+/); let i = 0;
  while (i < toks.length - 1 && HONORIFIC.test(toks[i]) && !/^(?:the|of|and|inc|llc|llp|lp|co|corp|ltd|plc)\.?$/i.test(toks[i])) i++;
  return toks.slice(i).join(" ");
}
/** the surname of a tokenised name: the last token that is not a generational suffix */
function lastNameToken(parts: string[]): string | undefined { return [...parts].reverse().find((t) => !/^(?:jr|sr|ii|iii|iv|esq|md|phd)$/.test(t)); }

export function attachDerived(graph: MatterGraph, alias: string, owner: Span): void {
  // two characters name nothing ("CO", "IP" on a real docket, 2026-09-15): never an alias, whatever derived it
  if (alias.replace(/[^\p{L}\p{N}]/gu, "").length < 3 || STOP_ALIAS.has(alias.trim().toLowerCase())) return;
  const tok = alias.toLowerCase();
  const claimants = new Set<string>();
  for (const sub of graph.substitutions()) {
    if (sub.alias.toLowerCase() === owner.text.toLowerCase()) continue;
    // a person's surname is shared only with another PERSON: the firm "SCOTT PATTON PC" is not a second owner of
    // attorney Dwight W. Scott's surname (live box run, 2026-09-16: "SCOTT" became its own node beside his)
    if (PERSON_LIKE.has(owner.type) && !PERSON_LIKE.has(sub.type)) continue;
    const parts = sub.alias.replace(/[,.;:()"']/g, " ").split(/\s+/).map((t) => t.toLowerCase());
    if (parts.includes(tok) && parts.length > 1) claimants.add(sub.placeholder);
  }
  const ownerNode = graph.find(owner.text);
  const others = [...claimants].filter((p) => p !== ownerNode?.placeholder);
  // a rival that is only this surname under an honorific ("Judge Ellison" minted by the JUDGE rule before the full
  // name) is not another person: it is linked into the owner and the surname attaches (real docket, 2026-09-16)
  const aliasesOf = (p: string) => graph.substitutions().filter((x) => x.placeholder === p).map((x) => x.alias);
  const rivals = others.filter((p) => !aliasesOf(p).every((a) => nameCore(a) === tok));
  if (rivals.length) { graph.add({ text: alias, type: "PERSON" }); return; } // ambiguous: own node, verbatim restore
  if (ownerNode) for (const p of others) graph.link(owner.text, aliasesOf(p)[0]);
  // SURNAME FIRST: "Strickling" was proposed on an early chunk and got its own node; the full name arrived later.
  // A bare-surname node nobody else claims is the same person, so the two are linked (real docket, 2026-09-15:
  // "Lawrence E. Strickling" split across [PERSON_2] and [PERSON_3]).
  const existing = graph.find(alias);
  if (existing && ownerNode && existing !== ownerNode && existing.aliases.every((a) => !/\s/.test(a.trim()))) { if (graph.link(owner.text, alias)) return; }
  graph.add({ text: alias, type: owner.type }, owner.text);
}

/** Fold each span's text (and each coref key/value) the way the document was folded. Never the JSON itself. */
export function foldProposal(p: ReturnType<typeof parseProposal>): ReturnType<typeof parseProposal> {
  if (!p) return p;
  const spans = p.spans.map((s) => (s && typeof s === "object" && typeof (s as { text?: unknown }).text === "string") ? { ...(s as object), text: normalizeInput((s as { text: string }).text).text } : s);
  const coref: Record<string, string> = {};
  for (const [k, v] of Object.entries(p.coref)) coref[normalizeInput(k).text] = normalizeInput(v).text;
  return { ...p, spans, coref };
}

export const MAX_PROPOSAL_SPANS = 80;   // = PROPOSAL_SCHEMA spans.maxItems
export const MAX_PASS1_ROUNDS = 6;      // a 4k chunk naming 480 entities is a party list, and it still gets there
export type LocalModel = (prompt: string, format: unknown) => Promise<string>;

export const MAX_DOC_CHARS = 60_000;

/** Run one document through the graph. Mutates `graph` (that is the point: the matter accumulates). Throws only
 *  when the document must not leave — a residual alias after substitution — never on a model failure, which is
 *  degraded to "regex-only" and reported in `stats` so the ledger shows it. */
export async function scrambleDocument(rawDoc: string, graph: MatterGraph, model: LocalModel | null): Promise<ScrambleResult & { degraded: string[]; verdict_leaks: number; normalized: Record<string, number> }> {
  if (rawDoc.length > MAX_DOC_CHARS) throw new Error(`document too large for one pass (${rawDoc.length} > ${MAX_DOC_CHARS}); split by section first (node 0: minimize)`);
  // node 0.5 — fold confusables BEFORE anything reads the text: NFKC, zero-width and invisible characters,
  // mixed-script homoglyphs, typographic quotes. Adopted from the five-model review 2026-09-15: the red-team
  // shows variant spellings are handled one by one; folding them on the way in removes the class. The output is
  // the folded document — a Cyrillic "о" in a client's name never reaches the frontier in either form.
  const norm = normalizeInput(rawDoc); const doc = norm.text;
  // node 0.6 -- the input gate: a raw document carrying anything placeholder-shaped is refused before any model
  // sees it. That is what lets the OUTPUT gate treat a placeholder hugged by brackets as editorial prose.
  const rawLook = inputLookalikes(doc);
  if (rawLook.length) throw new Error(`refusing to release: ${rawLook.length} placeholder look-alike token(s) in the INPUT: ${[...new Set(rawLook)].slice(0, 5).map((t) => JSON.stringify(t)).join(" ")}`);
  const degraded: string[] = []; const rejected: Rejection[] = []; const accepted: Span[] = [];

  // node 1 — regex. Deterministic, first, and the model is told these are gone.
  // a regex-class person or organisation gets its derived aliases too (surname, defined terms): "Southwest Global
  // Logistics, Inc. ("SGL")" is taken by the suffix rule before the model sees it, and "SGL" must follow it
  const regexAccepted = regexSpans(doc);
  const regexKept = regexAccepted.map((s) => { const t = addSpan(graph, s); accepted.push(t); return t; });
  let text = scramble(doc, graph);
  // THE MODEL'S VIEW: the document with the regex-class identifiers gone and every NAME still visible. Scrubbing
  // the names of earlier chunks too (as the first build did) hid a second person of a known surname: once "SPEER"
  // was an alias, "Donnie Lou Speer" reached the model as "Donnie Lou [PERSON_1]", the given-name extension
  // absorbed the given names into the first Speer's placeholder, and the model could never propose the name
  // (lesson XXIII, 2026-09-16). The alias hints still tell the model what is known.
  const view = () => scramble(doc, graph, (t) => REGEX_TYPES.has(t));

  // node 2 — local model proposes spans on the ALREADY regex-scrubbed text, so it cannot re-propose an SSN.
  let pass1_rounds = 1;
  if (model) {
    const n = nonce();
    let proposal: ReturnType<typeof parseProposal> = null; let salvagedNote: string | null = null;
    // One retry on an empty or unparseable response. Measured 2026-09-15 on the first liaison run: a chunk that
    // parsed to 29 spans when called directly came back unparseable once inside the run — a transient, and a
    // whole chunk should not go out regex-only over one. The reason records the raw length so the ledger can tell
    // "empty" from "truncated".
    for (let attempt = 1; attempt <= 2 && !proposal; attempt++) {
      try {
        const seen0 = view(); const raw = await model(pass1Prompt(seen0, relevantHints(graph, seen0), n), PROPOSAL_SCHEMA);
        // proposals are folded the same way as the document, so a model that copies a confusable spelling still
        // matches -- but PER SPAN, after parsing. Folding the raw JSON turned the typographic quotes in
        // "Robert “Bob” A. Nguyen" into ASCII quotes inside a JSON string, the whole proposal became
        // unparseable, and the chunk went out regex-only with eight secrets in it (battery seed 37, 2026-09-15).
        proposal = foldProposal(parseProposal(raw));
        if (!proposal) degraded.push(`pass1 attempt ${attempt}: unparseable proposal (${raw.length} chars)`);
        else if (proposal.salvaged !== undefined) salvagedNote = `pass1: output truncated at ${raw.length} chars, ${proposal.salvaged} complete span(s) salvaged`;
      } catch (e) { degraded.push(`pass1 attempt ${attempt}: ${(e as Error).message.slice(0, 80)}`); }
    }
    if (proposal && degraded.length) degraded.length = 0; // the retry succeeded: not degraded, though the ledger saw the attempt
    if (!proposal) degraded.push("pass1: no parseable proposal after retry");
    // A salvaged proposal is still degraded — the torn tail may have held spans — but it is far from regex-only,
    // and pass 2 runs on it precisely to catch what the tail lost.
    if (salvagedNote) degraded.push(salvagedNote);
    const prop = proposal;
    if (prop) {
      const seen1 = view(); const v = validateSpans(seen1, prop.spans); rejected.push(...v.rejected);
      // 1. every accepted span becomes a node; 2. coref claims LINK existing nodes (both strings must be in the
      // input and both must already be accepted, so a coref cannot smuggle a span in, and a cycle or a self-
      // reference is a no-op); 3. surnames are derived in code. Order matters: a coref applied at add-time
      // depended on which alias the model listed first and left a cycle as two nodes (red-team 7c).
      let fresh = 0; for (const s of v.accepted) { if (!graph.find(s.text)) fresh++; addSpan(graph, s); accepted.push(s); }
      for (const [a, b] of Object.entries(prop.coref)) if (seen1.includes(a) && seen1.includes(b)) graph.link(a, b);
      for (const s of v.accepted) for (const a of derivedAliases(s, doc)) attachDerived(graph, a, s);
      text = scramble(doc, graph);
      // A FULL proposal means the chunk had more entities than one call may return (the schema caps spans at 80;
      // a CERCLA party list names 1,494). While the proposal is full and accepting, pass 1 runs again on the
      // re-scrubbed text, so the next call sees only what is left. Bounded; each round is ledgered.
      // (full AND still finding NEW entities: a model that re-lists the known names fills its 80 without progress)
      let full = prop.spans.length >= MAX_PROPOSAL_SPANS && fresh > 0;
      for (let round = 2; full && round <= MAX_PASS1_ROUNDS; round++) {
        try {
          const seenN = view(); const raw = await model(pass1Prompt(seenN, relevantHints(graph, seenN), n), PROPOSAL_SCHEMA);
          const more = foldProposal(parseProposal(raw)); if (!more) break;
          const v2 = validateSpans(seenN, more.spans); rejected.push(...v2.rejected);
          let fresh2 = 0; for (const s of v2.accepted) { if (!graph.find(s.text)) fresh2++; addSpan(graph, s); accepted.push(s); }
          for (const s of v2.accepted) for (const a of derivedAliases(s, doc)) attachDerived(graph, a, s);
          if (v2.accepted.length) text = scramble(doc, graph);
          pass1_rounds = round;
          full = more.spans.length >= MAX_PROPOSAL_SPANS && fresh2 > 0;
        } catch (e) { degraded.push(`pass1 round ${round}: ${(e as Error).message.slice(0, 80)}`); break; }
      }
    }
  } else degraded.push("no local model: regex-only");
  // The regex-class people and organisations derive AFTER the model's spans are in, so a surname shared with a
  // model-proposed person ("Judge Bryant" by the honorific rule, "Deborah Bryant" by the model) is seen as
  // shared and gets its own node, as attachDerived requires; derived first, the judge would own "Bryant".
  // (an alias attached to an existing node does not change the node count, so the re-substitution is unconditional)
  if (regexKept.length) { for (const s of regexKept) for (const a of derivedAliases(s, doc)) attachDerived(graph, a, s); text = scramble(doc, graph); }
  // LATE name anchors (patterns.ts): "Ms. Peterson", "Mr. James A. Wilson", "the Decedent, X,". Each joins the node
  // that owns its surname when exactly one does; with none, or several, it is its own node (verbatim restore).
  {
    let added = false;
    const lastTok = (t: string) => t.replace(/[,.;:()"']/g, " ").trim().split(/\s+/).filter((x) => /^[A-Z]/.test(x) && !HONORIFIC.test(x)).pop()?.toLowerCase();
    for (const s of lateNameSpans(doc)) {
      if (graph.find(s.text) || STOP_ALIAS.has(s.text.trim().toLowerCase()) || s.text.trim().split(/\s+/).every((w) => STOP_ALIAS.has(w.toLowerCase()))) continue;
      const last = lastTok(s.text); if (!last) continue;
      // "Hon. Keith P. Ellison", "Judge Ellison": the name without its honorific is already an alias -> same node.
      // (On a real docket, 2026-09-16, one judge sat on FOUR placeholders: "Judge Keith P. Ellison", "Judge
      // Ellison", "Hon. Keith P. Ellison", "Honorable Keith P. Ellison" -- each honorific form counted every other
      // as a rival claimant of the surname and minted its own node.)
      const core = honorificFree(s.text); const coreNode = core !== s.text.trim() ? graph.find(core) : null;
      if (coreNode) { graph.add({ text: s.text, type: coreNode.type }, coreNode.aliases[0]); accepted.push(s); added = true; continue; }
      // a late name with a GIVEN name of its own joins only a node whose name it matches (addSpan: same core, a
      // middle spelt or initialled, a surname-only node); "Luis Delgado" had joined "Rodolfo Rudy Delgado" on the
      // surname alone (real docket, 2026-09-16). A bare or honorific-led surname still joins the surname's one owner.
      const claimants = new Set<string>();
      for (const sub of graph.substitutions()) if (lastTok(sub.alias) === last) claimants.add(sub.placeholder);
      const surnameOnly = !nameCore(s.text).includes(" ");
      if (surnameOnly && claimants.size === 1) { const owner = graph.substitutions().find((x) => x.placeholder === [...claimants][0])!; graph.add({ text: s.text, type: graph.find(owner.alias)!.type }, owner.alias); }
      else { const t = addSpan(graph, s); for (const a of derivedAliases(t, doc)) attachDerived(graph, a, t); }
      accepted.push(s); added = true;
    }
    if (added) text = scramble(doc, graph);
  }
  // document-level defined terms: owned by the node whose alias IS the name run (or the run's tail), else their own
  {
    let added = false;
    for (const { owner, terms } of docDefinedTerms(doc)) {
      if (!terms.length || (owner && (PUBLIC_OWNER.test(owner) || isSovereign(owner)))) continue;
      let node = (owner ? graph.find(owner) : null) ?? graph.substitutions().filter((x) => /\s/.test(x.alias.trim()) && owner.toLowerCase().endsWith(x.alias.toLowerCase())).map((x) => graph.find(x.alias)).find(Boolean) ?? null;
      // an owner no node claims is an entity the model missed ("ESTATE OF MARY LOUISE HARRIS"): it gets its own
      // node, so its defined names join IT and a derived surname from someone else cannot take its tail
      // "Defendant (Cindy)": a role word owns nothing; the term is its own node. Otherwise an unclaimed owner
      // becomes a node and its terms join it.
      // a capitalised run of five or more words with no connective and no organisation word is a term of art, and
      // so is what it defines: "the Head Eyes Ears Neck Throat (hereinafter, referred to as \u201cHEENT\u201d)" became
      // [PERSON_15] on a real docket (2026-09-16); "ESTATE OF MARY LOUISE HARRIS" keeps its "OF" and stays a name
      if (owner && owner.trim().split(/\s+/).length >= 5 && !ORG_SHAPED.test(owner) && !/\b(?:of|and|for|the|de|del|la|y)\b|&/i.test(owner)) continue;
      const roleOwner = !owner || ROLE_WORDS.has(owner.toLowerCase()) || /^[A-Z][a-z]+$/.test(owner) && ROLE_WORDS.has(owner.toLowerCase());
      // (through addSpan, so an owner that is a fuller form of an existing node joins it: "Daniel J. Garcia (\u201cDefendant\u201d)" after a caps
      // caption's "GARCIA" sat on a second placeholder across a real docket, 2026-09-16)
      // (the owner may come back trimmed -- "Weaver Depo" -> "Weaver" -- and is looked up under the text kept; proof
      // run 11, 2026-09-16, crashed three filings looking it up under the label)
      if (!node && !roleOwner && /\s/.test(owner)) { const kept = addSpan(graph, { text: owner, type: ORG_SHAPED.test(owner) ? "ORG" : "PERSON" }); node = graph.find(kept.text); if (node) { accepted.push({ text: kept.text, type: node.type }); added = true; } }
      for (const t of terms) {
        if (graph.find(t)) continue;
        if (node) graph.add({ text: t, type: node.type }, node.aliases[0]); else graph.add({ text: t, type: "PERSON" });
        accepted.push({ text: t, type: node ? node.type : "PERSON" }); added = true;
      }
    }
    if (added) text = scramble(doc, graph);
  }

  // node 3 — verification pass on the scrambled text. Leaks it reports go through the SAME guard; nothing it
  // says is trusted more than pass 1 just because it is second.
  let verdict_leaks = 0;
  if (model && degraded.every((d) => d.startsWith("pass1: output truncated"))) {
    const n = nonce();
    try {
      const raw = await model(pass2Prompt(text, n), VERDICT_SCHEMA);
      const j = JSON.parse(raw) as { leaks?: unknown };
      if (Array.isArray(j.leaks)) j.leaks = j.leaks.map((l) => (l && typeof l === "object" && typeof (l as { text?: unknown }).text === "string") ? { ...(l as object), text: normalizeInput((l as { text: string }).text).text } : l);
      const v = validateSpans(text, j.leaks); rejected.push(...v.rejected); verdict_leaks = v.accepted.length;
      for (const s of v.accepted) { addSpan(graph, s); accepted.push(s); for (const a of derivedAliases(s, doc)) attachDerived(graph, a, s); }
      if (v.accepted.length) text = scramble(doc, graph);
    } catch (e) { degraded.push(`pass2: ${(e as Error).message.slice(0, 80)}`); }
  }

  // node 4 — the gate. The regex sweep re-runs on the output; any alias still present means the document does
  // not leave. This is the one place the pipeline refuses rather than degrades.
  const residual = residualAliases(text, graph);
  if (residual.length) throw new Error(`refusing to release: ${residual.length} accepted alias(es) still present after substitution (${residualTypes(residual, graph)})`);
  // an identifier the INPUT pass took and the substitution failed to reach: refuse. A regex hit that exists only
  // in the output (a context rule judged differently once a neighbour became a placeholder) is not one.
  const inputRegex = new Set(regexAccepted.map((s) => s.text));
  const leftover = regexSpans(text).filter((s) => !/\[[A-Z]+_\d+\]/.test(s.text) && inputRegex.has(s.text) && !onlyInCaptions(text, s.text));
  if (leftover.length) throw new Error(`refusing to release: regex pass finds ${leftover.length} identifier(s) in the output (${leftover.map((s) => s.type).join(", ")})`);
  // A token that LOOKS like a placeholder but is not one — "[CLIENT_1]]", "CLIENT_1", "_1" — could confuse the
  // frontier or the un-scramble step and cannot be told apart from an attack on the mapping (red-team 4, 9a).
  const lookalikes = placeholderLookalikes(text);
  // the tokens are named in the error: they are placeholder-shaped by definition, never a name or identifier
  if (lookalikes.length) throw new Error(`refusing to release: ${lookalikes.length} placeholder look-alike token(s) in the output: ${[...new Set(lookalikes)].slice(0, 5).map((t) => JSON.stringify(t)).join(" ")}`);

  const stats: ScrambleResult["stats"] = {};
  for (const s of accepted) stats[s.type] = (stats[s.type] ?? 0) + 1;
  // The FINAL substitution, with its ledger, against the RAW document when the only folds were typographic
  // (quotes, NBSP -- flex() matches those), so the document restores to its own bytes; when the input carried
  // invisible or confusable characters the folded text is the basis and the result says so. The raw output is
  // re-gated: nothing is released on the raw basis that the gate has not seen.
  const final = finalSubstitution(rawDoc, doc, norm.kinds, graph);
  if (final.basis === "normalized" && final.text !== text) throw new Error("scrambler: the final substitution differs from the gated text");
  return { scrambled: final.text, occurrences: final.occurrences, restore_basis: final.basis, accepted, rejected, stats, degraded, verdict_leaks, normalized: norm.kinds, pass1_rounds };
}

/** The TYPES of the residual aliases, for the refusal message: a type and a token count say what class of
 *  thing the gate caught ("PHONE, 1 word") without the ledger ever carrying the value. */
function residualTypes(residual: string[], graph: MatterGraph): string {
  return residual.map((a) => `${graph.find(a)?.type ?? "?"}, ${a.trim().split(/\s+/).length} word(s)`).join("; ");
}

/** A regex identifier whose every occurrence sits inside a cited caption ("Varsity Gold, Inc. v. Lunenfeld, No.
 *  CCB-08-550, 2008 WL 5243517") is public law: the substitution leaves it there on purpose, so the gate must not
 *  count it as a leftover (real docket, 2026-09-15). */
function onlyInCaptions(text: string, needle: string): boolean {
  let i = text.indexOf(needle); if (i < 0) return false;
  while (i >= 0) { if (!inCaptionAt(text, i, i + needle.length)) return false; i = text.indexOf(needle, i + needle.length); }
  return true;
}

/** Quote and NBSP folds are the only ones the alias matcher tolerates on its own (flex(): straight or typographic
 *  apostrophes and quotes, any whitespace run); invisibles, NFKC and homoglyphs are not, and a name carrying one
 *  would slip a raw-text match. */
const RAW_SAFE_KINDS = new Set(["quote", "nbsp"]);
export function finalSubstitution(raw: string, folded: string, kinds: Record<string, number>, graph: MatterGraph): { text: string; occurrences: Occurrence[]; basis: "raw" | "normalized" } {
  // an NFKC fold that touched no letter or digit ("…" -> "...", "—" -> "-") changes nothing a name is matched by,
  // so the raw basis stays; a fold inside a word (a ligature, a confusable) does not
  const lettersUnchanged = raw.replace(/[^\p{L}\p{N}]/gu, "") === folded.replace(/[^\p{L}\p{N}]/gu, "");
  if (Object.keys(kinds).every((k) => RAW_SAFE_KINDS.has(k) || (k === "nfkc" && lettersUnchanged))) {
    const r = scrambleWithLedger(raw, graph);
    if (!residualAliases(r.text, graph).length && !regexSpans(r.text).some((s) => !/\[[A-Z]+_\d+\]/.test(s.text)) && !placeholderLookalikes(r.text).length) return { ...r, basis: "raw" };
  }
  return { ...scrambleWithLedger(folded, graph), basis: "normalized" };
}

/** Re-substitute every chunk of a multi-chunk document with the graph as it stands AFTER the last chunk, and
 *  gate the result again. MEASURED 2026-09-15 on the real model, opinion 24-0052: "VELO" was proposed in a late
 *  chunk and survived 15 times in the chunks emitted before the graph knew it. A document is one matter; what
 *  the model learns on page 9 has to apply to page 1. Deterministic, no model call, the same release gate. */
export function finalizeChunks(chunks: string[], graph: MatterGraph): string[] { return finalizeChunksWithLedger(chunks, graph).map((x) => x.text); }
export function finalizeChunksWithLedger(chunks: string[], graph: MatterGraph): { text: string; occurrences: Occurrence[]; basis: "raw" | "normalized" }[] {
  return chunks.map((c) => {
    const n = normalizeInput(c);
    const { text, occurrences, basis } = finalSubstitution(c, n.text, n.kinds, graph);
    const residual = residualAliases(text, graph);
    if (residual.length) throw new Error(`refusing to release: ${residual.length} accepted alias(es) still present after the final pass (${residualTypes(residual, graph)})`);
    const lookalikes = placeholderLookalikes(text);
    if (lookalikes.length) throw new Error(`refusing to release: ${lookalikes.length} placeholder look-alike token(s) after the final pass: ${[...new Set(lookalikes)].slice(0, 5).map((t) => JSON.stringify(t)).join(" ")}`);
    return { text, occurrences, basis };
  });
}

export { MatterGraph } from "./graph";
export { unscramble, renderAnswer, restoreDocument, type Occurrence } from "./apply";
