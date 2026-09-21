import { test } from "node:test";
import assert from "node:assert/strict";
import { regexSpans, lateNameSpans, luhnValid, ibanValid } from "../src/patterns";
import { MatterGraph, scrambleDocument, unscramble } from "../src";

/* THE REGEX PASS, CLASS BY CLASS. Review 2026-09-15 ("New, and adopted", item 1) named identifier classes real
 * filings carry that the deterministic pass missed: bar numbers, Bates numbers, EIN/TIN, passports, VINs, plates,
 * medical record numbers; cards, IBANs and driver's licences belong to the same family. Every pattern here is
 * anchored by a context word or a shape that public law never takes, and every one has a negative that is a
 * statute section, a reporter cite, a docket, a year, a ZIP, a dollar amount or a Rule number. */

const texts = (t: string) => regexSpans(t).map((s) => s.text);
const accounts = (t: string) => regexSpans(t).filter((s) => s.type === "ACCOUNT").map((s) => s.text);

// ---- the fixture from tests/scrambler.test.ts must yield exactly what it yielded before this file existed ----------
const DOC = `Plaintiff John Doe (DOB: 03/14/1971, SSN 123-45-6789) sued Acme Widgets, Inc. in Cause No. 25-DCV-358159.
Mr. Doe's counsel, Maria Salinas of Salinas & Jones LLP, may be reached at msalinas@sjlaw.com or (713) 555-0142.
The court relied on Ethyl Corp. v. Daniel Constr. Co., 725 S.W.2d 705 (Tex. 1987) and Tex. Bus. & Com. Code § 15.50.
Judge Ramirez denied the motion. Doe appealed.`;

test("the original fixture yields exactly the spans it yielded before the new classes were added (measured against HEAD; the honorific rule now takes the judge)", () => {
  assert.deepEqual(regexSpans(DOC), [
    { text: "123-45-6789", type: "SSN" }, { text: "Acme Widgets, Inc.", type: "ORG" }, { text: "Salinas & Jones LLP", type: "ORG" }, { text: "Judge Ramirez", type: "JUDGE" }, { text: "msalinas@sjlaw.com", type: "EMAIL" }, { text: "(713) 555-0142", type: "PHONE" }, { text: "03/14/1971", type: "DOB" }, { text: "25-DCV-358159", type: "DOCKET" }]);
});

// ---- public law that no new pattern may touch, one negative per shape the task named ------------------------------
test("statute sections are not identifiers", () => {
  assert.deepEqual(texts("Limitations runs under § 16.004. See Tex. Civ. Prac. & Rem. Code § 38.001 and Tex. Bus. & Com. Code § 15.50."), []);
  assert.deepEqual(texts("Tex. Fam. Code §§ 261.101-261.1055 govern reporting. 42 U.S.C. § 1983. 6 Del. C. § 2708."), []);
});
test("reporter citations are not identifiers", () => {
  assert.deepEqual(texts("Ethyl Corp. v. Daniel Constr. Co., 725 S.W.2d 705 (Tex. 1987); 123 F.3d 456; 4 Cal. Rptr. 3d 249."), []);
});
test("docket numbers stay DOCKET and are not doubled as ACCOUNT by the Bates or EIN shapes", () => {
  assert.deepEqual(regexSpans("in Cause No. 25-DCV-358159 and No. 22-50123"), [{ text: "25-DCV-358159", type: "DOCKET" }, { text: "No. 22-50123", type: "DOCKET" }]);
  assert.deepEqual(accounts("Civil Action 4:21-CV-01234; No. 4:21-cv-01234-ABC"), [], "an upper-cased federal docket is not Bates");
});
test("years are not identifiers", () => {
  assert.deepEqual(texts("Acts 1985, 69th Leg., ch. 959, § 1, eff. Sept. 1, 1985. The 2024-2025 term. Filed in 2023."), []);
});
test("ZIP codes are not identifiers (a full street address is, since addresses became regex-class)", () => {
  assert.deepEqual(texts("P.O. Box 12548, Austin, TX 78711-2548. Houston, Texas 77002."), []);
  assert.deepEqual(regexSpans("201 W. 14th St., Austin, TX 78701-1234.").map((s) => s.type), ["ADDRESS"], "the address, never the bare ZIP");
});
test("dollar amounts are not identifiers", () => {
  assert.deepEqual(texts("damages of $1,234,567.89, a $4,111,111,111,111,111.00 judgment, $12-3456789 (a typo) and 1,234,567,890,123 units"), []);
});
test("Rule numbers are not identifiers", () => {
  assert.deepEqual(texts("Rule 91a; Tex. R. Civ. P. 91a; Fed. R. Civ. P. 12(b)(6); Rule 166a(c); Local Rule 7.1"), []);
});

// ---- bar numbers -------------------------------------------------------------------------------------------------
test("bar numbers: announced by 'State Bar No.', 'Bar No.', 'SBOT', 'TBN', 'Bar Card No.', 'Federal I.D. No.'", () => {
  assert.deepEqual(accounts("Maria Salinas, State Bar No. 24012345"), ["24012345"]);
  assert.deepEqual(accounts("Bar No. 12345678"), ["12345678"]);
  assert.deepEqual(accounts("SBOT 24012345"), ["24012345"]);
  assert.deepEqual(accounts("TBN: 00792345"), ["00792345"]);
  assert.deepEqual(accounts("Texas Bar Card No. 24012345"), ["24012345"]);
  assert.deepEqual(accounts("Federal I.D. No. 1234567"), ["1234567"]);
  assert.deepEqual(accounts("State Bar of Texas No. 24012345"), [], "an unusual phrasing is a miss, never a false hit");
});
test("bar numbers: a Rule, a year after 'bar', or a nine-digit run are not bar numbers", () => {
  assert.deepEqual(texts("under Rule 91a the bar date was set in 2024; Bar No. 2024; Bar No. 123456789"), []);
});

// ---- Bates numbers -----------------------------------------------------------------------------------------------
test("Bates: bare prefixed runs, underscore or dash joined, ranges, and the announced form", () => {
  assert.deepEqual(accounts("See ABC000123."), ["ABC000123"]);
  assert.deepEqual(accounts("produced as DEF_00045 and DEF-00046"), ["DEF_00045", "DEF-00046"]);
  assert.deepEqual(accounts("Bates No. 000123"), ["000123"]);
  assert.deepEqual(accounts("Bates-stamped PLTF0001234"), ["PLTF0001234"]);
  assert.deepEqual(accounts("SMITH000001–SMITH000045"), ["SMITH000001–SMITH000045"]);
  assert.deepEqual(accounts("Bates range DEF_00045 - DEF_00051"), ["DEF_00045 - DEF_00051"]);
});
test("Bates: a docket, a bill number, a standard, a short code and a docket inside a cited case are not Bates", () => {
  assert.deepEqual(accounts("Cause No. 25-DCV-358159"), []);
  assert.deepEqual(texts("HB 1234; SB 4; ISO 9001; RFC2616; COVID19; Form W2; LLC 2024"), []);
  assert.deepEqual(texts("Smith v. Jones, CIV-123456 (Tex. 2020) is on point."), [], "a cited case's docket-shaped number is public law");
  assert.deepEqual(accounts("Acme sued in CIV-123456 last year."), ["CIV-123456"], "the same shape outside a citation is this matter's identifier");
});

// ---- EIN / TIN ----------------------------------------------------------------------------------------------------
test("EIN: the bare 2-7 shape, and the announced forms with or without the hyphen", () => {
  assert.deepEqual(accounts("Acme Widgets, Inc., 12-3456789"), ["12-3456789"]);
  assert.deepEqual(accounts("EIN 12-3456789"), ["12-3456789"], "announced and bare forms de-duplicate to one span");
  assert.deepEqual(accounts("Employer Identification Number: 123456789"), ["123456789"]);
  assert.deepEqual(accounts("Tax ID No. 98-7654321; FEIN: 11-2233445"), ["98-7654321", "11-2233445"]);
});
test("EIN: an SSN, a ZIP+4, a phone, a section range and a five-digit docket are not EINs", () => {
  assert.deepEqual(regexSpans("SSN 123-45-6789, Austin, TX 78711-2548, (713) 555-0142, §§ 261.101-261.1055, No. 22-50123"),
    [{ text: "123-45-6789", type: "SSN" }, { text: "(713) 555-0142", type: "PHONE" }, { text: "No. 22-50123", type: "DOCKET" }]);
  assert.deepEqual(texts("a run of 12-3456789.5 units or 12-34567890"), [], "the shape must be exact: not a prefix of a longer number");
});

// ---- passports ---------------------------------------------------------------------------------------------------
test("passport: nine digits or letter-plus-eight, only after the word", () => {
  assert.deepEqual(accounts("Passport No. 123456789"), ["123456789"]);
  assert.deepEqual(accounts("U.S. Passport A12345678, issued 2022"), ["A12345678"]);
  assert.deepEqual(accounts("passport number: 987654321"), ["987654321"]);
});
test("passport: the word alone, a year after it, or a bare nine-digit run is not a passport number", () => {
  assert.deepEqual(texts("her passport was renewed in 2019; the passport expired; account balance 123456789 is a number with no context word"), []);
});

// ---- VINs -----------------------------------------------------------------------------------------------------------
test("VIN: 17 characters from the I/O/Q-free alphabet after 'VIN' or the spelled-out form", () => {
  assert.deepEqual(accounts("VIN 1HGCM82633A004352"), ["1HGCM82633A004352"]);
  assert.deepEqual(accounts("Vehicle Identification Number (VIN) 1HGCM82633A004352"), ["1HGCM82633A004352"]);
  assert.deepEqual(accounts("VIN: 5YJSA1E26HF123456"), ["5YJSA1E26HF123456"]);
});
test("VIN: no context, a letter I, a short run, or a person named Vin is not a VIN", () => {
  assert.deepEqual(texts("the truck 1HGCM82633A004352 was towed"), [], "the same 17 characters without the word are left to the model");
  assert.deepEqual(texts("VIN 1HGCM82633A00435I; VIN 12345; Vin Diesel testified; VIN 2024"), []);
});

// ---- licence plates -----------------------------------------------------------------------------------------------
test("plate: letters-then-digits or a mixed run after 'plate', with an optional state code that is consumed, not captured", () => {
  assert.deepEqual(accounts("plate TX ABC-1234"), ["ABC-1234"]);
  assert.deepEqual(accounts("license plate no. ABC1234"), ["ABC1234"]);
  assert.deepEqual(accounts("Texas plates 7XYZ123"), ["7XYZ123"]);
  assert.deepEqual(accounts("bearing license plate number TX ABC 1234"), ["ABC 1234"]);
  assert.deepEqual(accounts("the Ford, plate: KLM-9876, was towed"), ["KLM-9876"]);
});
test("plate: a year, a steel plate, 'boilerplate', and a plate with no number are not plates", () => {
  assert.deepEqual(texts("plate 2024; a steel plate No. 4; boilerplate 1234; the plate was bent; plates 5-7"), []);
});

// ---- medical record numbers -----------------------------------------------------------------------------------------
test("MRN: 'MRN', 'Medical Record No.', 'Patient ID', 'Chart No.'", () => {
  assert.deepEqual(accounts("MRN 12345678"), ["12345678"]);
  assert.deepEqual(accounts("Medical Record No.: MR-0012345"), ["MR-0012345"]);
  assert.deepEqual(accounts("Patient ID 998877"), ["998877"]);
  assert.deepEqual(accounts("Chart Number 44556677"), ["44556677"]);
});
test("MRN: 'mRNA', a page reference, a short chart number and 'patient account balance' are not MRNs", () => {
  assert.deepEqual(texts("mRNA 12345 vaccine; the chart on page 12; chart No. 3 shows; the patient account balance was due"), []);
});

// ---- payment cards --------------------------------------------------------------------------------------------------
test("card: Luhn-valid 16-digit runs in the three shapes, a 15-digit Amex, and a Mastercard", () => {
  assert.deepEqual(accounts("charged to 4111 1111 1111 1111"), ["4111 1111 1111 1111"]);
  assert.deepEqual(accounts("4111-1111-1111-1111"), ["4111-1111-1111-1111"]);
  assert.deepEqual(accounts("4111111111111111"), ["4111111111111111"]);
  assert.deepEqual(accounts("Amex 3782 822463 10005"), ["3782 822463 10005"]);
  // "ending 0004" is a second, genuine identifier phrase since the 'ending in' anchor landed (battery seed 35)
  assert.deepEqual(accounts("5500 0000 0000 0004 ending 0004").sort(), ["0004", "5500 0000 0000 0004"]);
  assert.ok(luhnValid("4111111111111111") && !luhnValid("4111111111111112") && !luhnValid("0000000000000000"));
});
test("card: a Luhn-invalid run, mixed separators, a dollar figure, a run of one digit, and an SSN beside a phone are not cards", () => {
  assert.deepEqual(texts("4111 1111 1111 1112; 1234567890123456; 4111-1111 1111-1111; $4111111111111111; 0000 0000 0000 0000"), []);
  assert.deepEqual(regexSpans("123-45-6789 713-555-0142").map((s) => s.type), ["SSN", "PHONE"]);
});

// ---- IBANs -------------------------------------------------------------------------------------------------------------
test("IBAN: registry examples pass the shape, the country list and mod-97", () => {
  assert.deepEqual(accounts("IBAN GB82 WEST 1234 5698 7654 32"), ["GB82 WEST 1234 5698 7654 32"]);
  assert.deepEqual(accounts("DE89370400440532013000"), ["DE89370400440532013000"]);
  assert.deepEqual(accounts("to NL91 ABNA 0417 1643 00 by wire"), ["NL91 ABNA 0417 1643 00"]);
  assert.ok(ibanValid("GB82WEST12345698765432") && !ibanValid("GB82WEST12345698765433"));
});
test("IBAN: a wrong check digit, a non-issuing country code, and a US-state-shaped run are not IBANs", () => {
  assert.deepEqual(texts("GB82 WEST 1234 5698 7654 33; US12 3456 7890 1234 56; TX78 7112 5481 2345; CA12 ABCD 1234 5678 90"), []);
});

// ---- driver's licences --------------------------------------------------------------------------------------------------
test("driver's licence: 'DL No.', 'TDL', 'Driver's License No.', 'TX DL #'", () => {
  assert.deepEqual(accounts("DL No. 12345678"), ["12345678"]);
  assert.deepEqual(accounts("TDL 12345678"), ["12345678"]);
  assert.deepEqual(accounts("Texas Driver's License No. 12345678"), ["12345678"]);
  assert.deepEqual(accounts("TX DL # 12345678"), ["12345678"]);
  assert.deepEqual(accounts("driver license number: 87654321"), ["87654321"]);
});
test("driver's licence: the phrase without a number, initials, and a suspension year are not licence numbers", () => {
  assert.deepEqual(texts("the driver's license was suspended in 2019; D.L. Smith appeared; DL was not produced"), []);
});

// ---- a signature block, whole ------------------------------------------------------------------------------------------
test("a Texas signature block: bar and federal numbers scrubbed, email scrubbed, the /s/ name taken by the signature rule, the firm taken by the suffix rule", () => {
  const block = "Respectfully submitted,\nSALINAS & JONES LLP\n/s/ Maria Salinas\nMaria Salinas\nState Bar No. 24012345\nFederal I.D. No. 1234567\nmsalinas@sjlaw.com\n(713) 555-0142";
  assert.deepEqual(regexSpans(block), [{ text: "Maria Salinas", type: "ATTORNEY" }, { text: "SALINAS & JONES LLP", type: "ORG" }, { text: "msalinas@sjlaw.com", type: "EMAIL" }, { text: "(713) 555-0142", type: "PHONE" }, { text: "24012345", type: "ACCOUNT" }, { text: "1234567", type: "ACCOUNT" }]);
});

// ---- through the pipeline: the release gate re-runs the same regexes on the output --------------------------------------
test("regex-only run on a filing full of the new classes releases, re-sweeps clean, and round-trips", async () => {
  const doc = "Defendant (EIN 12-3456789; VIN 1HGCM82633A004352; plate TX ABC-1234) paid with 4111 1111 1111 1111 to GB82 WEST 1234 5698 7654 32. "
    + "Records at MRN 12345678 and Bates ABC000123–ABC000130; counsel State Bar No. 24012345, TDL 87654321, Passport No. 123456789. See Rule 91a and § 16.004.";
  const g = new MatterGraph("m");
  const r = await scrambleDocument(doc, g, null);
  for (const secret of ["12-3456789", "1HGCM82633A004352", "ABC-1234", "4111", "GB82", "12345678", "ABC000123", "24012345", "87654321", "123456789"])
    assert.ok(!r.scrambled.includes(secret), `leaked: ${secret}\n${r.scrambled}`);
  assert.ok(r.scrambled.includes("Rule 91a") && r.scrambled.includes("§ 16.004"), "public law survives verbatim");
  assert.equal(r.stats.ACCOUNT, 10);
  assert.equal(unscramble(r.scrambled, g).text, doc, "every placeholder restores to exactly what it replaced");
});

test("announced cause numbers in Texas county styles are DOCKET; bare years and rule numbers are not", () => {
  const doc = "CAUSE NO. 2024-45678-H in the 190th District. See also Cause No. D-1-GN-24-00392, CAUSE NO. PR-24-00088, cause number 24-001123, and related matter cause number 24-9876. Case No. 2024 is not a docket; Rule 91a applies; Case No. 25 is too short.";
  const got = regexSpans(doc).filter((s) => s.type === "DOCKET").map((s) => s.text);
  for (const d of ["2024-45678-H", "D-1-GN-24-00392", "PR-24-00088", "24-001123", "24-9876"]) assert.ok(got.includes(d), `missed ${d}: ${JSON.stringify(got)}`);
  for (const n of ["2024", "91a", "25"]) assert.ok(!got.includes(n), `false positive ${n}`);
});

test("battery formats (2026-09-15): spaced SSNs, announced dockets, word-segment Bates ranges, phrased VINs, announced 5-digit bar numbers", () => {
  const doc = "SSN of Maria Garcia: 123 45 6789. CIVIL ACTION NO. 24-8891. The cause number for this matter is 2023-45678; the docket number is CV-23-9876. Also DC-23-12345, 2023-CV-5678 and D-1-GN-23-00789. Bates Range: HARPER-ANSWER-001 to HARPER-ANSWER-010. VIN REFERENCED IN PETITION: 1HGCV1F34MA012345. Ms. Pritchard's Delaware Bar Number is 55432. Her bar number is 67890.";
  const got = regexSpans(doc); const texts = got.map((s) => s.text);
  for (const x of ["123 45 6789", "24-8891", "2023-45678", "CV-23-9876", "DC-23-12345", "2023-CV-5678", "D-1-GN-23-00789", "HARPER-ANSWER-001", "HARPER-ANSWER-010", "1HGCV1F34MA012345", "55432", "67890"]) assert.ok(texts.includes(x), `missed ${x}: ${JSON.stringify(texts)}`);
  assert.equal(got.find((s) => s.text === "123 45 6789")?.type, "SSN");
  // and the public-law negatives still hold with the new shapes in play
  const neg = regexSpans("See Tex. Civ. Prac. & Rem. Code § 16.004, 725 S.W.2d 705 (Tex. 1987), Rule 91a, ZIP 78711-2548, $12,345.67, and (713) 555-0142 in 2024.");
  assert.deepEqual(neg.filter((s) => s.type !== "PHONE").map((s) => s.text), []);
});

test("'account ending in 4567' is caught by the phrase; a bare 4567 elsewhere is not an identifier", () => {
  const got = regexSpans("Funds moved to the account ending in 4567 and the card ending 1234; the last four digits are 9876. Page 4567 of the record; the year 2024.");
  assert.deepEqual(got.filter((s) => s.type === "ACCOUNT").map((s) => s.text), ["4567", "1234", "9876"]);
});

test("DOB, date first and the pleading ordinal: 'On March 14, 1971, James Michael Harrison was born' and 'born on the 14th day of March, 1971'", () => {
  const dob = (t: string) => regexSpans(t).filter((s) => s.type === "DOB").map((s) => s.text);
  assert.deepEqual(dob("On March 14, 1971, James Michael Harrison was born in Galveston."), ["March 14, 1971"]);
  assert.deepEqual(dob("On 3/14/1971, Harrison was born."), ["3/14/1971"]);
  assert.deepEqual(dob("The child was born on the 14th day of March, 1971."), ["14th day of March, 1971"]);
  assert.deepEqual(dob("On March 14, 1971, the court signed the order."), [], "a date followed by prose is not a DOB");
  assert.deepEqual(dob("On March 14, 1971, Harrison was born, but on June 1, 2020, the claim was born of a dispute."), ["March 14, 1971"]);
});

test("a street address and a minor's initials are regex-class (live battery, 2026-09-15)", () => {
  const of = (t: string, type: string) => regexSpans(t).filter((s) => s.type === type).map((s) => s.text);
  assert.deepEqual(of("TO: Jane Elizabeth Mason\n1203 Elmview Drive, Houston, Texas 77002\nPhone: (713) 555-0199", "ADDRESS"), ["1203 Elmview Drive, Houston, Texas 77002"]);
  assert.deepEqual(of("offices at 2000 McKinney Avenue, Suite 1500, Dallas, TX 75201.", "ADDRESS"), ["2000 McKinney Avenue, Suite 1500, Dallas, TX 75201"]);
  assert.deepEqual(of("resides at 78 Wildflower Trail and works at 500 Main St.", "ADDRESS"), ["78 Wildflower Trail", "500 Main St."]);
  assert.deepEqual(of("See 12 S.W.3d 34; 42 U.S.C. § 1983; Rule 4 applies.", "ADDRESS"), []);
  assert.deepEqual(of("your minor son, A.B., aged 15, was driving. The minor A.B. is seven. In re: C.D.E., a minor.", "PERSON"), ["A.B.", "C.D.E."]);
  assert.deepEqual(of("the child support order under U.S. law; the minor's counsel cited 5 U.S.C. § 1.", "PERSON"), []);
});

test("structured shapes from the live battery, 2026-09-15: DOB twins and prose, redacted SSN, announced identifiers, signature-block counsel, honorific judges", () => {
  const of = (t: string, type: string) => regexSpans(t).filter((s) => s.type === type).map((s) => s.text);
  assert.deepEqual(of("Mr. Fortune’s date of birth is December 12, 1970 (12/12/1970). His Social", "DOB").sort(), ["12/12/1970", "December 12, 1970"]);
  assert.deepEqual(of("Plaintiff's date of birth is listed in the state-court petition as July 11, 1978.", "DOB"), ["July 11, 1978"]);
  assert.deepEqual(of("signed by Clara Benson on her date of birth, March 3, 1985.", "DOB"), ["March 3, 1985"]);
  assert.deepEqual(of("date of birth unknown; the accident occurred on May 5, 2020.", "DOB"), [], "a clause boundary ends the search");
  assert.deepEqual(of("DEFENDANT'S SSN (redacted): ***-**-9012 and XXX-XX-1234.", "SSN"), ["***-**-9012", "XXX-XX-1234"]);
  assert.deepEqual(of("The defendant’s medical license number is L-4567. The mower’s serial number is VIN 4U7AA12345. Member ID: 88-1234-Q.", "ACCOUNT").sort(), ["4U7AA12345", "88-1234-Q", "L-4567"]);
  assert.deepEqual(of("PIEDMONT LEGAL GROUP, P.C.\nBy: _______________\nSteven A. Parker (Bar No. 22334)\nAttorney for Plaintiff", "ATTORNEY"), ["Steven A. Parker"]);
  assert.deepEqual(of("/s/ Deborah Harper\nState Bar No. 24123456", "ATTORNEY"), ["Deborah Harper"]);
  assert.deepEqual(of("served on counsel for Defendant, Attorney Sarah Johnson of Johnson & Lee LLP.", "ATTORNEY"), ["Sarah Johnson"]);
  assert.deepEqual(of("the Attorney General of Texas moved; Attorney for Plaintiff signed.", "ATTORNEY"), []);
  assert.deepEqual(of("referred to as Judge Garcia. The Honorable Elena M. Cruz presided; Justice Young dissented. The Judge Advocate General agreed.", "JUDGE").sort(), ["Honorable Elena M. Cruz", "Judge Garcia", "Justice Young"]);
});

test("prose dockets, organisation suffixes and the By: line (live battery, 2026-09-15)", () => {
  const of = (t: string, type: string) => regexSpans(t).filter((s) => s.type === type).map((s) => s.text);
  assert.deepEqual(of("The cause number will be CV-2025-0789 in the 401st Judicial District. The docket number for our internal appeal is AP-2023-2176. The case number is OSHA-2024-09876.", "DOCKET").sort(), ["AP-2023-2176", "CV-2025-0789", "OSHA-2024-09876"]);
  assert.deepEqual(of("APPEAL NO. 14-24-00567-CV\n\nFile No.: A-098-765-432", "DOCKET").sort(), ["14-24-00567-CV", "A-098-765-432"]);
  assert.deepEqual(of("the matter of Al-Hassan v. Garland, No. 2024-AS-0157 (Immigration Ct. 2024)", "DOCKET"), [], "a docket inside a cited case is a citation");
  assert.deepEqual(of("counsel Sarah Johnson of Johnson & Lee LLP; registered agent Capitol Corporate Services, Inc., at 600 Congress; the Company objected.", "ORG").sort(), ["Capitol Corporate Services, Inc.", "Johnson & Lee LLP"]);
  assert.deepEqual(of("the Texas Department of Insurance and the Supreme Court of Texas; Acme Widgets, Inc. v. Doe, 12 S.W.3d 34 (Tex. 1999).", "ORG"), [], "public bodies and cited parties are not organisations to scrub");
  assert.deepEqual(of("For Rio Grande Petroleum Corporation\nBy: Michael S. Rivera, Vice President of Operations", "PERSON"), ["Michael S. Rivera"]);
  assert.deepEqual(of("The undersigned attorney, Mark A. Bryant, Bar No. 24056789, certifies", "ATTORNEY"), ["Mark A. Bryant"]);
});

test("a DOB after a name with an initial matches on the INPUT, so the gate never sees a regex hit that exists only in the output", () => {
  const of = (t: string, type: string) => regexSpans(t).filter((s) => s.type === type).map((s) => s.text);
  assert.deepEqual(of("Date of Birth of Thomas R. Whitfield: January 14, 1978\nEmail of Thomas", "DOB"), ["January 14, 1978"]);
  assert.deepEqual(of("Date of Birth of [PERSON_8]: January 14, 1978", "DOB"), ["January 14, 1978"]);
  assert.deepEqual(of("date of birth is unknown. On May 5, 2020, the accident occurred.", "DOB"), [], "a sentence end still bounds the clause");
});

test("honorific-anchored people, role apposition, counsel anchors and two more address forms (after-run, 2026-09-15)", () => {
  const of = (t: string, type: string) => regexSpans(t).filter((s) => s.type === type).map((s) => s.text);
  const late = (t: string, type: string) => lateNameSpans(t).filter((s) => s.type === type).map((s) => s.text);
  assert.deepEqual(late("TO: Ms. Sarah L. Peterson\n78 Wildflower Circle\n\nDear Ms. Peterson:\n\nMr. James A. Wilson of Wilson & Hart, LLP appeared. Mr. Doe's counsel.", "PERSON").sort(), ["Doe", "James A. Wilson", "Peterson", "Sarah L. Peterson"]);
  assert.deepEqual(late("Mr. President spoke; Dr. Pepper was served; Ms. Justice Young sat.", "PERSON"), ["Pepper"], "titles after an honorific are not names");
  assert.deepEqual(late("Respondent admits that the Decedent, Margaret Louise Hartwell, died on March 12, 2024.", "PERSON"), ["Margaret Louise Hartwell"]);
  assert.deepEqual(late("Suite 200, Fort Worth, Texas 76102, Attn: Robert M. Harrison, phone (817) 555-0142. A copy was served on Rebecca Chen on November 5, 2024.", "ATTORNEY").sort(), ["Rebecca Chen", "Robert M. Harrison"]);
  assert.deepEqual(of("located at 100 West 6th Street, Austin, Texas 78701 and 500 Broadway, Houston, Texas 77008.", "ADDRESS").sort(), ["100 West 6th Street, Austin, Texas 78701", "500 Broadway, Houston, Texas 77008"]);
  assert.deepEqual(of("Baker v. Capital One Bank (USA), N.A., 512 S.W.3d 405 (Tex. App.—Fort Worth 2021, no pet.)", "ORG"), []);
});

test("signature-block names above the bar number or the role line, and counsel in apposition (battery after-run, 2026-09-15)", () => {
  const late = (t: string, type: string) => lateNameSpans(t).filter((s) => s.type === type).map((s) => s.text);
  assert.deepEqual(late("Respectfully submitted,\n\n__________________________________\nDavid L. Chen, Esq.\nTexas Bar No. 24091234\n", "ATTORNEY"), ["David L. Chen"]);
  assert.deepEqual(late("APPROVED AS TO FORM:\n\n________________________________\nLydia M. Hargrave\nAttorney for Plaintiff\n", "ATTORNEY"), ["Lydia M. Hargrave"]);
  assert.deepEqual(late("PARKER & MOORE, LLP\n\nBy: ______________________________\n\nJessica R. Moore\nTexas Bar No. 24045678\n", "ATTORNEY"), ["Jessica R. Moore"]);
  assert.deepEqual(late("served on counsel for Plaintiff, Sarah Mitchell of Mitchell & Perez, P.C.; Plaintiff's counsel, Linda Graham of Graham & Associates; his attorney of record, Patricia L. Henderson, at 500 Oak Street", "ATTORNEY").sort(), ["Linda Graham", "Patricia L. Henderson", "Sarah Mitchell"]);
  assert.deepEqual(late("Respectfully submitted,\n\n_________________________\nAttorney for Plaintiff\n", "ATTORNEY"), [], "a role line alone is not a name");
});

test("a reporter in pinpoint form is not an address: '133 S. Ct. at 1147' (real docket, 2026-09-15)", () => {
  const of = (t: string) => regexSpans(t).filter((s) => s.type === "ADDRESS").map((s) => s.text);
  // ("20 Massachusetts Ave" is a street address -- the Department of Justice's -- and taking it is the safe direction)
  assert.deepEqual(of("See Clapper, 133 S. Ct. at 1147; Sessions, 137 S. Ct. at 1689; 20 Massachusetts Ave N.W. is not at issue."), ["20 Massachusetts Ave"]);
  assert.deepEqual(of("offices at 500 S. Main St., Houston, Texas 77002 and 12 N. Ct. Square"), ["500 S. Main St., Houston, Texas 77002"]);
});

test("the name below a role line ending in a colon (battery third reading, 2026-09-15)", () => {
  const late = (t: string) => lateNameSpans(t).filter((s) => s.type === "ATTORNEY").map((s) => s.text);
  assert.deepEqual(late("Midland, Texas 79701\n\nAttorney for Defendant:\nThomas R. Baker\nBaker & Hinton LLP\n500 Main Street"), ["Thomas R. Baker"]);
  assert.deepEqual(late("Counsel for Plaintiff Acme Widgets, Inc.:\n/s/ Jennifer L. Shaw, Esq.\nShaw & Nguyen, PLLC"), ["Jennifer L. Shaw"]);
  assert.deepEqual(late("Attorney for Defendant:\nBaker & Hinton LLP\n"), [], "a firm below the role line is not a person");
});

test("ranks, corporate roles in apposition, and '& Associates' firms (battery third reading, 2026-09-15)", () => {
  const late = (t: string, type: string) => lateNameSpans(t).filter((s) => s.type === type).map((s) => s.text);
  assert.deepEqual(late("the police report narrative of San Antonio Police Officer Kevin M. O’Brien, attached as Exhibit C, and Sgt. Derek J. Simmons.", "PERSON").sort(), ["Derek J. Simmons", "Kevin M. O’Brien"]);
  assert.deepEqual(late("The defendant’s president, Thomas White, was born on March 3, 1975. The plaintiff’s representative is John White (no relation).", "PERSON").sort(), ["John White", "Thomas White"]);
  assert.deepEqual(late("the officer of the court; the manager of operations; the agent for service", "PERSON"), []);
  assert.deepEqual(regexSpans("at the offices of Smith & Associates, 100 Main Street, Houston, Texas 77002, and Jones & Sons").filter((s) => s.type === "ORG").map((s) => s.text), ["Smith & Associates", "Jones & Sons"]);
});

test("a role word before a company is not the company; a Texas appellate docket number is a docket (third reading, 2026-09-15)", () => {
  assert.deepEqual(regexSpans("an Employment Agreement with Plaintiff TechBridge Solutions, Inc. on February 1, 2018; Defendant Acme Widgets, Inc. and Third-Party Defendant Zeta Corp. answered.").filter((s) => s.type === "ORG").map((s) => s.text), ["TechBridge Solutions, Inc.", "Acme Widgets, Inc.", "Zeta Corp."]);
  assert.deepEqual(regexSpans("COURT OF APPEALS FOR THE FIFTH DISTRICT OF TEXAS\n\nNO. 05-24-00567-CV\n\nTHOMAS E. FORESTER, Appellant").filter((s) => s.type === "DOCKET").map((s) => s.text), ["05-24-00567-CV"]);
});

test("real-docket lessons VI (2026-09-15): a bar number keeps its letter prefix; a judge is letters, not a table header; a possessive never leads a late name", () => {
  assert.deepEqual(regexSpans("Assistant Attorney General\nMichigan State Bar No. P60069            P.O. Box 861").filter((s) => s.type === "ACCOUNT").map((s) => s.text), ["P60069"]);
  assert.deepEqual(regexSpans("Department of Justice   COVID-19       Case     Counts\nJustice Young dissented.").filter((s) => s.type === "JUDGE").map((s) => s.text), ["Justice Young"]);
  assert.deepEqual(lateNameSpans("the member, Prible's Due Process claim was denied; the officer, Robert K. Prible, testified.").filter((s) => s.type === "PERSON").map((s) => s.text), ["Robert K. Prible"]);
});

test("a late name is name tokens only: headings and sentence boundaries are not names (real dockets, 2026-09-15)", () => {
  const late = (t: string) => lateNameSpans(t).map((s) => s.text);
  assert.deepEqual(late("R. Mr. Schooley Testified That That Basis Of His Contradictory Testimony Was Wrong"), [], "a Title-Case heading");
  assert.deepEqual(late("Dr. Roman. Because Dr. Roman said so, Ms. Scarlott neither abused it.").sort(), ["Roman", "Scarlott"]);
  assert.deepEqual(late("Mr. J. R. Ewing, Jr. and Ms. Mary-Kate St. James appeared.").sort(), ["J. R. Ewing", "Mary-Kate St. James"]);
});

test("two names in two columns are two names, not one (real docket, 2026-09-15)", () => {
  assert.deepEqual(lateNameSpans("Attorney for Plaintiff:\nC. BRAD SCHUELKE                               Shannon Halijan\nState Bar No. 24001").map((s) => s.text), ["C. BRAD SCHUELKE"]);
});

test("the signature block of the first live real docket (2026-09-16): a rule of underscores after '/s/ Name', a caps name after a merged column above 'Attorney General of Texas', a name above 'Assistant Attorney General'", () => {
  const of = (t: string) => regexSpans(t).filter((s) => s.type === "ATTORNEY").map((s) => s.text);
  assert.deepEqual(of("                                     /s/ Drew L. Harris_______________\n"), ["Drew L. Harris"]);
  assert.deepEqual(of("/s/ Drew L. Harris _____________\nAssistant Attorney General"), ["Drew L. Harris"]);
  const late = (t: string) => lateNameSpans(t).map((s) => s.text);
  assert.deepEqual(late("GREG ABBOTT                                  DREW L. HARRIS\nAttorney General of Texas                    Assistant Attorney General"), ["GREG ABBOTT", "DREW L. HARRIS"]);
  assert.deepEqual(late("       Drew L. Harris\n       Assistant Attorney General\n       State Bar No. 24057887"), ["Drew L. Harris"]);
  assert.deepEqual(late("Attorney for Plaintiff:\nC. BRAD SCHUELKE                               Shannon Halijan\nState Bar No. 24001"), ["C. BRAD SCHUELKE"], "a second-column name above a bare bar number still belongs to nobody");
  assert.deepEqual(of("By: /s/ Lydia M. Hargrave____\nCounsel"), ["Lydia M. Hargrave"]);
});

test("a cited case's docket number is public when a reporter citation follows across a line wrap (live box run, 2026-09-16), and this matter's own docket number is still taken", () => {
  const dockets = (t: string) => regexSpans(t).filter((s) => s.type === "DOCKET").map((s) => s.text);
  assert.deepEqual(dockets("see also Shannon v. Henderson, No. 01-10346, slip op. at 8, 275 F.3d\n\n42, 2001 WL 1223633 (5th Cir. Sep. 25, 2001)."), []);
  assert.deepEqual(dockets("Calderon v. Potter, No. 04-40190, 2004 WL 2375543,\n\n*5 (5th Cir. Oct. 19, 2004)"), []);
  assert.ok(dockets("Plaintiff Jason Shurb filed Civil Action No. 4:13-cv-00271 on February 4, 2013.").length === 1);
});
