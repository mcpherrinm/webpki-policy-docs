# Unclear Certificate Requirements — Synthesis Report

Sources reviewed: `cabf_br.md`, `mozilla.md`, `chrome.md`, `apple.md`, `microsoft.md`, `ccadb.md`, `letsencrypt_cp_cps.md`, the four derived docs (`roots.md`, `intermediates.md`, `leaves.md`, `cross-certs.md`), and `le-certs/linter.py`.

The findings fall into four families. **Family A** (term/definition collisions across policies) is the primary focus and leads. **Family B** (compliance facts not in the cert bytes) is the silent driver of most linter "MANUAL" verdicts. **Family C** (numeric/threshold drift) is where one policy's literal text contradicts another's. **Family D** (derived-doc paraphrase drift) is where the requirements docs introduced ambiguity not present in the sources.

---

## Family A — Cross-document term collisions

### A1. "Applicant" means two completely different things

Same English word, two legal concepts:

- **CABF BR §1.6.1** (`cabf_br.md:281`) / LE / Mozilla operational practice: the natural person or Legal Entity *requesting a leaf certificate*.
- **Chrome §Definitions** (`chrome.md:134`): the organization with an open *Root Inclusion Request* in CCADB.

There is no cross-reference between the two. A CA reading Chrome immediately after the BR will collide on this term. *(High confusion risk; not reconcilable — the labels are genuinely overloaded.)*

### A2. "CA Owner" vs "CA Operator" vs "CA Provider" vs "Program Participant"

Each policy uses its own umbrella term and they are **not** interchangeable:

- **CCADB** (`ccadb.md:38–41`): "CA Owner" = entity in the subject DN **OR** entity controlling the keys.
- **Chrome** (`chrome.md:129–139`): adopts CCADB's "CA Owner" + adds "Chrome Root Program Participant" to cover applicants.
- **Mozilla** (`mozilla.md:12`): "CA operator" = entity in **possession/control of the keys** (key control only — DN-named entities are not in scope unless they also control keys).
- **Apple** (`apple.md`): "CA provider" — used throughout, never defined.
- **Microsoft** (`microsoft.md:§2.1`): "Program Participant" — used throughout, never defined; also mixes "Commercial CAs" and "CAs" without distinguishing them.

A holding-company structure where the DN entity and the key-holder are different organizations would be **one** CA Owner under CCADB/Chrome but **two** CA operators under Mozilla.

### A3. "Subordinate CA in scope for audit/disclosure" — four scoping rules

- **CABF BR §8.1** (`cabf_br.md:3715`): keyed on `basicConstraints.cA=TRUE` (capability).
- **Mozilla §1.1** (`mozilla.md:36–44`): "technically capable of issuing **working server or email** certificates" — excludes EKU-constrained **or** name-constrained-to-no-DNS/email.
- **CCADB §3.2** (`ccadb.md:103–106`): "capable of validating to a certificate included in a Root Store" — no EKU/nameConstraint carve-out; **transitive** (CCADB §5 pulls every ancestor of a serverAuth-issuing CA into TLS audit scope).
- **Microsoft §2.1.5** (`microsoft.md:29`): unconstrained = "not **domain-constrained**" — i.e., requires *name* constraint specifically.
- **Apple §1.1.2–1.1.4**: bare "capable of issuing TLS certificates" — no carve-out language.

**Genuine conflict**: an EKU-only-constrained S/MIME sub-CA is exempt under CABF/Mozilla (technically constrained) but **not** under Microsoft (not domain-constrained). The linter's `_le_hierarchy_dedication` heuristic (`linter.py:1110–1144`) invents its own classification algorithm because none of the policies provides one.

### A4. "Delegated Third Party" / "Enterprise RA" / "subcontractor" / "external RA services" / "Affiliate"

Five terms for overlapping concepts:

- **CABF BR §1.6.1** (`cabf_br.md:333, 359, 433`): formally defines DTP, Enterprise RA, RA — distinct.
- **CCADB §5.2** (`ccadb.md:209`): "external RA services" used as an example of an "Affiliate."
- **Microsoft §2.1.8** (`microsoft.md:35`): "subcontractor" — undefined, no cross-reference.
- **Mozilla §2.1** (`mozilla.md:86–88`): "Registration Authority or Delegated Third Party functions" — undefined.

CCADB's example "external RA services" attaching to "Affiliate" is internally inconsistent: an Affiliate per CABF §1.6.1 (`cabf_br.md:279`) requires ≥10% common control, which a typical contract-RA does not satisfy. A CA classifying a contract-RA as "Affiliate" on the CCADB form would be using a non-CABF meaning.

### A5. "Incident" — scope of the definition differs

- **Mozilla §2.4** (`mozilla.md:167–170`): non-compliance with Mozilla policy.
- **Chrome §1.5** (`chrome.md:354`): non-compliance + "any other situation that may impact the CA's integrity, trustworthiness, or compatibility."
- **Apple §3** (`apple.md:258`): non-compliance with Apple policy.
- **Microsoft / CCADB / CABF**: no formal definition; CCADB §6.1 (`ccadb.md:321`) just references IRGs.

Chrome's catchall is broader than any other's. A CA reading only Mozilla cannot determine whether an event is a Chrome-reportable incident.

### A6. "Trusted Agent" (Microsoft) vs "Trusted Role" (CABF) vs "Trusted Contributor" (LE) vs "POC" (CCADB)

Four overlapping labels covering different functions (program-rep vs. operational HSM role vs. CCADB contact). Casual misreading would conflate them.

### A7. "Subscriber" — defined in CABF, used undefined elsewhere

- **CABF BR §1.6.1**: formally defines Subscriber, Applicant, Subject.
- **LE §1.6.1** (`letsencrypt_cp_cps.md:140`): "see BR" — circular.
- **Mozilla** uses "subscriber" three times without defining it (`mozilla.md:109, 722, 723`).

### A8. "Cross-certificate" — three definitions

- **CCADB §3.2** (`ccadb.md:107–109`): requires the additional cert to be issued by a *different* CA Owner.
- **Mozilla §5.3.2** (`mozilla.md:639`): broader — includes same-key reissues by the same operator ("self-signed, doppelgänger, reissued, cross-signed").
- **Chrome §1.6.1** (`chrome.md:391–402`): adds a 3-week pre-issuance approval requirement *unique to Chrome*.

The local `cross-certs.md` document leans on the CABF BR's §7.1.2.2 profile, which is yet a fourth framing (signed by a different issuing CA, identical subject+SPKI).

---

## Family B — Compliance facts not in the certificate bytes

A linter cannot decide these from cert content alone. The derived docs state the rules without flagging this.

### B1. "Applicant date" / "added-to-root-store date" gating

- **Apple §2.1.3** (single-purpose root requirement) keys on whether the applicant submitted on/after 2024-04-15.
- **Mozilla §7.5** (post-2025-03-15 root-store inclusion) keys on root-store inclusion date.
- **Chrome §1.3.2** keys on whether the hierarchy was disclosed to CCADB before/on/after 2026-06-15 and 2025-06-15.

The linter (`linter.py:1199–1202`) substitutes "root's `notBefore`" as a proxy for "added-to-root-store date" and labels this "Conservative classification" — an explicit hedge. `intermediates.md` §7 (`line 307`) acknowledges this but does not propose a heuristic.

### B2. "Affiliation" gates the cross-cert EKU rule

`cross-certs.md:108, 144–148` and the CABF BR table (`cabf_br.md:2316–2330`) make `extKeyUsage` presence/content conditional on whether the cross-cert is affiliated. **Affiliation is not in the certificate.** The derived doc never flags this.

### B3. "Internal Name" detection requires IANA TLD list

- **CABF BR Definitions** (`cabf_br.md:369`): "cannot be verified as globally unique within the public DNS at the time of certificate issuance because it does not end with a Top-Level Domain registered in IANA's Root Zone Database."
- **leaves.md §5 #1** restates without acknowledging the lookup dependency.
- Linter (`linter.py:1440–1454`) heuristically substitutes "has a dot and last label ≥ 2 chars" — flags whole classes (`corp.lan`, `host.internal`) as fine.

### B4. "Shares private key with corresponding root" (Mozilla post-2019 EKU exception)

`intermediates.md §4.6 #4` and `mozilla.md:607–611` carve out an exception for cross-certificates that share a private key with a corresponding root. **Determining "corresponding root" requires a chain/SPKI lookup**, not byte inspection of the cross-cert. The linter (`linter.py:915–921`) uses `O = "Internet Security Research Group"` as a heuristic proxy and explicitly labels it a heuristic.

### B5. "From a CSPRNG" (serial number)

`roots.md §1.2 #3`, `intermediates.md §1.2 #3`, `leaves.md §1.2 #3`, `cross-certs.md §2.2 #3` all say `serialNumber MUST contain at least 64 bits of output from a CSPRNG`. **CSPRNG-origin is not byte-observable**; the linter measures `bit_length()` and calls this a "heuristic" (`linter.py:148–155`). The companion non-sequentiality rule is reported `MANUAL`, "not byte-observable".

### B6. "Within 48 hours of certificate signing operation" (leaf notBefore)

`leaves.md §1.5 #1` cites CABF BR §7.1.2.7 verbatim. The signing time is not in the cert. Also, the +48h/-48h asymmetry is undefined: the CABF sub-CA profile (`cabf_br.md:2950`) explicitly disallows forward-dating; the leaf profile is silent. A literal-reading linter that accepts ±48h is more permissive than the sub-CA rule.

### B7. DER vs. BER strictness

`roots`/`intermediates`/`leaves` all require ASN.1 DER (`linter.py:1768–1770`), but the linter takes "cryptography library accepted it" as evidence of validity — and that library is known to be permissive in places. The derived docs do not define what "DER-valid" means operationally.

---

## Family C — Numeric / threshold drift across policies

### C1. WebTrust version pinning

- **Mozilla §3.1.1** (`mozilla.md:193–200`): WebTrust for CA **v2.2.2 or later**.
- **Microsoft §4.2.1** (`microsoft.md:237`): WebTrust for CA **v2.1**.
- **Chrome §1.4** (`chrome.md:329`): not superseded by more than 30 days.

A CA audited literally per Microsoft's table (v2.1) fails Mozilla.

### C2. Audit report delivery deadline

- **CABF §8.6, Microsoft §4.1.4, Mozilla §3.1.3**: "three months" (89–92 days, calendar-dependent).
- **CCADB §5.2** (`ccadb.md:205`): "**92 calendar days**".

For a Dec-31 audit period end, Mozilla/CABF/Microsoft demand Mar-31 but CCADB allows up to Apr-1.

### C3. Change-of-control notification lead time

- **Microsoft §2.1.6**: ≥120 days.
- **Chrome §1.6.2**: ≥30 days.
- **Mozilla §8, Apple §1.4**: "before," no minimum.
- **CCADB**: silent.

### C4. Sub-CA / intermediate disclosure deadline

- **CCADB §3.2**: 7 calendar days from **issuance**.
- **Mozilla §5.3.2**: one week from **creation**.
- **Apple §2.1.2**: 7 days from **first cert issued by the subordinate**.

Three different clocks; "issuance" vs. "creation" vs. "first child cert" diverge for sub-CAs that exist before being put into production.

### C5. Root CA validity / term-limit measurement basis

- **Microsoft §3.1.8** (`microsoft.md:74`): minimum 8 years, maximum 25 years, from **submission date**.
- **CABF BR §7.1.2.1.1** table: 2922–9132 days for `notAfter − notBefore`.
- **Chrome §1.3.1.2** (`chrome.md:200–217`): keyed on **key material age**, 15-year ceiling.

`roots.md:43–44` flattens these into "at least 2922 days" / "at most 9132 days" citing both CABF and Microsoft — but Microsoft's clock is *submission to notAfter* and Chrome's is *key age*. Three different measured quantities. A linter following `roots.md` literally tests neither Microsoft's nor Chrome's actual rule.

### C6. Multi-purpose roots: allowed by some, prohibited by others

- **Microsoft §3.1.13**: multi-purpose Root OK; issuing CA must be single-purpose.
- **Chrome §1.3.2** (`chrome.md:232–246`): dedicated TLS hierarchies required after 2026-06-15.
- **Apple §2.1.3**: single-purpose roots for applicants on/after 2024-04-15.
- **Mozilla**: applies TLS+S/MIME policy.

A multi-purpose Root acceptable to Microsoft and Mozilla can be rejected by Chrome and Apple.

### C7. Mozilla §2.1 fixed reuse windows vs CABF BR §4.2.1 step-down

`leaves.md §10 #1–#5` cites Mozilla §2.1 *and* CABF §4.2.1 as if they agreed. Mozilla §2.1 (`mozilla.md:94`) sets a fixed 398-day / 825-day reuse cap; CABF §4.2.1 steps down (200 / 100 / 47 days on the same schedule as cert validity). A leaf issued in March 2027 with a 195-day-old domain validation is BR-compliant but Mozilla-§2.1-non-compliant on a literal reading.

---

## Family D — Derived-doc paraphrase drift (introduced by `roots/intermediates/leaves/cross-certs.md`)

### D1. SHA-1 narrow exception — predicate dropped

`roots.md §3 #4` and `cross-certs.md §3 #3` list the SHA-1 reissuance exception but **omit** the source predicate "the new cert's `extKeyUsage` is present and has at least one key purpose specified" (CABF BR §7.1.3.2.1, `cabf_br.md:3455–3459`). A linter taking the derived rule would accept a SHA-1 reissuance with no `extKeyUsage` at all.

### D2. `notAfter` of cross-certificate left "unspecified"

`cross-certs.md §2.5 #4`: "otherwise unspecified by the CABF profile and inherits whatever bounds apply via root-program lifecycle rules below." But the only rule "below" is the LE 8-year cap and the Chrome 3-year SHOULD; for a cross-signed root, the underlying root profile's 8–25y bounds (`roots.md §1.5 #3–#5`) should apply. The doc fails to cross-link.

### D3. `commonName` uniqueness silently upgraded SHOULD→MUST

`roots.md §1.6 #3` says CN "MUST uniquely identify" the cert. CABF §7.1.2.10.2 says **SHOULD**. Microsoft §3.1.3 says MUST. The derived doc cites both, hiding the upgrade.

### D4. RSA-4096 root rule footnoted as out-of-scope

`roots.md §3` (the Microsoft RSA-4096 rule) is footnoted *"Out-of-scope for TLS-only roots."* This is misframed: Microsoft §3.1.20 applies to all root submissions, with the column split between code-signing/timestamping (4096 only) and everything else (2048 allowed). A linter following the footnote literally would skip the §3.1.20 check on TLS roots entirely.

### D5. "Italicized footnote = MUST" risk

`intermediates.md §1.5 #4`, `cross-certs.md §2.5 #2`: *"(Universal X.509 constraint — implicit in chain validation.)"* — italicized "implicit" rules that a linter author scanning for "MUST" easily skips. The chain-validation constraint is real but not flagged as testable.

### D6. LE "descriptive practice" hedge

`leaves.md §1.5 #8`, `intermediates.md §1.5 #6` and several other LE rules carry *"(LE §7.1 frames this as descriptive practice rather than a per-issuance MUST.)"* — making it ambiguous whether the linter should enforce LE caps as hard rules or warnings.

### D7. `extKeyUsage` "MUST or SHOULD (per affiliation)"

`cross-certs.md §4.6` flattens the CABF MUST/SHOULD split into "MUST or SHOULD (per affiliation)" without giving the linter writer any way to determine affiliation.

### D8. `keyUsage` rules double-list for RSA leaves

`leaves.md §4.7 #3` forbids `keyAgreement, nonRepudiation, encipherOnly, decipherOnly` plus `keyCertSign, cRLSign` for RSA. Item #7 re-forbids the same set. Item #10 for ECDSA says `keyAgreement MAY be asserted but is NOT RECOMMENDED`. The `(RSA only)` qualifier in #3 is essential to reconcile and easy to miss.

### D9. CN-SAN correspondence

`leaves.md §1.6` says CN value "MUST exactly correspond to one entry in the SAN extension." For wildcard SANs, "exactly correspond" doesn't specify whether the CN must be the wildcard string verbatim or may be a covered FQDN; CABF §7.1.4.3 requires the former.

### D10. SAN-criticality "empty SEQUENCE"

`leaves.md §4.10` footnote: SAN MUST be critical if the `subject` field is an "empty SEQUENCE." What counts as empty (zero RDNs, an RDN of zero ATVs, an ATV of zero length)? Not disambiguated.

---

## Linter signals confirming the above

Notable ambiguity markers in `le-certs/linter.py`:

- **Heuristic flags** for `CSPRNG bits` (l.148), `hierarchy dedication` (l.1110), `internal name` (l.1440), `root detection` (l.915), `chain-vintage` (l.1199).
- **`MANUAL` early-returns** for `non-sequentiality` (l.157), `notBefore vs sign-time` (l.1373), `ASN.1 DER validity` (l.1768), `Apple §2.1.3 cascade outside corpus` (l.1231), `SKI derivation method` (l.1756).
- **Stub disguised as PASS**: `chk_country_encoding_printablestring` (l.792) returns PASS unconditionally; the actual check is duplicated in `chk_country_printablestring` (l.1332).
- **Dead-branch logic**: leaf-CRLDP short-lived branch contains `not crldp_present or crldp_present` — tautologically True (l.1622–1640).
- **Self-comparison bug**: `path == os.path.basename` compares string to function (l.1284) — never matches, so cert-under-test is included in its own peer-comparison.
- **SHOULD treated inconsistently**: sub-CA 3-year and leaf-EKU-extras get a freelance `"WARN"` status (l.825, 1581) not declared in the linter's pass/fail enum; RSA-exponent SHOULD is treated as PASS/FAIL (l.307).
- **Tolerances without citation**: `+0.5s` validity slack (l.1363, 1371), `+2 days` LE sub-CA cap (l.829), `+1 day` for SHOULD-3-year (l.823). The leap-second clause in CABF §6.3.2 forbids any tolerance.
- **First-match dispatch** with duplicate entries (l.1779 comment), a catch-all `(r" SHOULD ", chk_manual(...))` at l.2298 that swallows any unimplemented SHOULD.

---

## The shortlist — items most likely to bite a CA

If forced to pick the ten items most likely to cause a CA to think it's compliant when it isn't:

1. **"Applicant" ambiguity** (A1) — Chrome vs CABF, no cross-reference.
2. **"Domain-constrained" vs "technically constrained"** (A3) — an EKU-only-constrained S/MIME sub-CA is exempt under CABF/Mozilla and non-exempt under Microsoft.
3. **WebTrust version drift** (C1) — Microsoft's table cites stale versions Mozilla rejects.
4. **120-day vs 30-day change-of-control** (C3).
5. **Mozilla §2.1 fixed reuse windows vs CABF step-down** (C7) — they will diverge starting 2026-03-15.
6. **Root validity bound measured from three different anchors** (C5) — submission vs. notBefore vs. key-creation.
7. **SHA-1 cross-cert exception with the EKU predicate dropped** (D1).
8. **Cross-cert `notAfter` "unspecified"** (D2) — leaves a cross-signed root unconstrained on paper.
9. **"Affiliation" gates `extKeyUsage` rules** without an in-cert signal (B2).
10. **`notBefore` within 48h: leaf permissive, sub-CA strict** (B6) — a leaf-style ±48h check applied to a sub-CA is incorrect.
