"""
CA/Browser Forum Baseline Requirements v2.2.6 — Boulder compliance overrides.

The BR is the technical core of webpki. Boulder implements the bulk of its
issuance-side requirements. Coverage below focuses on the rules whose
implementation maps to specific Boulder code; the many non-technical sections
(governance, audit, naming, definitions) remain at the default "na".

Boulder ranges referenced by file:line are approximate against the working
copy at /home/mattm/src/boulder.
"""

# Shorthand helpers
def c(text):
    return {"status": "compliant", "text": text}

def n(text):
    return {"status": "na", "text": text}

def i(text):
    return {"status": "need-info", "text": text}


OVERRIDES = {
    "cabf_br": {
        # ── 3.2.2.4 Validation of Domain Authorization or Control ───────────
        # Methods Boulder supports:
        "3.2.2.4.7": n("Header — see paragraph below."),
        "3.2.2.4.7/p1": c("DNS Change = ACME dns-01. `va/dns.go` validateDNS01 implements _acme-challenge TXT record check."),
        "3.2.2.4.18": n("Section header — Boulder doesn't implement v2 of Agreed-Upon Change to Website (uses 3.2.2.4.19 ACME)."),
        "3.2.2.4.19": n("Section header — see paragraph below."),
        "3.2.2.4.19/p1": c("Agreed-Upon Change to Website - ACME = http-01. `va/http.go:667` validateHTTP01 fetches /.well-known/acme-challenge/<token>."),
        "3.2.2.4.20": n("Section header — see paragraph below."),
        "3.2.2.4.20/p1": c("TLS Using ALPN = tls-alpn-01. `va/tlsalpn.go:153-208` validateTLSALPN01."),
        # Methods Boulder does NOT implement — N/A from Boulder's perspective.
        "3.2.2.4.1": n("Method not implemented by Boulder."),
        "3.2.2.4.2": n("Method not implemented by Boulder."),
        "3.2.2.4.3": n("Method not implemented by Boulder."),
        "3.2.2.4.4": n("Method not implemented by Boulder."),
        "3.2.2.4.5": n("Method retired by the CAB Forum (Domain Authorization Document)."),
        "3.2.2.4.6": n("Method retired by the CAB Forum."),
        "3.2.2.4.8": n("Method not implemented by Boulder."),
        "3.2.2.4.9": n("Method retired by the CAB Forum (Test Certificate)."),
        "3.2.2.4.10": n("Method retired by the CAB Forum (TLS Using a Random Value)."),
        "3.2.2.4.11": n("Method retired by the CAB Forum (Any Other Method)."),
        "3.2.2.4.12": n("Method not implemented by Boulder."),
        "3.2.2.4.13": n("Method not implemented by Boulder."),
        "3.2.2.4.14": n("Method not implemented by Boulder."),
        "3.2.2.4.15": n("Method not implemented by Boulder."),
        "3.2.2.4.16": n("Method not implemented by Boulder."),
        "3.2.2.4.17": n("Method not implemented by Boulder."),
        "3.2.2.4.21": n("Section header — see paragraph below."),
        "3.2.2.4.21/p1": c("DNS Labeled with Account ID - ACME = dns-account-01. `va/dns.go` validateDNSAccount01 (challenge type `core.ChallengeTypeDNSAccount01`)."),
        "3.2.2.4.22": n("Section header — see paragraph below."),
        "3.2.2.4.22/p1": c("DNS TXT Record with Persistent Value = dns-persist-01. `va/dns_persist.go:86-118` validateDNSPersist01."),

        # ── 3.2.2.5 IP Address Validation ───────────────────────────────────
        "3.2.2.5.1": n("Method not implemented by Boulder."),
        "3.2.2.5.2": n("Method not implemented by Boulder."),
        "3.2.2.5.3": n("Method not implemented by Boulder."),
        "3.2.2.5.4": n("Retired method."),
        "3.2.2.5.5": n("Method not implemented by Boulder."),
        "3.2.2.5.6": n("Section header — see paragraph below."),
        "3.2.2.5.6/p1": c("ACME http-01 for IPs — IP-identifier branch in `va/http.go` (ident.Type IP)."),
        "3.2.2.5.7": n("Section header — see paragraph below."),
        "3.2.2.5.7/p1": c("ACME tls-alpn-01 for IPs — IP-identifier branch in `va/tlsalpn.go:153`."),
        "3.2.2.5.8": n("Method not implemented by Boulder (DNS TXT in reverse namespace)."),

        # ── 3.2.2.6 Wildcard validation ─────────────────────────────────────
        "3.2.2.6/p1": c("Wildcards validated only via dns-01 — `policy/pa.go` ChallengesFor restricts wildcard names to DNS01."),

        # ── 3.2.2.7 Data source accuracy ────────────────────────────────────
        "3.2.2.7/p1": c("DV validation results reused only within configured window (validAuthzLifetime, < 398 days). `ra/ra.go:276-279, 1090`."),

        # ── 3.2.2.8 CAA ─────────────────────────────────────────────────────
        "3.2.2.8/p1": c("CAA checking — `va/caa.go:39-99` DoCAA implements RFC 8659 + BR §3.2.2.8."),
        "3.2.2.8/p2": c("CAA tree-climbing implemented per RFC 8659 in `va/caa.go`."),
        "3.2.2.8/p3": c("CAA identifying domain `letsencrypt.org`: configured in CA's caaIdentities; `va/caa.go` enforces match."),
        "3.2.2.8/p4": c("Account URI and validation method binding (RFC 8657) supported: `va/caa.go:487-542`."),
        "3.2.2.8.1": n("Section header — see paragraphs below."),
        "3.2.2.8.1/p1": c("DNSSEC validation on CAA — `bdns/dns.go` uses an AD-aware resolver; CAA queries use DNSSEC-validating lookups."),

        # ── 3.2.2.9 MPIC ────────────────────────────────────────────────────
        "3.2.2.9/p1": c("Multi-Perspective Issuance Corroboration — `va/va.go` orchestrates remote VAs; `va/caa.go:37-39` notes MPIC for CAA."),
        # Subsequent paragraphs of 3.2.2.9 describe perspective-count/distance rules — operational config matches.

        # ── 3.2.5 Validation of Authority ───────────────────────────────────
        # Boulder DV doesn't require authority validation — N/A from BR perspective; default ok.

        # ── 3.2.6 Criteria for interoperation ──────────────────────────────
        # Default N/A.

        # ── 4.1.2 Enrollment process ────────────────────────────────────────
        "4.1.2/p1": c("Enrollment via ACME (RFC 8555) — `wfe2/wfe.go` newAccount/newOrder/finalize handlers."),

        # ── 4.2.1 Performing I&A ───────────────────────────────────────────
        "4.2.1/p1": c("Pre-issuance identity verification — performed via challenges by `va/va.go` and gated in `ra/ra.go` FinalizeOrder."),
        "4.2.1/p2": c("Validation freshness — `ra/ra.go:276-279, 1090` (validAuthzLifetime, default 30 days for LE)."),
        "4.2.1/p3": c("High-risk identifier check — `policy/pa.go:59-107` (HighRiskBlockedNames + AdminBlockedNames)."),
        "4.2.1/p4": c("ICANN/PSL TLD rejection — `policy/pa.go:299-305` (errICANNTLD)."),

        # ── 4.2.2 Approval/Rejection ───────────────────────────────────────
        "4.2.2/p1": c("Boulder rejects cert applications failing validation, blocklist, or rate limits. `ra/ra.go` FinalizeOrder and `ratelimits/`."),

        # ── 4.3.1 Issuance ──────────────────────────────────────────────────
        "4.3.1.1": n("Section header — Root CA issuance is manual via ceremony."),
        "4.3.1.1/p1": c("Root CA issuance requires manual action of a Trusted Role via `cmd/ceremony/`."),
        "4.3.1.2": n("Section header — see paragraphs below."),
        "4.3.1.2/p1": c("Pre-issuance (tbsCertificate) linting — `issuance/cert.go:357-361` calls `i.Linter.Check` running zlint and Boulder's own lints in `linter/`."),
        "4.3.1.2/p2": c("If linting fails, issuance aborts — `issuance/cert.go:360`."),
        "4.3.1.3": n("Section header — see paragraph below."),
        "4.3.1.3/p1": c("Post-issuance linting via the precert-linting path in `linter/linter.go` and zlint applied via ceremony tools."),

        # ── 4.9.1.1 Revocation reasons ─────────────────────────────────────
        "4.9.1.1/p1": c("Short-lived cert revocation handling — Boulder may accept or ignore revocation requests for short-lived certs (`ra/ra.go` admin revocation gating)."),
        "4.9.1.1/p2": c("24-hour MUST-revoke list — Boulder admin revocation supports reason codes (`ra/ra.go` AdministrativelyRevokeCertificate, `revocation/reasons.go`)."),
        "4.9.1.1/li1": c("Unspecified (no reason) → no reasonCode extension. Supported in Boulder via reason code 0 (`revocation/reasons.go`)."),
        "4.9.1.1/li2": c("privilegeWithdrawn (9) — `revocation/reasons.go`."),
        "4.9.1.1/li3": c("keyCompromise (1) — `revocation/reasons.go`. ACME revoke-cert with cert key authorizes this reason: `wfe2/wfe.go:1051-1135`."),
        "4.9.1.1/li4": c("keyCompromise for weak-key disclosures — same path; Boulder also has weak-key DB checks (`goodkey/good_key.go:319` Fermat; SA blocked-key list)."),
        "4.9.1.1/li5": c("superseded (4) for failed validation/CAA — admin revocation can set reason 4 (`cmd/admin/cert.go:77`)."),
        "4.9.1.1/p3": c("5-day SHOULD-revoke list — supported via admin revocation with appropriate reason codes."),
        "4.9.1.1/li6": c("superseded (4) for non-compliant keys — supported via admin revocation flow."),
        "4.9.1.1/li7": c("privilegeWithdrawn (9) — supported."),
        "4.9.1.1/li8": c("privilegeWithdrawn (9) — supported."),
        "4.9.1.1/li9": c("cessationOfOperation (5) — `revocation/reasons.go` includes this code."),
        "4.9.1.1/li10": c("privilegeWithdrawn (9) — supported."),
        "4.9.1.1/li11": c("privilegeWithdrawn (9) — supported."),
        "4.9.1.1/li12": c("superseded (4) — supported."),
        "4.9.1.1/li13": c("privilegeWithdrawn (9) — supported."),
        "4.9.1.1/li14": c("CA termination — unspecified (0); operational, not runtime code."),
        "4.9.1.1/li15": c("CP/CPS-required revocation — operational."),
        "4.9.1.1/li16": c("keyCompromise — supported."),

        # ── 4.9.1.2 Sub-CA revocation reasons ──────────────────────────────
        "4.9.1.2/p1": n("Header — Sub-CA revocation handled via ceremony tooling, not Boulder runtime."),
        # All sub-CA revocation list items: Boulder doesn't revoke its own sub-CAs at runtime; ceremony marshals reason codes.
        **{f"4.9.1.2/li{k}": n(f"Sub-CA revocation circumstance; handled via `cmd/ceremony/main.go:872-882`.") for k in range(1, 10)},

        # ── 4.9.2 Who can request revocation ───────────────────────────────
        "4.9.2/p1": c("Subscriber/RA/CA-initiated and third-party Certificate Problem Reports supported. ACME endpoint: `wfe2/wfe.go:442` revoke-cert. CPRs are operationally handled."),

        # ── 4.9.3 Procedure for revocation request ─────────────────────────
        "4.9.3/p1": c("ACME-based revocation: `wfe2/wfe.go:1010-1137`."),
        "4.9.3/p2": c("24x7 revocation request acceptance — Boulder WFE is always-on; admin tooling in `cmd/admin/`."),

        # ── 4.9.5 Time to process revocation ──────────────────────────────
        "4.9.5/p1": n("Operational 24h preliminary report — process, not code."),

        # ── 4.9.7 CRL issuance frequency ───────────────────────────────────
        "4.9.7/p1": c("CRLs at HTTP — `crl/storer/storer.go` uploads to S3-compatible storage exposed via HTTP."),
        "4.9.7/p2": c("Within 24h of first cert — operational."),
        "4.9.7/li1": c("Partitioned CRLs — Boulder publishes sharded CRLs (`issuance/crl.go:101-109`)."),
        "4.9.7/p3": n("Header for Subscriber-cert CRL frequency."),
        "4.9.7/li2": c("CRL update cadence — Boulder's `crl/updater/continuous.go` re-issues each shard within the 4-day window (LE has no AIA OCSP, so 4-day window applies)."),
        "4.9.7/li3": c("Sub-7-day OCSP-AIA case — N/A (Boulder doesn't include AIA OCSP)."),
        "4.9.7/li4": c("Update within 24h of revocation — `crl/updater/` queues revoked certs into next shard within minutes."),
        "4.9.7/p4": n("Header for CA-cert CRL frequency."),

        # ── 4.9.8 CRL latency ──────────────────────────────────────────────
        "4.9.8/p1": n("Operational latency (<10s) — CDN/HTTP-level concern, not Boulder code."),

        # ── 4.9.9 Online status (OCSP) ────────────────────────────────────
        "4.9.9/p1": c("OCSP — Boulder has deprecated OCSP signing. LE certs do not include AIA OCSP. This is BR-compliant since BR §4.9.9 makes OCSP optional under Ballot SC-063."),
        # Subsequent items in 4.9.9 are OCSP-specific → N/A for Boulder.

        # ── 4.9.12 Key compromise ─────────────────────────────────────────
        "4.9.12/p1": c("ACME proof-of-possession revocation (cert key signed JWS) — `wfe2/wfe.go:1051-1135` revokeCertByCertKey marks keyCompromise."),

        # ── 4.9.13 Suspension ─────────────────────────────────────────────
        "4.9.13/p1": c("Boulder does NOT implement suspension — only revocation. BR forbids suspension."),

        # ── 4.10 Certificate status services ──────────────────────────────
        "4.10.1/p1": n("Operational behaviour — CRL availability."),
        "4.10.2/p1": n("Service availability target — operational SLO."),

        # ── 6.1.1.3 Subscriber Key Pair Generation ────────────────────────
        "6.1.1.3/p1": c("Subscriber keys are validated against known-weak lists: ROCA (`goodkey/blocked_key_check.go`), Fermat-factorable (`goodkey/good_key.go:319`), Debian weak keys (`goodkey/sagoodkey/`)."),

        # ── 6.1.5 Key sizes ───────────────────────────────────────────────
        "6.1.5/p1": n("Header for key-size table."),
        "6.1.5/p2": c("RSA modulus >= 2048, divisible by 8: `goodkey/good_key.go:287-333`."),
        "6.1.5/p3": c("ECDSA P-256/P-384/P-521: `goodkey/good_key.go:275-281`."),

        # ── 6.1.6 Public key parameters ───────────────────────────────────
        "6.1.6/p1": c("RSA exponent 65537, odd modulus, no small factors: `goodkey/good_key.go:287-333`."),
        "6.1.6/p2": c("ECDSA full public-key validation per SP 800-56A: `goodkey/good_key.go:174-280`."),

        # ── 6.1.7 Key usage ───────────────────────────────────────────────
        "6.1.7/p1": c("Key usages set per profile in `issuance/cert.go` and ceremony for CA certs. EE: digitalSignature + optional keyEncipherment."),

        # ── 6.3.2 Validity periods ────────────────────────────────────────
        "6.3.2/p1": c("Subscriber cert validity bounded by issuance profile (LE: up to 100 days, far under 398-day max). NotBefore/NotAfter set in `issuance/cert.go:312`."),

        # ── 7.1.1 Version ─────────────────────────────────────────────────
        "7.1.1/p1": c("All certificates are X.509 v3 (Go crypto/x509 default + verified by zlint)."),

        # ── 7.1.2.7 Subscriber Certificate Profile ────────────────────────
        "7.1.2.7": n("Section header."),
        "7.1.2.7.1": n("Subscriber Certificate Types header."),
        "7.1.2.7.2": n("DV header — Boulder issues only DV."),
        "7.1.2.7.2/p1": c("DV subscriber profile — Boulder issues DV. `issuance/cert.go:167-182` asserts policyOID 2.23.140.1.2.1."),
        "7.1.2.7.3": n("IV — Boulder does not issue IV."),
        "7.1.2.7.4": n("OV — Boulder does not issue OV."),
        "7.1.2.7.5": n("EV — Boulder does not issue EV."),
        "7.1.2.7.6": n("Subscriber Cert Extensions header."),
        "7.1.2.7.7": n("AIA — see paragraph."),
        "7.1.2.7.7/p1": c("AIA caIssuers populated; AIA OCSP intentionally omitted (Boulder deprecated OCSP). `issuance/cert.go:179`."),
        "7.1.2.7.8/tr1": c("EE BasicConstraints — cA=false default in `issuance/cert.go` (no IsCA override). zlint lint enforces."),
        "7.1.2.7.8/tr2": c("BasicConstraints criticality — Go x509 outputs as critical when present."),
        "7.1.2.7.9": n("Certificate Policies header."),
        "7.1.2.7.9/p1": c("CertificatePolicies contains BR DV OID 2.23.140.1.2.1 — `issuance/cert.go:167-182`."),
        "7.1.2.7.10": n("EKU header."),
        # 7.1.2.7.10 contains a table of EKU rows — the key items
        "7.1.2.7.10/tr1": c("EE EKU contains id-kp-serverAuth. `issuance/cert.go:300-309`."),
        "7.1.2.7.10/tr2": c("EE EKU may contain id-kp-clientAuth. `issuance/cert.go:300-309` (in default profile)."),
        "7.1.2.7.10/tr3": c("EE EKU must not contain anyExtendedKeyUsage. Boulder leaves do not include it."),
        "7.1.2.7.10/tr4": c("EE EKU must not contain id-kp-codeSigning. Boulder is TLS-only."),
        "7.1.2.7.10/tr5": c("EE EKU must not contain id-kp-emailProtection. Boulder is TLS-only."),
        "7.1.2.7.10/tr6": c("EE EKU must not contain id-kp-timeStamping. Boulder is TLS-only."),
        "7.1.2.7.10/tr7": c("EE EKU must not contain id-kp-OCSPSigning. Boulder leaves are not OCSP responders."),
        "7.1.2.7.11": n("Key Usage header."),
        "7.1.2.7.11/p1": c("EE KeyUsage set per key type — digitalSignature for ECDSA, digitalSignature+keyEncipherment for RSA. `issuance/cert.go` (see KeyUsage assignment based on req.PublicKey type)."),
        "7.1.2.7.12": n("SAN header."),
        "7.1.2.7.12/p1": c("EE SAN populated with requested identifiers (dNSName/iPAddress). `issuance/cert.go:317` (DNSNames)."),

        # ── 7.1.2.8 OCSP Responder Profile — Boulder doesn't issue these ──
        "7.1.2.8": n("OCSP Responder profile — Boulder doesn't issue OCSP responder certs (OCSP deprecated)."),
        **{f"7.1.2.8.{k}": n("OCSP Responder rule — Boulder doesn't issue OCSP responder certs.") for k in range(1, 9)},

        # ── 7.1.2.9 Precertificate Profile ─────────────────────────────────
        "7.1.2.9": n("Header."),
        "7.1.2.9.3": n("Header — see paragraph."),
        "7.1.2.9.3/p1": c("Precert poison: critical extension OID 1.3.6.1.4.1.11129.2.4.3 with NULL value — `issuance/cert.go:188-193` (ctPoisonExt)."),
        "7.1.2.9.4": n("Precert AKI header."),

        # ── 7.1.2.10 Common CA Fields — set during ceremony ───────────────
        "7.1.2.10": n("Common CA fields — set during ceremony, not Boulder runtime."),
        **{f"7.1.2.10.{k}": n("CA cert field — set during ceremony.") for k in range(1, 9)},

        # ── 7.1.2.11 Common Certificate Fields ─────────────────────────────
        "7.1.2.11.1": n("AKI header."),
        "7.1.2.11.1/tr1": c("AKI is present and matches issuer SKID — Go crypto/x509 sets keyIdentifier from the signing cert."),
        "7.1.2.11.1/tr2": c("AKI keyIdentifier byte-for-byte matches issuer SKID."),
        "7.1.2.11.1/tr3": c("AKI extension non-critical."),
        "7.1.2.11.2": n("CDP header."),
        "7.1.2.11.2/p1": c("CDP populated with one URL: `issuance/cert.go:355` (CRLDistributionPoints = [crlURL(shard)])."),
        "7.1.2.11.3": n("SCT list header."),
        "7.1.2.11.3/p1": c("SCT list extension assembled from precert SCTs: `issuance/cert.go:198` generateSCTListExt."),
        "7.1.2.11.4": n("SKID header."),
        "7.1.2.11.4/p1": c("SKID computed per RFC 5280 method 1 (SHA-1 of SPKI). `ca/ca.go:495-505` generateSKID using RFC 7093 method."),

        # ── 7.1.3 Algorithm OIDs ───────────────────────────────────────────
        "7.1.3.1": n("Section header."),
        "7.1.3.1/p1": c("SPKI AlgorithmIdentifier byte-for-byte per BR — Go crypto/x509 produces standard encodings; verified by zlint in `linter/`."),
        "7.1.3.1.1": n("Header."),
        "7.1.3.1.1/p1": c("RSA SPKI encoding (rsaEncryption + NULL) byte-for-byte matches BR."),
        "7.1.3.1.2": n("Header."),
        "7.1.3.1.2/p1": c("ECDSA SPKI encoding matches RFC 5480 (named curve, no implicit/specified curves)."),
        "7.1.3.2": n("Section header."),
        "7.1.3.2/p1": c("Signature AlgorithmIdentifier byte-for-byte per BR — `issuance/issuer.go` sigAlg + Go crypto/x509."),
        "7.1.3.2.1": n("Header."),
        "7.1.3.2.1/p1": c("RSA signature: SHA-256+ used (LE primarily SHA-256); see `issuance/issuer.go` sigAlg selection."),
        "7.1.3.2.2": n("Header."),
        "7.1.3.2.2/p1": c("ECDSA signature: SHA-256 with P-256, SHA-384 with P-384; matched in ceremony config."),

        # ── 7.1.4 Name forms ──────────────────────────────────────────────
        "7.1.4.1": n("Header."),
        "7.1.4.1/p1": c("DNS name encoding: A-label form, normalized per BR. `policy/pa.go` and `bdns/dns.go` enforce ASCII LDH + IDN parsing."),
        "7.1.4.2": n("Header."),
        "7.1.4.2/p1": c("Subject attribute encoding handled by Go crypto/x509 and zlint lints; Boulder DV profile omits most subject attrs."),
        "7.1.4.3": n("Header."),
        "7.1.4.3/p1": c("Subscriber CN must be a value from SAN (if present): `issuance/cert.go` (CommonName uses first SAN under conditions)."),
        "7.1.4.4": n("Header."),
        "7.1.4.4/p1": c("Boulder DV omits other subject attributes (no O, OU, L, ST, C, etc.) — `issuance/cert.go` template only sets CN."),

        # ── 7.2 CRL Profile ────────────────────────────────────────────────
        "7.2": n("Header."),
        "7.2/p1": n("Preamble for CRL profile."),
        "7.2.1": n("Version header."),
        "7.2.1/p1": c("CRL v2 emitted by Go crypto/x509 RevocationList type — used in `issuance/crl.go:90`."),
        "7.2.2": n("CRL entry extensions header."),
        "7.2.2/p1": c("CRL contains CRL number, AKI, IDP. `issuance/crl.go:90-109`."),
        "7.2.2.1": n("IDP header — see paragraph."),
        "7.2.2.1/p1": c("Critical IDP with URI distributionPoint: `issuance/crl.go:103-109` (MakeUserCertsExt, marked critical) + `linter/lints/cpcps/lint_crl_has_idp.go:57-93`."),

        # ── 7.3 OCSP Profile — Boulder does not generate OCSP ─────────────
        "7.3": n("OCSP profile — Boulder no longer signs OCSP responses."),
        "7.3.1": n("OCSP version — N/A."),
        "7.3.2": n("OCSP extensions — N/A."),
        "7.3.2/p1": n("OCSP extensions rule — N/A for Boulder (no OCSP)."),

        # ── 8.x Compliance Audit — non-technical, default N/A acceptable ─

        # ── 9.x Other Business and Legal Matters — non-technical ────────
    },
}
