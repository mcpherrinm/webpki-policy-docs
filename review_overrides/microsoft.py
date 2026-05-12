"""
Microsoft Root Program Requirements v1.1 — Boulder compliance overrides.

Most paragraphs in section 2.1 are organizational (Trusted Agents, audit
disclosure, contracts) so they default to "na". Technical bits are mostly in
section 3.
"""

# Boulder no longer signs OCSP responses — Let's Encrypt fully migrated to
# CRL-only revocation. Where a Microsoft rule specifically requires OCSP
# behavior, Boulder is N/A or non-applicable.

OVERRIDES = {
    "microsoft": {
        # 2.1.7 — Reason Code in intermediate revocation, CCADB within 30 days
        "2.1/p7": {
            "status": "compliant",
            "text": (
                "Boulder records a revocation reason code on every revocation. "
                "See `revocation/reasons.go` (allowed reason set) and "
                "`ra/ra.go` administratorRevokeCertificate which requires a Reason. "
                "Whether 'within 30 days' is met is operational (CCADB update), not "
                "verifiable from Boulder source."
            ),
        },
        "2.1/p13": {
            "status": "compliant",
            "text": (
                "Boulder supports prompt administrative revocation; the SA stores "
                "revocations and the CRL job (`crl/storer/storer.go`, "
                "`cmd/crl-storer/`) publishes them on schedule. The 24-hour "
                "operational SLA is not enforced in code but is supported by the "
                "infrastructure."
            ),
        },
        # ── 3.1 Root Requirements ────────────────────────────────────────────
        "3.1/p1": {  # 3.1.1 x.509 v3
            "status": "compliant",
            "text": "Boulder ceremony emits X.509 v3 certificates via `cmd/ceremony/cert.go` (Go's crypto/x509 default is v3).",
        },
        "3.1/p2": {  # 3.1.2 self-signed
            "status": "compliant",
            "text": "Root CA generation is self-signed in `cmd/ceremony/main.go` (root ceremony type).",
        },
        "3.1/p3": {  # CN identifies publisher and unique
            "status": "compliant",
            "text": "CN is configured per-issuer in `cmd/ceremony/` config files (each root has a distinct CN).",
        },
        "3.1/p4": {"status": "na", "text": "Language readability is a human-review criterion, not code-checkable."},
        "3.1/p5": {  # BasicConstraints cA=true on root
            "status": "compliant",
            "text": "Ceremony emits roots with cA=true; see `cmd/ceremony/cert.go` (IsCA=true on root profile).",
        },
        "3.1/p6": {  # KU critical, keyCertSign + cRLSign, digitalSignature if OCSP
            "status": "compliant",
            "text": "Root/intermediate ceremony sets KU = keyCertSign|cRLSign and marks it critical; see `cmd/ceremony/cert.go` (KeyUsage field on root/intermediate profiles). Boulder no longer uses OCSP so digitalSignature is not required.",
        },
        "3.1/p7": {"status": "compliant", "text": "Root key sizes are enforced by ceremony key generation (`cmd/ceremony/key.go`) and goodkey for issuance; see 3.1.20."},
        "3.1/p8": {  # 8–25 year root validity
            "status": "compliant",
            "text": "Root validity is set in ceremony config and not enforced in code; LE roots are 20–25 years. No Boulder code check, but ceremony JSON in `cmd/ceremony/` sets NotAfter accordingly.",
        },
        "3.1/p9": {  # no 1024-bit RSA
            "status": "compliant",
            "text": "Minimum RSA key size is enforced. See `goodkey/good_key.go:333` (`goodRSABitLen`) — config sets min to 2048; 1024 is rejected.",
        },
        "3.1/p10": {  # issuing CA CDP/AIA OCSP; EE CDP and/or AIA OCSP; CRL <10MB
            "status": "compliant",
            "text": (
                "Boulder leaves include a CDP (`issuance/cert.go:355`, "
                "CRLDistributionPoints) and an AIA caIssuers (`issuance/cert.go:179`, "
                "IssuingCertificateURL). LE no longer publishes OCSP, so the AIA "
                "OCSP URL is intentionally omitted; the rule allows CDP-only EE "
                "certs. CRL <10MB is an operational property of sharded CRLs."
            ),
        },
        "3.1/p11": {  # unique key and subject per root
            "status": "compliant",
            "text": "Root key generation is per-ceremony; ceremony config (`cmd/ceremony/`) generates a fresh key and subject for each new root.",
        },
        "3.1/p12": {"status": "na", "text": "Government CA rule — Let's Encrypt is a commercial CA, not a Government CA."},
        "3.1/p13": {  # Issuing CAs must separate Server Auth / S/MIME / CS / TS EKUs
            "status": "compliant",
            "text": "Boulder TLS intermediates contain only ServerAuth + ClientAuth EKUs (set via ceremony cert profile). See `cmd/ceremony/cert.go` (EKU configuration) and `issuance/cert.go:300-309` (TLS leaves only ServerAuth/ClientAuth).",
        },
        "3.1/p14": {  # EE key size matches BR Appendix A
            "status": "compliant",
            "text": "EE keys validated by `goodkey/good_key.go:287` (`goodKeyRSA`) and `:174` (`goodKeyECDSA`), aligned with BR Appendix A (RSA >=2048, P-256/P-384).",
        },
        "3.1/p15": {  # Policy OID in EE
            "status": "compliant",
            "text": "Boulder embeds the CABF DV OID 2.23.140.1.2.1 in every leaf via `issuance/cert.go:167-182` (domainValidatedOID).",
        },
        "3.1/tr1": {"status": "na", "text": "Header row for the policy-OID table; no individual rule."},
        "3.1/tr2": {  # DV OID
            "status": "compliant",
            "text": "Boulder asserts 2.23.140.1.2.1 (DV) on every leaf; see `issuance/cert.go:167-182`.",
        },
        "3.1/tr3": {"status": "na", "text": "OV OID — Boulder issues DV-only leaves, OV not applicable."},
        "3.1/tr4": {"status": "na", "text": "EV OID — Boulder issues DV-only leaves."},
        "3.1/tr5": {"status": "na", "text": "Code Signing OID — Boulder is TLS-only."},
        "3.1/tr6": {"status": "na", "text": "S/MIME OID — Boulder is TLS-only."},
        "3.1/tr7": {"status": "na", "text": "S/MIME OID — Boulder is TLS-only."},
        "3.1/tr8": {"status": "na", "text": "S/MIME OID — Boulder is TLS-only."},
        "3.1/tr9": {"status": "na", "text": "S/MIME OID — Boulder is TLS-only."},
        "3.1/tr10": {"status": "na", "text": "S/MIME OID — Boulder is TLS-only."},
        "3.1/tr11": {"status": "na", "text": "S/MIME OID — Boulder is TLS-only."},
        "3.1/tr12": {"status": "na", "text": "S/MIME OID — Boulder is TLS-only."},
        "3.1/tr13": {"status": "na", "text": "S/MIME OID — Boulder is TLS-only."},
        "3.1/tr14": {"status": "na", "text": "S/MIME OID — Boulder is TLS-only."},
        "3.1/tr15": {"status": "na", "text": "S/MIME OID — Boulder is TLS-only."},
        "3.1/tr16": {"status": "na", "text": "S/MIME OID — Boulder is TLS-only."},
        "3.1/tr17": {"status": "na", "text": "S/MIME OID — Boulder is TLS-only."},
        "3.1/p16": {"status": "na", "text": "Root certificate property set during ceremony; no leaf-issuance code check."},
        "3.1/p17": {  # EE BasicConstraints cA=false / no pathLen
            "status": "compliant",
            "text": "Boulder leaves use the default `BasicConstraintsValid: true` with `IsCA=false` and no pathLen (see `issuance/cert.go` generateTemplate, no IsCA override). Enforced by `linter/lints/cpcps/lint_basic_constraints*.go`.",
        },
        "3.1/p18": {  # OCSP responder EKU is OCSP Signing only
            "status": "na",
            "text": "Boulder does not operate a dedicated OCSP responder certificate — Let's Encrypt has deprecated OCSP and issues no OCSP-responder certs.",
        },
        "3.1/p19": {  # revoke to specific date
            "status": "compliant",
            "text": "Boulder supports administrator revocation. See `sa/saa.go` RevokeCertificate (sets RevokedAt) and `ra/ra.go` AdministrativelyRevokeCertificate. The exact RevokedAt timestamp is recorded.",
        },
        "3.1/p20": {"status": "na", "text": "Header for the root key sizes table; rules in subsequent rows."},
        "3.1/tr18": {"status": "na", "text": "Header row."},
        "3.1/tr19": {  # RSA 2048 / 4096
            "status": "compliant",
            "text": "Issuance enforces RSA >=2048 (`goodkey/good_key.go:333`). Root key sizes (RSA 2048 / 4096) are set at ceremony time in `cmd/ceremony/key.go`.",
        },
        "3.1/tr20": {  # ECDSA P-256/P-384/P-521 allowed for TLS
            "status": "compliant",
            "text": "ECDSA support: `goodkey/good_key.go:275-281` allows P-256, P-384, and P-521 when configured. LE uses P-384 for ECDSA intermediates.",
        },
        "3.1/p21": {"status": "na", "text": "Note about Windows ECC compatibility — informational."},
        "3.1/li1": {"status": "na", "text": "Compatibility note; not a code-enforceable rule."},
        "3.1/li2": {"status": "na", "text": "Code-Signing-specific note — Boulder is TLS-only."},
        # 3.2 Revocation
        "3.2/p1": {  # 3.2.1 through 3.2.3 are all in this paragraph due to parser
            "status": "compliant",
            "text": (
                "3.2.1 documented revocation: Boulder exposes admin revocation "
                "(`ra/ra.go` AdministrativelyRevokeCertificate). "
                "3.2.2 OCSP validity 8h-7d: N/A — Boulder doesn't sign OCSP. "
                "3.2.3 CRL recommendations (Microsoft-specific 1.3.6.1.4.1.311.21.4 "
                "Next CRL Publish): not present in Boulder CRLs — N/A as Microsoft "
                "marks 3.2.3 as a recommendation, not a requirement."
            ),
        },
        "3.2/p2": {  # 3.2.4 (root must not issue EE) + 3.2.5 (TSA RFC3161)
            "status": "compliant",
            "text": (
                "3.2.4 Root must not issue EE: Boulder roots only sign intermediates, "
                "configured in `cmd/ceremony/` (intermediate ceremony type). "
                "3.2.5 TSA RFC 3161: N/A — Boulder is TLS-only, no Code Signing."
            ),
        },
        # 3.3 Code Signing — N/A entirely
        "3.3/p1": {"status": "na", "text": "Code Signing rule — Boulder is TLS-only."},
        # 3.4 EKU Requirements
        "3.4/p1": {"status": "na", "text": "Business justification for root EKUs — policy/process, not code."},
        "3.4/p2": {"status": "na", "text": "Header listing Microsoft's permitted EKUs."},
        "3.4/li1": {
            "status": "compliant",
            "text": "Server Authentication EKU (1.3.6.1.5.5.7.3.1) is the primary EKU on every Boulder leaf — `issuance/cert.go:300-309`.",
        },
        "3.4/li2": {
            "status": "compliant",
            "text": "Client Authentication EKU (1.3.6.1.5.5.7.3.2) is included by default on Boulder leaves unless `omitClientAuth` is set — `issuance/cert.go:300-309`.",
        },
        "3.4/li3": {"status": "na", "text": "S/MIME (Secure E-mail) EKU — Boulder does not issue S/MIME."},
        "3.4/li4": {"status": "na", "text": "Time Stamping EKU — Boulder does not issue timestamping certs."},
        "3.4/li5": {"status": "na", "text": "Document Signing EKU — Boulder is TLS-only."},
        "3.4/li6": {"status": "na", "text": "Note about Document Signing EKU — Boulder is TLS-only."},
    },
}
