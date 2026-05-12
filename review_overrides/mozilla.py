"""
Mozilla Root Store Policy 3.0 — Boulder compliance overrides.

Covers the technical, Boulder-verifiable rules in:
  - §2.1, §2.2 (validation practices)
  - §4.1 (CRL disclosure)
  - §5.1, 5.1.1, 5.1.2, 5.1.3 (algorithms and SHA-1)
  - §5.2 (forbidden/required practices)
  - §5.3, 5.3.1 (intermediates)
  - §5.4 (precertificates)
  - §6, 6.1, 6.1.1, 6.1.2 (revocation)
  - §7.5.x (dedicated hierarchies)
"""

OVERRIDES = {
    "mozilla": {
        # 2.1 CA Operations
        "2.1/li3": {
            "status": "na",
            "text": "MFA on accounts capable of triggering issuance — operational/HSM access policy, not Boulder code.",
        },
        "2.1/li4": {
            "status": "compliant",
            "text": "Pre-issuance verification — Boulder VA performs CAA + identifier challenges before issuance. See `va/va.go:484-498` and `ra/ra.go` FinalizeOrder gating on validated authorizations.",
        },
        "2.1/li5": {
            "status": "compliant",
            "text": (
                "DV reuse window — Boulder enforces ValidAuthzLifetime when reusing "
                "valid authorizations. See `ra/ra.go:276-279` (validAuthzLifetime "
                "field) and `ra/ra.go:1090` (authz age check). LE configures this "
                "well within 398 days per the TLS BRs."
            ),
        },

        # 2.2 Validation Practices
        "2.2/li3": {
            "status": "compliant",
            "text": (
                "DV per BR 3.2.2.4 — Boulder implements http-01 (3.2.2.4.19), "
                "dns-01 (3.2.2.4.7), and tls-alpn-01 (3.2.2.4.20). See "
                "`va/va.go:484-498` and per-method implementations in "
                "`va/http.go`, `va/dns.go`, `va/tlsalpn.go`."
            ),
        },
        "2.2/li4": {
            "status": "compliant",
            "text": (
                "IP-address validation per BR 3.2.2.5 — Boulder validates IP identifiers "
                "via http-01 / tls-alpn-01. See `va/http.go` and `va/tlsalpn.go` "
                "IP-handling branches; identifier types are in `identifier/identifier.go`."
            ),
        },
        "2.2/li5": {"status": "na", "text": "EV — Boulder issues DV only."},

        # 4.1 Additional Requirements (CCADB CRL disclosure)
        "4.1/li1": {
            "status": "compliant",
            "text": "Boulder publishes partitioned CRLs; CCADB JSON Array of Partitioned CRLs is populated externally with URLs matching those in issued certs (`issuance/cert.go:355`).",
        },
        "4.1/li2": {
            "status": "compliant",
            "text": (
                "Each partitioned CRL has a critical IDP extension. See "
                "`issuance/crl.go:103-109` (MakeUserCertsExt) and "
                "`linter/lints/cpcps/lint_crl_has_idp.go:57-93` (post-issuance lint)."
            ),
        },
        "4.1/li3": {"status": "na", "text": "Security-incident-driven intermediate revocation triggers Bugzilla secure-bug filing — operational."},

        # 5.1 Algorithms
        "5.1/p1": {"status": "na", "text": "Header for allowed algorithms; rules in li1–li5."},
        "5.1/li1": {
            "status": "compliant",
            "text": (
                "RSA key validation: modulus >= 2048, divisible by 8. Enforced in "
                "`goodkey/good_key.go:287-333` (goodKeyRSA + goodRSABitLen) and "
                "supplemental zlint via `linter/`."
            ),
        },
        "5.1/li2": {"status": "na", "text": "Header for ECDSA curves; specific items follow."},
        "5.1/li3": {
            "status": "compliant",
            "text": "P-256 supported (`goodkey/good_key.go:275`).",
        },
        "5.1/li4": {
            "status": "compliant",
            "text": "P-384 supported (`goodkey/good_key.go:277`).",
        },
        "5.1/li5": {
            "status": "compliant",
            "text": "P-521 supported (`goodkey/good_key.go:279`).",
        },
        "5.1/p2": {"status": "na", "text": "Note about Curve25519/448 — not used by Boulder."},
        "5.1/p3": {
            "status": "na",
            "text": "EdDSA only allowed in S/MIME hierarchies — Boulder is TLS-only, so EdDSA isn't issued.",
        },

        # 5.1.1 RSA encoding rules — verified by the linter
        "5.1.1/p1": {
            "status": "compliant",
            "text": "RSA SPKI uses standard rsaEncryption OID with NULL parameter — emitted by Go's crypto/x509 and verified by zlint in `linter/`.",
        },
        "5.1.1/p2": {
            "status": "compliant",
            "text": "Boulder does not emit RSASSA-PSS in SubjectPublicKeyInfo — Go's x509 uses rsaEncryption.",
        },
        # 5.1.1 signature algorithms
        "5.1.1/li1": {"status": "na", "text": "SHA-1 RSA — Boulder does not sign with SHA-1 (signed only with SHA-256+); see `issuance/issuer.go` sigAlg selection."},
        "5.1.1/li2": {
            "status": "compliant",
            "text": "RSA + SHA-256 supported for issuance. Boulder configures SHA256-WithRSA for RSA-key issuers (`cmd/ceremony/cert.go`).",
        },
        "5.1.1/li3": {
            "status": "compliant",
            "text": "RSA + SHA-384 supported; configurable via ceremony.",
        },
        "5.1.1/li4": {
            "status": "compliant",
            "text": "RSA + SHA-512 supported; configurable via ceremony, though LE primarily uses SHA-256.",
        },
        "5.1.1/li5": {"status": "na", "text": "RSASSA-PSS — Boulder does not currently use RSASSA-PSS for signing."},
        "5.1.1/li6": {"status": "na", "text": "RSASSA-PSS — not used."},
        "5.1.1/li7": {"status": "na", "text": "RSASSA-PSS — not used."},

        # 5.1.2 ECDSA encoding/signature
        "5.1.2/p1": {"status": "compliant", "text": "ECDSA SPKI encoding follows RFC 5480 standard via Go's crypto/x509 ASN.1 marshaler."},
        "5.1.2/li1": {"status": "compliant", "text": "P-256 SPKI byte-for-byte matches RFC 5480 — verified by zlint via `linter/`."},
        "5.1.2/li2": {"status": "compliant", "text": "P-384 SPKI byte-for-byte matches RFC 5480."},
        "5.1.2/li3": {"status": "compliant", "text": "P-521 SPKI byte-for-byte matches RFC 5480."},
        "5.1.2/li4": {
            "status": "compliant",
            "text": "ECDSA-P256 signing uses SHA-256 — set in `cmd/ceremony/cert.go` (ecdsa-with-SHA256).",
        },
        "5.1.2/li5": {
            "status": "compliant",
            "text": "ECDSA-P384 signing uses SHA-384 — set in ceremony config.",
        },
        "5.1.2/li6": {
            "status": "compliant",
            "text": "ECDSA-P521 signing uses SHA-512 — supported when configured.",
        },

        # 5.1.3 SHA-1 prohibition
        "5.1.3/p1": {"status": "compliant", "text": "Boulder does not issue S/MIME and does not use SHA-1 for any signing path."},
        "5.1.3/p2": {"status": "compliant", "text": "Boulder uses SHA-256/SHA-384 in all signing paths."},
        "5.1.3/li1": {"status": "compliant", "text": "Boulder does not issue OCSP signing certs (OCSP deprecated)."},
        "5.1.3/li2": {"status": "compliant", "text": "Boulder intermediates are SHA-256/SHA-384 (ceremony config)."},
        "5.1.3/li3": {"status": "na", "text": "OCSP responses — Boulder does not produce OCSP responses."},
        "5.1.3/li4": {"status": "compliant", "text": "CRLs signed by Boulder use SHA-256/SHA-384 (matches issuer signing algorithm)."},
        # 5.1.3 li5-14 — narrow SHA-1 exceptions; Boulder does not use SHA-1 at all → na.
        "5.1.3/p3": {"status": "na", "text": "Exception list for SHA-1 EE certs — Boulder does not sign with SHA-1."},
        "5.1.3/p4": {"status": "na", "text": "Exception list for SHA-1 intermediates — Boulder does not sign with SHA-1."},
        "5.1.3/p5": {
            "status": "compliant",
            "text": "Boulder never signs CT precertificates with SHA-1 — uses SHA-256/SHA-384 via issuer config.",
        },

        # 5.2 Forbidden and Required Practices
        "5.2/p2": {
            "status": "compliant",
            "text": "Roots don't issue EE certs directly — Boulder issues from intermediates only. Ceremony separates roots from issuing CAs.",
        },
        "5.2/p3": {
            "status": "compliant",
            "text": (
                "Serial numbers > 0 with >= 64 bits CSPRNG entropy. See "
                "`ca/ca.go:478-493` (generateSerialNumber: 136 random bits + "
                "1-byte prefix)."
            ),
        },
        "5.2/p4": {"status": "na", "text": "Header for MUST-NOT list (li1-li3 below)."},
        "5.2/li1": {
            "status": "compliant",
            "text": "ASN.1 DER encoding errors are prevented by Go's crypto/x509 and 117+ zlint lints applied via `linter/linter.go`.",
        },
        "5.2/li2": {
            "status": "compliant",
            "text": "Invalid public keys (e.g. RSA exp=1) blocked by `goodkey/good_key.go` (exponent and modulus checks).",
        },
        "5.2/li3": {
            "status": "compliant",
            "text": (
                "Missing SAN, missing IDP on partitioned CRLs, etc. — Boulder leaves always have SAN "
                "(`issuance/cert.go:317`); CRLs always have IDP (`issuance/crl.go:97-109`); zlint enforces these in `linter/`."
            ),
        },
        "5.2/p5": {"status": "na", "text": "Header for additional MUST-NOTs (li4-li5 below)."},
        "5.2/li4": {
            "status": "compliant",
            "text": (
                "Duplicate issuer/serial prevented by random serial generation "
                "(`ca/ca.go:478-493`) + DB uniqueness on (issuer, serial)."
            ),
        },
        "5.2/li5": {
            "status": "compliant",
            "text": (
                "CDP URLs in Boulder leaves point to a live CRL service "
                "(`issuance/cert.go:355` + `crl/storer/`). Boulder no longer emits AIA OCSP, so the second clause is moot."
            ),
        },
        "5.2/p6": {
            "status": "compliant",
            "text": "Boulder never generates subscriber key pairs; subscribers always submit a CSR. See `ra/ra.go` NewOrder/FinalizeOrder using the supplied CSR.",
        },
        "5.2/p7": {
            "status": "compliant",
            "text": (
                "EE certs include an EKU extension that does not include anyExtendedKeyUsage. "
                "See `issuance/cert.go:300-309` (ekus = serverAuth + clientAuth)."
            ),
        },

        # 5.3 Intermediate Certificates
        "5.3/p1": {"status": "na", "text": "Definition / scoping — operational."},
        "5.3/p2": {"status": "na", "text": "Definition — basicConstraints cA=true."},
        "5.3/p3": {"status": "na", "text": "Chain-of-trust definition — no Boulder code rule."},
        "5.3/p4": {
            "status": "compliant",
            "text": (
                "Boulder TLS intermediates contain an EKU extension and do not include anyExtendedKeyUsage "
                "(`cmd/ceremony/cert.go`)."
            ),
        },
        "5.3/li1": {
            "status": "compliant",
            "text": "EKU is present on Boulder intermediates (ceremony config).",
        },
        "5.3/li2": {
            "status": "compliant",
            "text": "anyExtendedKeyUsage is not present in Boulder intermediates.",
        },
        "5.3/li3": {
            "status": "compliant",
            "text": "Boulder intermediates do not combine id-kp-serverAuth with id-kp-emailProtection (TLS-only).",
        },

        # 5.3.1 Technically constrained intermediates — Boulder intermediates aren't technically constrained, they're audited.
        "5.3.1/p1": {"status": "na", "text": "Encouragement / non-normative."},
        "5.3.1/p2": {"status": "na", "text": "Technically-constrained definition; Boulder's intermediates are not name-constrained — they're audited."},
        "5.3.1/p3": {"status": "na", "text": "Section 2.3 reference."},
        "5.3.1/p4": {"status": "na", "text": "Name-constraint rules — Boulder doesn't constrain its TLS intermediates."},

        # 5.4 Precertificates
        "5.4/p1": {
            "status": "compliant",
            "text": (
                "Boulder treats precert and final cert as binding pair. See "
                "`issuance/cert.go:419` (final cert built with matching serial) "
                "and `precert/precert.go:Correspond` enforcing precert/cert "
                "correspondence."
            ),
        },
        "5.4/li1": {
            "status": "compliant",
            "text": "Precert/final cert correspondence enforced in `precert/precert.go` (Correspond function); called from `issuance/cert.go:364-368`.",
        },
        "5.4/li2": {
            "status": "compliant",
            "text": "Precert misissuance treated as final-cert misissuance — Boulder logs and tracks precert serials in `sa/sa.go` precertificates table.",
        },
        "5.4/li3": {
            "status": "compliant",
            "text": "Boulder can revoke a serial that was only precert-issued — revocation uses serial keying, not full cert presence. See `sa/sa.go:807-840`.",
        },
        "5.4/li4": {
            "status": "compliant",
            "text": (
                "Boulder's CRLs include all revoked serials whether or not a final cert was issued. "
                "The CRL updater reads from certificateStatus, which is keyed by serial (`sa/sa.go`)."
            ),
        },

        # 6 Revocation
        "6/p1": {
            "status": "compliant",
            "text": (
                "24x7 revocation status — Boulder CRL service "
                "(`crl/storer/storer.go`, `cmd/crl-storer/`) publishes CRLs continuously."
            ),
        },
        "6/p2": {
            "status": "compliant",
            "text": (
                "EE CRL update at least every 7 days, nextUpdate within 10 days of thisUpdate. "
                "Boulder CRL profile enforces validity intervals in `issuance/crl.go:94` "
                "and CRL updater re-issues shards continuously."
            ),
        },
        "6/p3": {"status": "na", "text": "OCSP requirement preface — Boulder does not provide OCSP."},
        "6/li1": {"status": "na", "text": "OCSP-specific (every 4 days) — Boulder no longer signs OCSP."},
        "6/li2": {"status": "na", "text": "OCSP nextUpdate rule — N/A."},
        "6/li3": {"status": "na", "text": "OCSP nextUpdate vs notAfter rule — N/A."},
        "6/p4": {"status": "na", "text": "CPS-disclosed key compromise demonstration — policy, not code."},

        # 6.1 TLS Revocation
        "6.1/p1": {
            "status": "compliant",
            "text": (
                "BR §4.9.1 revocation: Boulder supports admin revocation with all required reason codes. "
                "See `revocation/reasons.go` and `ra/ra.go` AdministrativelyRevokeCertificate."
            ),
        },

        # 6.1.1 CRLReason codes
        "6.1.1/p1": {
            "status": "compliant",
            "text": (
                "Reason codes are persisted to the certificate status table and emitted "
                "in the CRL entry's reasonCode extension when present. See `sa/sa.go:807-840` "
                "and `linter/lints/cabf_br/lint_crl_acceptable_reason_codes.go` (post-CRL "
                "verification of acceptable reason codes)."
            ),
        },
        "6.1.1/li1": {
            "status": "compliant",
            "text": "keyCompromise (1) is supported as a revocation reason in `revocation/reasons.go`.",
        },
        "6.1.1/li2": {
            "status": "compliant",
            "text": "privilegeWithdrawn (9) supported in `revocation/reasons.go`.",
        },
        "6.1.1/li3": {
            "status": "compliant",
            "text": "cessationOfOperation (5) supported in `revocation/reasons.go`.",
        },
        "6.1.1/li4": {
            "status": "compliant",
            "text": "affiliationChanged (3) supported in `revocation/reasons.go`.",
        },
        "6.1.1/li5": {
            "status": "compliant",
            "text": "superseded (4) supported in `revocation/reasons.go`.",
        },
        "6.1.1/p2": {
            "status": "compliant",
            "text": (
                "Restrictions on keyCompromise / superseded / privilegeWithdrawn — Boulder's "
                "admin revocation flow accepts an explicit reason from the operator. Reason validation "
                "is in `cmd/admin/cert.go:77-90`."
            ),
        },

        # 6.1.2 IDP — same as 4.1/li2
        "6.1.2/p1": {
            "status": "compliant",
            "text": (
                "Boulder CRLs always include a critical IDP with URI distributionPoint. "
                "See `issuance/crl.go:97-109` and `linter/lints/cpcps/lint_crl_has_idp.go:57-93`."
            ),
        },
        "6.1.2/li1": {
            "status": "compliant",
            "text": "IDP URI matches CDP in EE certs — both come from `crlURL(shard)` in `issuance/issuer.go`.",
        },
        "6.1.2/li2": {
            "status": "compliant",
            "text": "IDP URI matches CCADB-disclosed URL — operational alignment via `issuance/issuer.go` crlURLBase config.",
        },

        # 7.5 Dedicated Root Certificates — LE roots are post-2025 TLS-only
        "7.5/p1": {
            "status": "compliant",
            "text": "Let's Encrypt roots are TLS-only — ceremony configs in `cmd/ceremony/` define TLS-only hierarchies.",
        },
        # 7.5.1 Server Authentication Hierarchies (post 2025-03-15)
        "7.5.1/p1": {
            "status": "compliant",
            "text": (
                "Sub-CA & EE certs under a TLS root have EKU = id-kp-serverAuth (+optionally id-kp-clientAuth). "
                "Boulder leaves: `issuance/cert.go:300-309`. Boulder intermediates: ceremony config."
            ),
        },
        # 7.5.2 S/MIME — N/A
        "7.5.2/p1": {"status": "na", "text": "S/MIME hierarchy rule — Boulder is TLS-only."},
    },
}
