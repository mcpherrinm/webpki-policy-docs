"""
Let's Encrypt CP/CPS 6.1 — Boulder compliance overrides.

Boulder IS the LE CA software, so most descriptive technical statements in
the CP/CPS are inherently compliant — Boulder implements what the document
describes. Sections of the CP/CPS that are pure governance/personnel/audit/
facility statements default to "na".

Only the technical sections that map directly to Boulder runtime behavior
are annotated below; everything else stays at the default ("na").
"""

OVERRIDES = {
    "letsencrypt_cp_cps": {
        # ── 3.2.2 Domain validation methods ──────────────────────────────────
        "3.2.2/p1": {
            "status": "compliant",
            "text": "DV methods: see `va/va.go:484-498` (dispatcher) and per-method `va/http.go`, `va/dns.go`, `va/tlsalpn.go`.",
        },
        "3.2.2/li1": {
            "status": "compliant",
            "text": "BR 3.2.2.4.7 (DNS Change) = ACME dns-01. `va/dns.go` validateDNS01.",
        },
        "3.2.2/li2": {
            "status": "compliant",
            "text": "BR 3.2.2.4.19 (ACME http-01). `va/http.go:667` validateHTTP01.",
        },
        "3.2.2/li3": {
            "status": "compliant",
            "text": "BR 3.2.2.4.20 (tls-alpn-01). `va/tlsalpn.go` validateTLSALPN01.",
        },
        "3.2.2/p2": {
            "status": "compliant",
            "text": "IP-address validation header; specifics in li4/li5 below. Handled by `va/va.go` plus identifier-type switches in `va/http.go`/`va/tlsalpn.go`.",
        },
        "3.2.2/li4": {
            "status": "compliant",
            "text": "BR 3.2.2.5.6 (ACME http-01 for IPs). IP branch in `va/http.go`.",
        },
        "3.2.2/li5": {
            "status": "compliant",
            "text": "BR 3.2.2.5.7 (ACME tls-alpn-01 for IPs). IP branch in `va/tlsalpn.go`.",
        },
        "3.2.2/p3": {
            "status": "compliant",
            "text": (
                "Wildcards limited to DNS-01: enforced in `wfe2/wfe.go` NewOrder/NewAuthz "
                "and `policy/pa.go` ChallengeTypeForIdentifier (wildcard names get only DNS01)."
            ),
        },
        "3.2.2/p4": {
            "status": "compliant",
            "text": (
                "MPIC: remote perspectives corroborate primary. See `va/caa.go:37-39` "
                "(MPIC for CAA) and the remote-VA setup in `va/va.go`."
            ),
        },
        "3.2.2/p5": {
            "status": "compliant",
            "text": "BR conformance — Boulder VA codifies BR-aligned challenge implementations.",
        },

        # ── 4.2 Application processing ──────────────────────────────────────
        "4.2.1/p1": {"status": "compliant", "text": "Boulder performs all I&A in code — see `ra/ra.go` FinalizeOrder requiring valid authorizations."},
        "4.2.1/p2": {
            "status": "compliant",
            "text": "90-day validation freshness: `ra/ra.go:276-279, 1090` (validAuthzLifetime enforces reuse window).",
        },
        "4.2.1/p3": {
            "status": "compliant",
            "text": "CAA check: `va/caa.go` DoCAA implements RFC 8659 + BR §3.2.2.8; TTL-aware caching is managed via the SA's order timestamps.",
        },
        "4.2.1/p4": {
            "status": "compliant",
            "text": "High-risk blocklist: `policy/pa.go:59-107` (HighRiskBlockedNames).",
        },
        "4.2.2/p1": {
            "status": "compliant",
            "text": "Order finalization gates on validated authorizations: `ra/ra.go` FinalizeOrder.",
        },
        "4.2.2/p2": {
            "status": "compliant",
            "text": (
                "Public Suffix List + ICANN-domains check: `policy/pa.go:299-305` "
                "(errICANNTLD/errICANNTLDWildcard) using the publicsuffix-go ICANN "
                "list to reject TLDs and non-PSL-leaf identifiers."
            ),
        },

        # ── 4.3 Certificate issuance ────────────────────────────────────────
        "4.3.1/p1": {
            "status": "compliant",
            "text": (
                "End-to-end issuance: `ra/ra.go` FinalizeOrder → `ca/ca.go` "
                "IssueCertificate → `issuance/cert.go` Prepare (linting) → HSM sign. "
                "Pre-sign lint: `issuance/cert.go:357-361`."
            ),
        },
        "4.3.1/p2": {
            "status": "na",
            "text": "Root issuance is operator-driven offline via `cmd/ceremony/` — not a Boulder runtime path.",
        },
        "4.3.2/p1": {
            "status": "compliant",
            "text": "Cert returned via ACME finalize/cert endpoints: `wfe2/wfe.go` FinalizeOrder/Certificate handlers.",
        },

        # ── 4.4 Certificate acceptance ──────────────────────────────────────
        "4.4.2/p2": {
            "status": "compliant",
            "text": "Subscriber certs returned via ACME; CT submission via `ctpolicy/ctpolicy.go` (best-effort logging is built in).",
        },
        "4.4.2/p3": {
            "status": "compliant",
            "text": "Precertificate may not become a final cert if issuance aborts after precert is signed (e.g. SCT fetch failure). Boulder handles this in `ca/ca.go` issuance flow.",
        },

        # ── 4.9 Revocation ──────────────────────────────────────────────────
        "4.9.1/p1": {
            "status": "compliant",
            "text": "BR-aligned revocation: see `revocation/reasons.go` and `ra/ra.go` AdministrativelyRevokeCertificate.",
        },
        "4.9.1/p2": {
            "status": "na",
            "text": "Subscriber-facing warning about revocation timelines — not code.",
        },
        "4.9.2/p1": {
            "status": "compliant",
            "text": "ACME revocation endpoint: `wfe2/wfe.go:442` (revoke-cert handler).",
        },
        "4.9.3/p1": {
            "status": "compliant",
            "text": "ACME revocation procedure: `wfe2/wfe.go:1010-1137` (revokeCertBySubscriberKey + revokeCertByCertKey).",
        },
        "4.9.3/li1": {
            "status": "compliant",
            "text": "Cert-key revocation: `wfe2/wfe.go:1051-1135` revokeCertByCertKey.",
        },
        "4.9.3/li2": {
            "status": "compliant",
            "text": "Subscriber-account-key revocation: `wfe2/wfe.go:1010-1137` revokeCertBySubscriberKey.",
        },
        "4.9.3/li3": {
            "status": "compliant",
            "text": "Demonstrated control over all SANs is verified before allowing third-party revocation; `wfe2/wfe.go` revoke-cert authorization check.",
        },
        "4.9.7/p1": {
            "status": "compliant",
            "text": "CRL frequency: `crl/updater/continuous.go` re-issues each shard within the BR window.",
        },
        "4.9.9/p1": {
            "status": "compliant",
            "text": "OCSP is not currently provided by Boulder (deprecated); the CP/CPS phrasing ('may provide … makes no commitment') is consistent with this.",
        },
        "4.9.12/p1": {
            "status": "compliant",
            "text": (
                "Key-compromise via ACME signed-by-cert-key: `wfe2/wfe.go:1051-1135` "
                "(revokeCertByCertKey marks reason as KeyCompromise)."
            ),
        },
        "4.9.12/p3": {
            "status": "compliant",
            "text": "On demonstrated key compromise Boulder adds the SPKI to the blocked-key registry (`sa/sa.go` AddBlockedKey / `sa/saro.go` KeyBlocked) and revokes unexpired certs sharing that key.",
        },
        "4.9.12/p4": {"status": "na", "text": "Policy clarification, not code-level rule."},
        "4.9.13/p1": {
            "status": "compliant",
            "text": "Boulder does not implement certificate suspension — only revocation.",
        },

        # ── 4.10 Certificate status services ────────────────────────────────
        "4.10.1/p1": {
            "status": "compliant",
            "text": "CRL retention until first publication after NotAfter: `crl/updater/` shard logic retains entries until cert expiry.",
        },
        "4.10.2/p1": {"status": "na", "text": "Service availability — operational uptime, not code."},

        # ── 6.1 Key pair generation ─────────────────────────────────────────
        "6.1.1/p1": {
            "status": "compliant",
            "text": "CA keys are HSM-generated via `cmd/ceremony/` (FIPS 140 HSMs).",
        },
        "6.1.1/p2": {
            "status": "compliant",
            "text": (
                "Subscriber key validation: `goodkey/good_key.go` "
                "(size, ROCA via `goodkey/sagoodkey/` lookup, Fermat factorization "
                "via `goodkey/good_key.go:319` 'crocs.fi.muni.cz' reference; "
                "blocked-key DB lookup in `sa/saa.go`)."
            ),
        },
        "6.1.2/p1": {
            "status": "compliant",
            "text": "Boulder never generates subscriber keys; CSRs are supplied via ACME (`wfe2/wfe.go` FinalizeOrder).",
        },
        "6.1.3/p1": {
            "status": "compliant",
            "text": "Public keys arrive via ACME CSR submission: `wfe2/wfe.go` FinalizeOrder, parsed in `ra/ra.go`.",
        },
        "6.1.5/p1": {"status": "na", "text": "Root CA key sizes — set during ceremony, not Boulder runtime."},
        "6.1.5/p2": {"status": "na", "text": "Subordinate CA key sizes — set during ceremony."},
        "6.1.5/p3": {
            "status": "compliant",
            "text": (
                "Subscriber key sizes: RSA 2048/3072/4096 enforced via "
                "`goodkey/good_key.go:333` (goodRSABitLen, allowed modulus list); "
                "ECDSA P-256/P-384/P-521 via `:275-279`."
            ),
        },
        "6.1.6/p1": {
            "status": "compliant",
            "text": (
                "RSA public-exponent 65537 + odd modulus with no factors < 752: "
                "`goodkey/good_key.go:287-330` (goodKeyRSA exponent check; "
                "modulus smooth-factor check)."
            ),
        },
        "6.1.6/p2": {
            "status": "compliant",
            "text": (
                "ECDSA full public key validation per SP 800-56A: "
                "`goodkey/good_key.go:174-280` (goodKeyECDSA, isOnCurve, point "
                "verification)."
            ),
        },

        # ── 6.2 Private Key Protection ──────────────────────────────────────
        "6.2.1/p1": {"status": "na", "text": "HSM FIPS 140 standard — operational; HSM-interaction code is in `pkcs11helpers/`."},
        "6.2.6/p1": {"status": "na", "text": "HSM-internal key wrap/transfer — operational, performed during ceremony."},

        # ── 7.1 Certificate profile (tables) ────────────────────────────────
        "7.1.1/p1": {
            "status": "compliant",
            "text": "X.509 v3 — emitted by Go crypto/x509 by default; Boulder leaves are v3.",
        },
        # Root CA Certificate Profile table rows (these are under the synthetic section ID
        # 'root-ca-certificate-profile').
        # Use the slug-form ids generated by the markdown TOC parser.

        # Profile table rows — these eltIds use slug section names.
        # See manifest entries beginning 'root-ca-certificate-profile/...'.
        "root-ca-certificate-profile/tr1": {"status": "na", "text": "Root cert field — set in ceremony, not in Boulder runtime."},
        "root-ca-certificate-profile/tr2": {"status": "na", "text": "Root cert field — set in ceremony."},
        "root-ca-certificate-profile/tr3": {"status": "na", "text": "Root cert field — set in ceremony."},
        "root-ca-certificate-profile/tr4": {"status": "na", "text": "Root cert validity — set in ceremony."},
        "root-ca-certificate-profile/tr5": {"status": "na", "text": "Root BasicConstraints — set in ceremony."},
        "root-ca-certificate-profile/tr6": {"status": "na", "text": "Root SPKI — set in ceremony."},
        "root-ca-certificate-profile/tr7": {"status": "na", "text": "Root KeyUsage — set in ceremony."},

        # TLS Subordinate CA Certificate Profile rows
        "tls-subordinate-ca-certificate-profile/tr1": {
            "status": "compliant",
            "text": "Sub-CA serial CSPRNG — ceremony emits with secure RNG; `cmd/ceremony/cert.go`.",
        },
        "tls-subordinate-ca-certificate-profile/tr8": {
            "status": "compliant",
            "text": "Sub-CA EKU = TLS Server (+optional Client) — ceremony EKU config; matches `issuance/cert.go:300-309` for the corresponding leaves.",
        },
        "tls-subordinate-ca-certificate-profile/tr9": {
            "status": "compliant",
            "text": "Sub-CA Certificate Policies = CABF DV (2.23.140.1.2.1) — embedded in leaves via `issuance/cert.go:167-182`; sub-CA cert itself set in ceremony.",
        },

        # Subscriber EE profile rows
        "subscriber-end-entity-certificate-and-precertifi/tr1": {
            "status": "compliant",
            "text": "EE serial CSPRNG with 64 bits entropy: `ca/ca.go:478-493` (136 random bits).",
        },
        "subscriber-end-entity-certificate-and-precertifi/tr2": {
            "status": "compliant",
            "text": "EE Issuer DN derived from issuing CA: handled by `issuance/cert.go` template (issuer set by signing cert).",
        },
        "subscriber-end-entity-certificate-and-precertifi/tr3": {
            "status": "compliant",
            "text": "EE Subject CN=none or first SAN: `issuance/cert.go:314` (CommonName handling with omitCommonName).",
        },
        "subscriber-end-entity-certificate-and-precertifi/tr4": {
            "status": "compliant",
            "text": "Validity up to 100 days — set by issuance profile (NotBefore/NotAfter in `issuance/cert.go:312`).",
        },
        "subscriber-end-entity-certificate-and-precertifi/tr5": {
            "status": "compliant",
            "text": "EE BasicConstraints cA=False — Go x509 default for non-CA templates; `issuance/cert.go` generateTemplate.",
        },
        "subscriber-end-entity-certificate-and-precertifi/tr6": {
            "status": "compliant",
            "text": "EE KeyUsage digitalSignature + optional keyEncipherment — set in `issuance/cert.go` template based on key type.",
        },
        "subscriber-end-entity-certificate-and-precertifi/tr7": {
            "status": "compliant",
            "text": "EE EKU serverAuth + clientAuth: `issuance/cert.go:300-309`.",
        },
        "subscriber-end-entity-certificate-and-precertifi/tr8": {
            "status": "compliant",
            "text": "EE CertificatePolicies = 2.23.140.1.2.1 (CABF DV): `issuance/cert.go:167-182`.",
        },
        "subscriber-end-entity-certificate-and-precertifi/tr9": {
            "status": "compliant",
            "text": "EE AIA caIssuers (and optional OCSP — Boulder omits OCSP): `issuance/cert.go:179` IssuingCertificateURL.",
        },
        "subscriber-end-entity-certificate-and-precertifi/tr11": {
            "status": "compliant",
            "text": "EE SAN: `issuance/cert.go:317` (DNSNames). IP SANs handled similarly.",
        },
        "subscriber-end-entity-certificate-and-precertifi/tr12": {
            "status": "compliant",
            "text": "Precert poison extension: `issuance/cert.go:188-193` (ctPoisonExt).",
        },
        "subscriber-end-entity-certificate-and-precertifi/tr13": {
            "status": "compliant",
            "text": "SCT list extension: `issuance/cert.go:195-198` (sctListOID + generateSCTListExt).",
        },
        "subscriber-end-entity-certificate-and-precertifi/tr14": {
            "status": "compliant",
            "text": "CDP — `issuance/cert.go:355` (CRLDistributionPoints set per shard).",
        },

        # ── 7.1.3 Algorithm OIDs ─────────────────────────────────────────────
        "7.1.3.1/p1": {
            "status": "compliant",
            "text": "SPKI AlgorithmIdentifier byte-for-byte matches BR §7.1.3.1 — Go crypto/x509 + zlint enforce this in `linter/`.",
        },
        "7.1.3.2/p1": {
            "status": "compliant",
            "text": "Signature AlgorithmIdentifier matches BR §7.1.3.2 — `issuance/issuer.go` configures sigAlg; verified post-sign by zlint.",
        },

        # ── 7.1.4 Name forms ────────────────────────────────────────────────
        "7.1.4/p1": {
            "status": "compliant",
            "text": "Boulder leaves omit subject:organizationName/CN-only-from-SAN/etc: `issuance/cert.go` template populates only Subject CN if profile allows. `linter/lints/cpcps/lint_subject_dn*.go` checks subject DN composition.",
        },

        # ── 7.2 CRL profile (tables) ────────────────────────────────────────
        # Both sub-CA-status and EE-status CRL tables follow.
        "7.2/p1": {"status": "na", "text": "Header for CRL profile tables."},
    },
}
