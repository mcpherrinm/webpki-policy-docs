"""
CCADB Policy v2.0 — Boulder compliance overrides.

CCADB is overwhelmingly about disclosure mechanics (uploading documents,
filling out fields, audit submission formats). Almost every entry stays at
the default "na". The Boulder-verifiable bits are:
  - §3.2 (reasonCode on revoked CA-cert CRL entries)
  - §6.2 (partitioned CRL URL/IDP rules)
  - §6.3 (cross-certificate EKU rules)
"""

OVERRIDES = {
    "ccadb": {
        # ── §3.2 Subordinate CA Certificates ────────────────────────────────
        # reasonCode on intermediate-cert CRL revocation entries.
        "3.2/p5": {
            "status": "compliant",
            "text": (
                "Boulder always records a revocation reason. For Boulder-issued "
                "leaves see `sa/sa.go:807-840` (RevokedReason persisted) and "
                "`linter/lints/cabf_br/lint_crl_acceptable_reason_codes.go` "
                "(post-issuance lint). When LE revokes an intermediate it is "
                "done via the ceremony tool which marshals the reason code "
                "into the revocation list entry: `cmd/ceremony/main.go:876-882`."
            ),
        },

        # ── §6.2 CRL Disclosures ────────────────────────────────────────────
        # Boulder publishes a JSON Array of Partitioned CRLs; the full-CRL
        # field is empty.
        "6.2/p1": {
            "status": "compliant",
            "text": (
                "Boulder publishes partitioned (sharded) CRLs for each issuing "
                "CA. The URL set populated in CCADB matches what Boulder "
                "advertises in issued certs. Generation: "
                "`crl/storer/storer.go` (upload pipeline) and "
                "`issuance/cert.go:355` (per-leaf CDP)."
            ),
        },
        "6.2/li1": {
            "status": "na",
            "text": "Boulder does not use the 'full and complete CRL' field; LE publishes partitioned CRLs (see li2 / li6).",
        },
        "6.2/li2": {
            "status": "compliant",
            "text": "Boulder publishes a JSON Array of Partitioned CRLs — sharded by serial number in `issuance/cert.go:350-355` (shard = serial mod numShards).",
        },
        "6.2/p2": {"status": "na", "text": "Header for the URL rules below."},
        "6.2/li3": {
            "status": "compliant",
            "text": (
                "Boulder CRL URLs match exactly between the CCADB record, the "
                "IDP extension in each CRL, and the CDP extension in each "
                "leaf. All three are derived from `Issuer.crlURL(shard)` in "
                "`issuance/issuer.go`; the IDP value is set in "
                "`issuance/crl.go:101-109` and the leaf CDP in "
                "`issuance/cert.go:355`."
            ),
        },
        "6.2/p3": {"status": "na", "text": "Header for the full-CRL branch — Boulder takes the partitioned-CRL branch."},
        "6.2/li4": {"status": "na", "text": "Rule applies only if 'full and complete CRL' field is populated; Boulder leaves it empty."},
        "6.2/li5": {"status": "na", "text": "Rule applies only when using a full CRL; Boulder uses the partitioned array."},
        "6.2/p4": {"status": "na", "text": "Header for the partitioned-CRL branch — applies to Boulder."},
        "6.2/li6": {
            "status": "compliant",
            "text": (
                "Each Boulder partitioned CRL contains a critical "
                "issuingDistributionPoint extension with a URI "
                "distributionPoint that matches the CCADB record. See "
                "`issuance/crl.go:97-109` (MakeUserCertsExt with "
                "crlURL(shard)) and the post-issuance lint "
                "`linter/lints/cpcps/lint_crl_has_idp.go:57-93` (presence + "
                "criticality + URI shape)."
            ),
        },
        "6.2/li7": {
            "status": "compliant",
            "text": "Boulder's full-CRL field in CCADB is empty (partitioned-CRL deployment).",
        },
        "6.2/p5": {
            "status": "compliant",
            "text": (
                "CRLs are republished frequently — the continuous updater in "
                "`crl/updater/continuous.go` re-issues each shard well under "
                "the 4-hour availability window."
            ),
        },

        # ── §6.3 Cross-certification across PKI Hierarchies ─────────────────
        # Cross-cert EKU rules. Cross-certs are issued by LE only at the
        # ceremony level — not the per-leaf Boulder runtime. The text below
        # cites where the corresponding EKU policy is enforced in code where
        # it applies.
        "6.3/p1": {"status": "na", "text": "Context paragraph on dedicated hierarchies."},
        "6.3/p2": {"status": "na", "text": "Context paragraph on cross-certificates."},
        "6.3/p3": {
            "status": "na",
            "text": (
                "Cross-certificate EKU rule. Cross-certificates from LE roots "
                "to other CAs are signed via the ceremony tool "
                "(`cmd/ceremony/main.go` cross-cert profiles) — the EKU set "
                "is configured in the ceremony JSON, not enforced at runtime."
            ),
        },
        # The 6.3 table rows describe which EKUs are required on a cross-cert
        # depending on the subject hierarchy's purpose. LE's TLS hierarchy
        # corresponds to row tr1 (TLS server auth only) for newly-issued
        # cross-certs; the other rows describe purposes Boulder does not
        # operate (TLS client only, S/MIME, code signing).
        "6.3/tr1": {
            "status": "compliant",
            "text": (
                "Subject TLS-serverAuth hierarchy → cross-cert EKU MUST be "
                "only id-kp-serverAuth. LE's serverAuth-only intermediates "
                "(rolled out for the Chrome §1.3.2 post-2026 requirement) "
                "match this. Ceremony configs in `cmd/ceremony/` set this "
                "EKU profile."
            ),
        },
        "6.3/tr2": {"status": "na", "text": "TLS client-auth-only hierarchy — Boulder is server-auth."},
        "6.3/tr3": {
            "status": "compliant",
            "text": (
                "Subject TLS (generic, serverAuth+clientAuth) hierarchy → "
                "cross-cert EKU MUST be only those two. LE's historical "
                "intermediates and current serverAuth+clientAuth "
                "intermediates match this; ceremony EKU config in "
                "`cmd/ceremony/`."
            ),
        },
        "6.3/tr4": {"status": "na", "text": "S/MIME — Boulder is TLS-only."},
        "6.3/tr5": {"status": "na", "text": "S/MIME generic — Boulder is TLS-only."},
        "6.3/tr6": {"status": "na", "text": "Code Signing — Boulder is TLS-only."},
        "6.3/p4": {"status": "na", "text": "EV policyIdentifier rule — LE does not issue EV."},

        # ── §6.4 Annual CCADB Self-Assessments ──────────────────────────────
        # Pure governance/process — defaults to "na" are fine; not overriding.

        # ── §7 Mailshots ────────────────────────────────────────────────────
        # Communication mechanism; default "na" is fine.
        "7/p2": {"status": "na", "text": "Document horizontal-rule separator caught as a paragraph by the parser."},
        "7/p3": {"status": "na", "text": "Public-domain copyright dedication — not a CA requirement."},
    },
}
