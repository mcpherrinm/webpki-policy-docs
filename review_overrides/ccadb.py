"""
CCADB Policy v2.0 — Boulder compliance overrides.

CCADB is overwhelmingly about disclosure mechanics (uploading documents,
filling out fields, audit submission formats). Very little maps to Boulder
runtime code.

Note: the markdown parser used to build id-manifest.json only captured
sections through 5.2.3 for CCADB — sections 6 (Additional Required Practices,
incl. CRL Disclosures) and 7 (Mailshots) are not present as commentable
refs in the manifest, so technical commentary on the CRL Disclosure
requirement in §6.2 (which Boulder satisfies via partitioned-CRL IDP
extensions and `crl/storer/storer.go`) cannot be attached. The §3.2/p5
override below covers the one technical CCADB rule whose ref does exist
in the manifest.
"""

OVERRIDES = {
    "ccadb": {
        # 3.2/p5 — reasonCode on intermediate-cert CRL revocation entries
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
    },
}
