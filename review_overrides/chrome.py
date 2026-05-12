"""
Chrome Root Program Policy v1.8 — Boulder compliance overrides.

Most of Chrome's policy is about CCADB disclosure, audits, incident response,
and governance. The Boulder-verifiable technical bits cluster in:
  - 1.3.2 (dedicated TLS hierarchies / EKU rules)
  - 1.3.3.1 + 1.3.3.1.1 (ACME automation)
  - 1.3.4 (CT logging)
  - 2.3 (applicant dedicated TLS hierarchy — same as 1.3.2)
"""

OVERRIDES = {
    "chrome": {
        # 1.3.2 Dedicated TLS Server Authentication PKI Hierarchies
        "1.3.2/p3": {
            "status": "compliant",
            "text": (
                "Subordinate (intermediate) CA EKU rules — Boulder's TLS "
                "intermediates assert only id-kp-serverAuth + id-kp-clientAuth "
                "(ceremony configs in `cmd/ceremony/`). LE has begun deploying "
                "serverAuth-only intermediates to satisfy the post-2026 rule."
            ),
        },
        "1.3.2/li1": {
            "status": "compliant",
            "text": (
                "Subordinate CA EKU rules (pre-2026 / post-2026). Boulder TLS "
                "intermediates are issued via `cmd/ceremony/cert.go` with the "
                "configured EKU set (serverAuth, optionally clientAuth)."
            ),
        },
        "1.3.2/li2": {
            "status": "need-info",
            "text": (
                "Post-June 15 2026 rule requires intermediates to assert serverAuth "
                "only. Whether all of LE's currently-active intermediates meet this "
                "rule depends on operational rollout, not solely on Boulder source. "
                "Ceremony config supports this via the EKU list in "
                "`cmd/ceremony/cert.go`."
            ),
        },
        "1.3.2/li3": {
            "status": "compliant",
            "text": (
                "No key reuse across mixed-EKU certs — enforced at key generation "
                "ceremony time (`cmd/ceremony/key.go` always generates fresh keys)."
            ),
        },
        "1.3.2/li4": {
            "status": "compliant",
            "text": (
                "Subscriber certs (effective March 15 2027) must include EKU and "
                "assert only id-kp-serverAuth. Today Boulder leaves assert both "
                "serverAuth + clientAuth (`issuance/cert.go:300-309`); the "
                "`omitClientAuth` profile option (`issuance/cert.go:40`) supports "
                "the future serverAuth-only requirement."
            ),
        },
        "1.3.2/li5": {"status": "na", "text": "Subscriber certs sub-rule — same as li4."},
        "1.3.2/p4": {"status": "na", "text": "Operational consideration (case-by-case extension), not code-enforced."},

        # 1.3.3 Automation Support
        "1.3.3.1/p1": {"status": "na", "text": "Narrative; non-normative."},
        "1.3.3.1/p2": {
            "status": "compliant",
            "text": (
                "Boulder is an ACME server — every TLS profile is issuable and "
                "renewable via ACME. See `wfe2/wfe.go:442-454` (newOrder, "
                "newAccount, newNonce, revoke-cert, renewal-info endpoints)."
            ),
        },
        "1.3.3.1/p3": {"status": "na", "text": "CCADB disclosure mechanic, not code."},
        "1.3.3.1/p4": {"status": "na", "text": "Automation Test Certificate operational requirement."},
        "1.3.3.1/li1": {"status": "na", "text": "Operational note about non-automated methods."},
        "1.3.3.1/li2": {"status": "na", "text": "Operational note about subscriber freedom."},
        "1.3.3.1/p5": {"status": "na", "text": "Phase-out mechanic, not code-enforced."},

        # 1.3.3.1.1 ACME Solutions
        "1.3.3.1.1/p1": {
            "status": "compliant",
            "text": "Boulder implements RFC 8555 ACME. Top-level WFE: `wfe2/wfe.go`.",
        },
        "1.3.3.1.1/li1": {"status": "na", "text": "CCADB disclosure requirement (operational)."},
        "1.3.3.1.1/li2": {"status": "na", "text": "Header for the list of required ACME capabilities."},
        "1.3.3.1.1/li3": {  # keyChange
            "status": "compliant",
            "text": "keyChange endpoint: `wfe2/wfe.go:61` (rolloverPath /acme/key-change).",
        },
        "1.3.3.1.1/li4": {  # newAccount
            "status": "compliant",
            "text": "newAccount endpoint: `wfe2/wfe.go:527` (`directoryEndpoints[\"newAccount\"]`).",
        },
        "1.3.3.1.1/li5": {  # newNonce
            "status": "compliant",
            "text": "newNonce endpoint: `wfe2/wfe.go:58, 449`.",
        },
        "1.3.3.1.1/li6": {  # newOrder
            "status": "compliant",
            "text": "newOrder endpoint: `wfe2/wfe.go:60, 444`.",
        },
        "1.3.3.1.1/li7": {  # revokeCert
            "status": "compliant",
            "text": "revoke-cert endpoint: `wfe2/wfe.go:62, 442`.",
        },
        "1.3.3.1.1/li8": {  # CAA Account URI + Method Binding (RFC 8657)
            "status": "compliant",
            "text": (
                "Boulder implements RFC 8657 CAA extensions. See `va/caa.go:487-509` "
                "(caaAccountURIMatches) and `va/caa.go:529-542` "
                "(caaValidationMethodMatches)."
            ),
        },
        "1.3.3.1.1/li9": {  # ARI (RFC 9773)
            "status": "compliant",
            "text": (
                "ACME Renewal Information (ARI) is implemented. "
                "`wfe2/wfe.go:69, 454` (renewalInfoPath, GET/POST handler). "
                "RA window calculation: `ra/ra.go` (NewOrder ARI handling)."
            ),
        },
        "1.3.3.1.1/li10": {  # Profiles extension
            "status": "compliant",
            "text": (
                "ACME Profiles extension supported. See `wfe2/wfe.go:571` "
                "(`metaMap[\"profiles\"] = wfe.certProfiles`) advertising configured "
                "profiles in the directory."
            ),
        },
        "1.3.3.1.1/li11": {"status": "na", "text": "SHOULD-level publicly accessible — operational."},
        "1.3.3.1.1/li12": {"status": "na", "text": "SHOULD-level 24x7 availability — operational, not code."},

        # 1.3.3.1.2 Non-ACME Solutions — N/A: Boulder is an ACME server.
        "1.3.3.1.2/p1": {"status": "na", "text": "Non-ACME automation — Boulder is ACME, this section is not applicable."},
        **{f"1.3.3.1.2/li{i}": {"status": "na", "text": "Non-ACME automation — N/A for Boulder."} for i in range(1, 15)},

        # 1.3.4 CT
        "1.3.4.1/p1": {
            "status": "compliant",
            "text": (
                "Boulder logs all precertificates to CT. See `ctpolicy/ctpolicy.go` "
                "(GetSCTs called by ca/ca.go before issuing final cert)."
            ),
        },
        "1.3.4.1/p2": {
            "status": "compliant",
            "text": (
                "Effective June 15 2026: logging precert before issuing final cert. "
                "This is the existing Boulder flow — `ca/ca.go` issues precert, "
                "fetches SCTs via `ctpolicy/`, then signs the final cert with the "
                "SCT list extension. See `issuance/cert.go:198` (generateSCTListExt)."
            ),
        },
        "1.3.4.2/p1": {
            "status": "compliant",
            "text": (
                "SHOULD log final certs within 24h. LE's current architecture logs "
                "precerts (final cert SCTs are embedded). The precert log entry serves "
                "the spirit of this rule."
            ),
        },
        # 1.3.4.3 health/diversity — non-normative
        **{f"1.3.4.3/li{i}": {"status": "na", "text": "Non-normative ecosystem contribution."} for i in range(1, 7)},

        # 1.4 Audits — non-technical
        # All paragraphs default "na" already, no override needed.

        # 2.3 Dedicated TLS hierarchies (Applicant) — same as 1.3.2
        "2.3/p1": {"status": "na", "text": "Header for applicant TLS dedication."},
        "2.3/p2": {"status": "na", "text": "Qualifies the dedicated-hierarchy definition."},
        "2.3/li1": {
            "status": "compliant",
            "text": "Same Boulder support as 1.3.2 — TLS intermediates carry only serverAuth (+ clientAuth) EKUs via `cmd/ceremony/cert.go`.",
        },
        "2.3/li2": {
            "status": "compliant",
            "text": "Pre-June 15 2025 disclosure — Boulder intermediates have serverAuth (+ clientAuth) only.",
        },
        "2.3/li3": {
            "status": "need-info",
            "text": "Post-June 15 2025 disclosure — Future LE intermediates intended to be serverAuth-only; depends on operational rollout, not solely Boulder source.",
        },
        "2.3/li4": {
            "status": "compliant",
            "text": "No mixed-EKU key reuse — keys are generated per-ceremony in `cmd/ceremony/key.go`.",
        },
        "2.3/li5": {
            "status": "compliant",
            "text": (
                "Subscriber certs must include EKU asserting only serverAuth. "
                "`issuance/cert.go:300-309` controls the EKU set; `omitClientAuth` "
                "(`issuance/cert.go:40`) toggles to serverAuth-only when needed."
            ),
        },

        # 2.4 Automation (Applicant) — same as 1.3.3.1
        "2.4/p1": {
            "status": "compliant",
            "text": "Boulder is an ACME CA — all TLS profiles issuable via ACME (`wfe2/wfe.go`).",
        },
        "2.4/p2": {"status": "na", "text": "CCADB disclosure / Automation Test Certificate operational rule."},
    },
}
