"""
Apple Root Certificate Program (2023-08-15) — Boulder compliance overrides.

Almost all of Apple's policy is audit/policy/governance: those are left at the
default "na" status. Only the small number of technical, Boulder-verifiable
rules are overridden here.
"""

OVERRIDES = {
    "apple": {
        # ── 2.1.2 Full CRLs ─────────────────────────────────────────────────────
        "2.1.2/li1": {
            "status": "compliant",
            "text": (
                "Boulder shard CRLs include a critical issuingDistributionPoint extension "
                "containing a URI distributionPoint. See `issuance/crl.go:97-109` "
                "(MakeUserCertsExt with crlURL(shard) appended as ExtraExtensions; "
                "absence of a base CRL URL is a hard error) and "
                "`linter/lints/cpcps/lint_crl_has_idp.go:57-93` (CRL-issuance linter "
                "verifying the IDP extension is present and critical)."
            ),
        },
        "2.1.2/li2": {
            "status": "compliant",
            "text": (
                "The IDP URI Boulder embeds is constructed from the issuer's "
                "configured crlURLBase joined with the shard index, the same URL "
                "exposed via the JSON Array of Partitioned CRLs (`issuance/crl.go:101-109`, "
                "`issuance/issuer.go` Issuer.crlURL)."
            ),
        },
        "2.1.2/li3": {
            "status": "na",
            "text": "Concerns the 'Full CRL' single-URL field, which Boulder does not use (Boulder publishes partitioned CRLs only).",
        },
        "2.1.2/li4": {
            "status": "na",
            "text": "Availability requirement (Apple polls every 4 hours); enforced by operational publishing, not in Boulder source.",
        },

        # ── 2.1.3 Single-purpose Root CAs ───────────────────────────────────────
        # These are properties of Root and Intermediate CA *certificates*
        # themselves, signed via the ceremony tool, not of leaf issuance.
        "2.1.3/p1": {
            "status": "na",
            "text": "Pertains to Root CA certificate structure (set in `cmd/ceremony/` configs and signed offline); not a runtime Boulder issuance behavior.",
        },
        "2.1.3/li1": {"status": "na", "text": "TLS purpose category header — not a technical rule."},
        "2.1.3/li2": {
            "status": "compliant",
            "text": (
                "Boulder's intermediate-issuing ceremony produces CA certs with the "
                "extendedKeyUsage extension. See `cmd/ceremony/cert.go` and the configured "
                "EKUs in `cmd/ceremony/testdata/`."
            ),
        },
        "2.1.3/li3": {
            "status": "compliant",
            "text": "Intermediate cert EKUs are set in ceremony config; see `cmd/ceremony/cert.go` EKU handling.",
        },
        "2.1.3/li4": {
            "status": "compliant",
            "text": "id-kp-serverAuth alone is supported via ceremony config (single-EKU intermediate).",
        },
        "2.1.3/li5": {
            "status": "compliant",
            "text": (
                "Boulder issues leaves under TLS intermediates that include id-kp-serverAuth "
                "and (optionally) id-kp-clientAuth. See `issuance/cert.go:300-309` "
                "(ekus = {ServerAuth, ClientAuth}, with omitClientAuth available)."
            ),
        },
        "2.1.3/li6": {
            "status": "na",
            "text": "Cross-purpose key reuse is operationally controlled at key-generation ceremony time; not enforced in Boulder runtime code.",
        },
        "2.1.3/li7": {"status": "na", "text": "S/MIME purpose category header — Boulder does not issue S/MIME."},
        "2.1.3/li8": {"status": "na", "text": "S/MIME-specific — Boulder is TLS-only."},
        "2.1.3/li9": {"status": "na", "text": "S/MIME-specific."},
        "2.1.3/li10": {"status": "na", "text": "S/MIME-specific."},
        "2.1.3/li11": {"status": "na", "text": "S/MIME-specific."},
        "2.1.3/li12": {"status": "na", "text": "S/MIME-specific."},
        "2.1.3/li13": {"status": "na", "text": "Client-auth-only purpose — Boulder issues TLS server certs."},
        "2.1.3/li14": {"status": "na", "text": "Client-auth-only purpose, not applicable to Boulder."},
        "2.1.3/li15": {"status": "na", "text": "Client-auth-only purpose, not applicable."},
        "2.1.3/li16": {"status": "na", "text": "Client-auth-only EKU rule, not applicable."},
        "2.1.3/li17": {"status": "na", "text": "Client-auth-only EKU rule, not applicable."},
        "2.1.3/li18": {"status": "na", "text": "Client-auth-only EKU rule, not applicable."},
        "2.1.3/li19": {"status": "na", "text": "Client-auth-only purpose, not applicable."},
        "2.1.3/li20": {"status": "na", "text": "Timestamping purpose — not applicable to Boulder."},
        "2.1.3/li21": {"status": "na", "text": "Timestamping-specific."},
        "2.1.3/li22": {"status": "na", "text": "Timestamping-specific."},
        "2.1.3/li23": {"status": "na", "text": "Timestamping-specific."},

        # ── 2.2 TLS validation methods ─────────────────────────────────────────
        "2.2/li1": {
            "status": "compliant",
            "text": (
                "Boulder supports multiple BR-defined validation methods. See "
                "`va/va.go:484-498` (dispatch table for HTTP01, DNS01, TLSALPN01, "
                "DNS-Account-01) and `core/objects.go:41-43` (challenge type constants). "
                "Specifically tls-alpn-01 (3.2.2.4.20) is implemented in `va/tlsalpn.go`."
            ),
        },
        "2.2/li2": {
            "status": "noncompliant",
            "text": (
                "BR 3.2.2.4.7 'DNS Change' is the dns-01 challenge family. Boulder "
                "supports dns-01 (RFC 8555) in `va/dns.go` — note that ACME dns-01 maps to "
                "BR 3.2.2.4.7. Compliant with intent of the requirement (validation via "
                "DNS change), though Apple lists the specific BR method numbers."
            ),
        },
        "2.2/li3": {
            "status": "na",
            "text": "BR 3.2.2.4.18 'Agreed-Upon Change to Website v2'. Boulder uses ACME http-01 (mapped to BR 3.2.2.4.19); 4.18 is not supported.",
        },
        "2.2/li4": {
            "status": "compliant",
            "text": (
                "BR 3.2.2.4.19 'Agreed-Upon Change to Website - ACME' is http-01. "
                "Implemented in `va/http.go:667` (validateHTTP01)."
            ),
        },
        "2.2/li5": {
            "status": "compliant",
            "text": (
                "BR 3.2.2.4.20 'TLS Using ALPN' = tls-alpn-01. Implemented in "
                "`va/tlsalpn.go:153-208` (validateTLSALPN01)."
            ),
        },
        # Apple requires at least one of these — Boulder supplies multiple. Mark
        # the parent section's intent at li1 above as compliant.

        # ── 2.3 S/MIME ─────────────────────────────────────────────────────────
        # Boulder does not issue S/MIME certs; the whole subsection is N/A.
        # (Default "na" already; explicit annotations follow for clarity.)
        "2.3/li1": {"status": "na", "text": "S/MIME-specific; Boulder issues only TLS server certs."},
        "2.3/li2": {"status": "na", "text": "S/MIME EKU; not applicable to Boulder."},
        "2.3/li3": {"status": "na", "text": "S/MIME SAN rule; not applicable to Boulder."},
        "2.3/li4": {"status": "na", "text": "S/MIME validity period rule; not applicable."},
        "2.3/li5": {"status": "na", "text": "S/MIME-specific (Boulder issues only TLS)."},
        "2.3/li6": {"status": "na", "text": "S/MIME key-size grouping header."},
        "2.3/li7": {"status": "na", "text": "S/MIME-specific."},
        "2.3/li8": {"status": "na", "text": "S/MIME-specific."},
    },
}
