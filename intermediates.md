# Intermediate (Subordinate CA) Certificate Requirements

This document collects the most restrictive certificate-content requirements that apply to an **intermediate CA certificate** — a subordinate CA certificate issued under a root or another sub-CA, used directly or transitively to issue TLS subscriber certificates. It covers both:

- **TLS Subordinate CA** (CABF BR §7.1.2.6): no `nameConstraints` required.
- **Technically Constrained TLS Subordinate CA** (CABF BR §7.1.2.5): `nameConstraints` required.

If you are profiling a **Technically Constrained Non-TLS Subordinate CA** (CABF BR §7.1.2.3) — i.e., an intermediate that cannot issue server certificates — see §6 below for the divergences.

Citations point into the policy documents in this directory:

- `[CABF BR §X]` → `cabf_br.md`
- `[Mozilla §X]` → `mozilla.md`
- `[Chrome §X]` → `chrome.md`
- `[Apple §X]` → `apple.md`
- `[Microsoft §X]` → `microsoft.md`
- `[CCADB §X]` → `ccadb.md`
- `[LE §X]` → `letsencrypt_cp_cps.md` (LE-issued certs only)

## 1. Structural / `tbsCertificate` fields

### 1.1 Version

1. The certificate `version` field MUST be v3 (integer value 2). [CABF BR §7.1.1, §7.1.2.5, §7.1.2.6]

### 1.2 Serial number

1. The certificate `serialNumber` MUST be greater than zero. [CABF BR §7.1.2.5, §7.1.2.6; Mozilla §5.2; LE §7.1]
2. The certificate `serialNumber` MUST be less than 2^159. [CABF BR §7.1.2.5, §7.1.2.6]
3. The certificate `serialNumber` MUST contain at least 64 bits of output from a CSPRNG. [CABF BR §7.1.2.5, §7.1.2.6; Mozilla §5.2; LE §7.1]
4. The certificate `serialNumber` MUST be non-sequential. [CABF BR §7.1.2.5, §7.1.2.6]
5. The combination of `issuer` DN and `serialNumber` MUST be unique within the issuing CA (CT precertificate exception not applicable to intermediates). [Mozilla §5.2]

### 1.3 Signature (inside `tbsCertificate`)

1. The encoded value of `tbsCertificate.signature` MUST be byte-for-byte identical to the outer `signatureAlgorithm`. [CABF BR §7.1.2.5, §7.1.2.6]
2. The signature `AlgorithmIdentifier` MUST be one of the encodings permitted by CABF BR §7.1.3.2 (see §3 below). [CABF BR §7.1.3.2; LE §7.1.3.2]

### 1.4 Issuer

1. The encoded `issuer` field MUST be byte-for-byte identical to the encoded `subject` field of the issuing CA. [CABF BR §7.1.2.5, §7.1.2.6, §7.1.4.1]
2. The certificate's signature MUST verify under the issuing CA's public key.

### 1.5 Validity

1. The `notBefore` value MUST be no later than the time of signing. [CABF BR §7.1.2.10.1]
2. The `notBefore` value MUST be no earlier than one day prior to the time of signing. [CABF BR §7.1.2.10.1]
3. The `notAfter` value MUST be no earlier than the time of signing. [CABF BR §7.1.2.10.1]
4. The `notAfter` value MUST NOT exceed the `notAfter` of the issuing CA certificate. *(Universal X.509 constraint — implicit in chain validation.)*
5. The validity period (`notAfter − notBefore`) SHOULD be at most 3 years. [Chrome §1.3.1.3]
6. A LE-issued intermediate's validity period is at most 8 years. [LE §7.1 (Subordinate CA profile)] *(LE-issued only; LE §7.1 frames this as descriptive practice rather than a per-issuance MUST.)*

### 1.6 Subject

1. All `subject` attribute encodings MUST conform to CABF BR §7.1.4. [CABF BR §7.1.2.10.2, §7.1.4]
2. The `subject` MUST contain a `countryName` attribute encoded as `PrintableString` whose value is a two-letter ISO 3166-1 alpha-2 country code for the country in which the CA's place of business is located, at most 2 characters; the `XX` user-assigned code permitted for subscriber profiles (§7.1.2.7.3/§7.1.2.7.4) MUST NOT be used in a CA certificate. [CABF BR §7.1.2.10.2, §7.1.4.2]
3. The `subject` MUST contain an `organizationName` attribute encoded as `UTF8String` or `PrintableString` and at most 64 characters. [CABF BR §7.1.2.10.2, §7.1.4.2]
4. The `subject` MUST contain a `commonName` attribute encoded as `UTF8String` or `PrintableString` and at most 64 characters; the `commonName` SHOULD identify the certificate uniquely within the issuing CA. [CABF BR §7.1.2.10.2, §7.1.4.2]
5. The `subject` MUST NOT contain an `organizationalUnitName` attribute. [CABF BR §7.1.2.10.2]
6. Each `RelativeDistinguishedName` in the `subject` MUST contain exactly one `AttributeTypeAndValue`. [CABF BR §7.1.4.1]
7. The `RDNSequence` MUST order attributes as listed in CABF BR §7.1.4.2. [CABF BR §7.1.4.1]
8. The `subject` MUST NOT contain more than one instance of any given `AttributeTypeAndValue` (except where explicitly allowed). [CABF BR §7.1.4.1]
9. The encoded `subject` MUST be byte-for-byte identical across all certificates whose subject DN is equal under RFC 5280 §7.1 (including expired/revoked). [CABF BR §7.1.4.1]
10. A LE-issued intermediate's `subject` MUST be `C=US, O=Let's Encrypt, CN=<meaningful>`. [LE §7.1 (Subordinate CA profile)] *(LE-issued only)*

### 1.7 `subjectPublicKeyInfo`

1. The SPKI algorithm MUST be RSA (`rsaEncryption`, OID 1.2.840.113549.1.1.1) or ECDSA (`id-ecPublicKey`, OID 1.2.840.10045.2.1). [CABF BR §7.1.3.1, §6.1.5; Mozilla §5.1; Microsoft §3.1.20]
2. EdDSA (Ed25519/Ed448) public keys MUST NOT appear in the SPKI of an intermediate trusted for server authentication. [Mozilla §5.1; CABF BR §6.1.5] *(Mozilla §5.1 permits EdDSA only for certificates carrying `id-kp-emailProtection`.)*
3. Curve25519 and Curve448 public keys MUST NOT appear in the SPKI. [CABF BR §6.1.5] *(Mozilla §5.1 says these curves are "not prohibited, but not currently supported"; the strict prohibition comes from CABF §6.1.5 enumerating only RSA and ECDSA P-256/P-384/P-521.)*
4. If the SPKI is RSA, the encoded modulus MUST be at least 2048 bits. [CABF BR §6.1.5; Mozilla §5.1; Microsoft §3.1.20]
5. If the SPKI is RSA, the modulus size in bits MUST be evenly divisible by 8. [CABF BR §6.1.5; Mozilla §5.1]
6. If the SPKI is RSA, the modulus MUST NOT be 1024 bits (a participating Root CA MUST NOT issue new 1024-bit RSA certificates). [Microsoft §3.1.9] *(Also implied by CABF §6.1.5's ≥2048-bit floor.)*
7. If the SPKI is RSA, the public exponent MUST be an odd integer ≥ 3. [CABF BR §6.1.6]
8. If the SPKI is RSA, the public exponent MUST NOT be 1 (i.e., the key MUST be a valid RSA public key). [Mozilla §5.2]
9. If the SPKI is RSA, the encoded `AlgorithmIdentifier` MUST be byte-for-byte identical to `300d06092a864886f70d0101010500`. [CABF BR §7.1.3.1.1; Mozilla §5.1.1; LE §7.1.3.1]
10. If the SPKI is RSA, the algorithm OID MUST NOT be `id-RSASSA-PSS` (1.2.840.113549.1.1.10). [CABF BR §7.1.3.1.1; Mozilla §5.1.1]
11. If the SPKI is ECDSA, the key MUST lie on NIST P-256, P-384, or P-521 in `namedCurve` form. [CABF BR §6.1.5, §7.1.3.1.2; Mozilla §5.1]
12. The ECDSA SPKI `AlgorithmIdentifier` MUST match the prescribed hex encoding for the curve (P-256: `301306072a8648ce3d020106082a8648ce3d030107`; P-384: `301006072a8648ce3d020106052b81040022`; P-521: `301006072a8648ce3d020106052b81040023`). [CABF BR §7.1.3.1.2; Mozilla §5.1.2]
13. ECDSA SPKI MUST use `namedCurve` form and MUST NOT use `implicitCurve` or `specifiedCurve` forms. [Mozilla §5.1.2]
14. ECDSA keys SHOULD be validated using ECC Full or Partial Public Key Validation (NIST SP 800-56A). [CABF BR §6.1.6; LE §6.1.6]
15. A LE-issued intermediate's SPKI is RSA with a 2048-bit modulus and exponent 65537, or ECDSA P-384. [LE §6.1.5, §6.1.6] *(LE-issued only; LE §7.1 frames this as descriptive practice.)*
16. LE-issued RSA intermediate keys have public exponent 65537 and an odd modulus with no factors smaller than 752. [LE §6.1.6] *(LE-issued only.)*

### 1.8 `issuerUniqueID` / `subjectUniqueID`

1. The `issuerUniqueID` field MUST NOT be present. [CABF BR §7.1.2.5, §7.1.2.6]
2. The `subjectUniqueID` field MUST NOT be present. [CABF BR §7.1.2.5, §7.1.2.6]

## 2. Outer `signatureAlgorithm` field

1. The outer `signatureAlgorithm` field MUST be byte-for-byte identical to `tbsCertificate.signature`. [CABF BR §7.1.2.5, §7.1.2.6]

## 3. Signature algorithm

1. The signature algorithm MUST be one of: RSASSA-PKCS1-v1_5 with SHA-256/384/512, RSASSA-PSS with SHA-256/384/512, or ECDSA with SHA-256/384/512, with the prescribed byte-for-byte `AlgorithmIdentifier` encodings. [CABF BR §7.1.3.2; Mozilla §5.1.1, §5.1.2; Microsoft §3.1.20]
2. The signature algorithm MUST NOT use SHA-1. [Mozilla §5.1.3]
3. Prior to 2026-09-15, the CA SHALL revoke any unexpired subordinate CA certificate that contains RSASSA-PKCS1-v1_5 with SHA-1. [CABF BR §7.1.3.2.1]
4. The narrow same-key SHA-1 reissuance exception in CABF BR §7.1.3.2.1 expires 2026-09-15 and does not apply to new intermediates. [CABF BR §7.1.3.2.1]
5. Mozilla bans SHA-1 on any intermediate chaining to a Mozilla root with only the duplicate-reissuance exception (same-size new key, same-length new serial, addition of an EKU or `pathLenConstraint`). [Mozilla §5.1.3]
6. The signature hash function MUST be SHA-256, SHA-384, or SHA-512 (no MD5, no other algorithms). [Microsoft §3.1.20]
7. If the signature uses an RSASSA-PKCS1-v1_5 `AlgorithmIdentifier`, the parameters field MUST be explicit NULL. [CABF BR §7.1.3.2.1; Mozilla §5.1.1]
8. The exact `AlgorithmIdentifier` byte encodings for each algorithm/hash combination MUST match CABF BR §7.1.3.2 (see `roots.md` §3 for the full enumeration of hex values). [CABF BR §7.1.3.2; Mozilla §5.1.1, §5.1.2]
9. ECDSA signature `AlgorithmIdentifier`s MUST omit the parameters field. [Mozilla §5.1.2]
10. RSASSA-PSS signature `AlgorithmIdentifier`s MUST omit the `trailerField` and MUST include explicit NULL parameters in the inner hash AlgorithmIdentifiers. [Mozilla §5.1.1]
11. If the signing key is ECDSA, the signature hash MUST match the curve: P-256 with SHA-256, P-384 with SHA-384, P-521 with SHA-512. [CABF BR §7.1.3.2.2; Mozilla §5.1.2]

## 4. Extensions

### 4.1 Extensions table — presence and criticality

| Extension | TLS Sub-CA §7.1.2.6 | Tech-Constrained TLS Sub-CA §7.1.2.5 | Critical | Notes |
|---|---|---|---|---|
| `authorityKeyIdentifier` (2.5.29.35) | MUST | MUST | N | [CABF BR §7.1.2.5.1, §7.1.2.6.1, §7.1.2.11.1] |
| `basicConstraints` (2.5.29.19) | MUST | MUST | Y | [CABF BR §7.1.2.5.1, §7.1.2.6.1, §7.1.2.10.4] |
| `certificatePolicies` (2.5.29.32) | MUST | MUST | N | [CABF BR §7.1.2.5.1, §7.1.2.6.1, §7.1.2.10.5] |
| `cRLDistributionPoints` (2.5.29.31) | MUST | MUST | N | [CABF BR §7.1.2.5.1, §7.1.2.6.1, §7.1.2.11.2] |
| `keyUsage` (2.5.29.15) | MUST | MUST | Y | [CABF BR §7.1.2.5.1, §7.1.2.6.1, §7.1.2.10.7] |
| `subjectKeyIdentifier` (2.5.29.14) | MUST | MUST | N | [CABF BR §7.1.2.5.1, §7.1.2.6.1, §7.1.2.11.4] |
| `extKeyUsage` (2.5.29.37) | MUST | MUST | N | [CABF BR §7.1.2.5.1, §7.1.2.6.1, §7.1.2.10.6] |
| `authorityInformationAccess` (1.3.6.1.5.5.7.1.1) | SHOULD | SHOULD | N | [CABF BR §7.1.2.5.1, §7.1.2.6.1, §7.1.2.10.3] |
| `nameConstraints` (2.5.29.30) | MAY | **MUST** | SHOULD be Y (MAY be N) | [CABF BR §7.1.2.5.1, §7.1.2.5.2, §7.1.2.6.1, §7.1.2.10.8] |
| SCT List (1.3.6.1.4.1.11129.2.4.2) | MAY | MAY | N | [CABF BR §7.1.2.5.1, §7.1.2.6.1, §7.1.2.11.3] |
| Any other extension | NOT RECOMMENDED | NOT RECOMMENDED | – | [CABF BR §7.1.2.11.5] |

### 4.2 `authorityKeyIdentifier`

1. The `authorityKeyIdentifier` extension MUST be present. [CABF BR §7.1.2.5.1, §7.1.2.6.1]
2. The `authorityKeyIdentifier` MUST NOT be marked critical. [CABF BR §7.1.2.5.1, §7.1.2.6.1]
3. The `keyIdentifier` field MUST be present and MUST equal the issuing CA's `subjectKeyIdentifier`. [CABF BR §7.1.2.11.1]
4. The `authorityCertIssuer` field MUST NOT be present. [CABF BR §7.1.2.11.1]
5. The `authorityCertSerialNumber` field MUST NOT be present. [CABF BR §7.1.2.11.1]

### 4.3 `basicConstraints`

1. The `basicConstraints` extension MUST be present. [CABF BR §7.1.2.5.1, §7.1.2.6.1]
2. The `basicConstraints` extension MUST be marked critical. [CABF BR §7.1.2.5.1, §7.1.2.6.1]
3. The `cA` boolean MUST be set to TRUE. [CABF BR §7.1.2.10.4]
4. The `pathLenConstraint` field MAY be present. [CABF BR §7.1.2.10.4]
5. A LE-issued intermediate MUST have `pathLenConstraint = 0`. [LE §7.1 (Subordinate CA profile)] *(LE-issued only)*

### 4.4 `keyUsage`

1. The `keyUsage` extension MUST be present. [CABF BR §7.1.2.5.1, §7.1.2.6.1]
2. The `keyUsage` extension MUST be marked critical. [CABF BR §7.1.2.5.1, §7.1.2.6.1]
3. The `keyCertSign` bit MUST be asserted. [CABF BR §7.1.2.10.7]
4. The `cRLSign` bit MUST be asserted. [CABF BR §7.1.2.10.7]
5. If the sub-CA's private key is used to sign OCSP responses, the `digitalSignature` bit MUST be asserted. [CABF BR §7.1.2.10.7]
6. The `nonRepudiation`, `keyEncipherment`, `dataEncipherment`, `keyAgreement`, `encipherOnly`, and `decipherOnly` bits MUST NOT be asserted. [CABF BR §7.1.2.10.7]
7. A LE-issued intermediate's `keyUsage` MUST assert `digitalSignature`, `keyCertSign`, and `cRLSign`, and nothing else. [LE §7.1 (Subordinate CA profile)] *(LE-issued only)*

### 4.5 `subjectKeyIdentifier`

1. The `subjectKeyIdentifier` extension MUST be present. [CABF BR §7.1.2.5.1, §7.1.2.6.1]
2. The `subjectKeyIdentifier` extension MUST NOT be marked critical. [CABF BR §7.1.2.5.1, §7.1.2.6.1]
3. The `subjectKeyIdentifier` value MUST be set per RFC 5280 §4.2.1.2 and MUST be unique within the issuing CA for the given public key. [CABF BR §7.1.2.11.4]

### 4.6 `extKeyUsage`

1. The `extKeyUsage` extension MUST be present. [CABF BR §7.1.2.5.1, §7.1.2.6.1; Mozilla §5.3]
2. The `extKeyUsage` extension MUST NOT be marked critical. [CABF BR §7.1.2.5.1, §7.1.2.6.1]
3. The `extKeyUsage` MUST contain `id-kp-serverAuth` (1.3.6.1.5.5.7.3.1). [CABF BR §7.1.2.10.6]
4. The `extKeyUsage` MAY contain `id-kp-clientAuth` (1.3.6.1.5.5.7.3.2). [CABF BR §7.1.2.10.6]
5. The `extKeyUsage` MUST NOT contain `id-kp-codeSigning` (1.3.6.1.5.5.7.3.3). [CABF BR §7.1.2.10.6; Microsoft §3.1.13]
6. The `extKeyUsage` MUST NOT contain `id-kp-emailProtection` (1.3.6.1.5.5.7.3.4). [CABF BR §7.1.2.10.6; Microsoft §3.1.13; Mozilla §5.3]
7. The `extKeyUsage` MUST NOT contain `id-kp-timeStamping` (1.3.6.1.5.5.7.3.8). [CABF BR §7.1.2.10.6; Microsoft §3.1.13]
8. The `extKeyUsage` MUST NOT contain `id-kp-OCSPSigning` (1.3.6.1.5.5.7.3.9). [CABF BR §7.1.2.10.6]
9. The `extKeyUsage` MUST NOT contain `anyExtendedKeyUsage` (2.5.29.37.0). [CABF BR §7.1.2.10.6; Mozilla §5.3]
10. The `extKeyUsage` MUST NOT contain the Precertificate Signing Certificate OID `1.3.6.1.4.1.11129.2.4.4`. [CABF BR §7.1.2.10.6]
11. The `extKeyUsage` SHOULD NOT contain any OID other than `id-kp-serverAuth` and `id-kp-clientAuth`. [CABF BR §7.1.2.10.6]
12. If the intermediate was created after 2019-01-01, the `extKeyUsage` extension MUST be present (Mozilla scope reinforces 4.6.1), with one exception: a cross-certificate that shares its private key with a corresponding root certificate is exempt from this rule and may omit `extKeyUsage`. [Mozilla §5.3]
13. If the intermediate was disclosed to CCADB before 2026-06-15 and operates beneath a Chrome Root Store root, the `extKeyUsage` MUST contain only `id-kp-serverAuth`, or only `id-kp-serverAuth` and `id-kp-clientAuth`. [Chrome §1.3.2(1)]
14. If the intermediate was disclosed to CCADB on or after 2026-06-15 and operates beneath a Chrome Root Store root, the `extKeyUsage` MUST contain only `id-kp-serverAuth`. [Chrome §1.3.2(1)]
15. If the intermediate is part of an Applicant PKI hierarchy disclosed to CCADB before 2025-06-15, the `extKeyUsage` MUST contain only `id-kp-serverAuth`, or only `id-kp-serverAuth` and `id-kp-clientAuth`. [Chrome §2.3(1)]
16. If the intermediate is part of an Applicant PKI hierarchy disclosed to CCADB on or after 2025-06-15, the `extKeyUsage` MUST contain only `id-kp-serverAuth`. [Chrome §2.3(1)]
17. The intermediate MUST NOT contain a public key that also appears in any other unexpired, unrevoked certificate asserting different `extKeyUsage` values. [Chrome §1.3.2(1), §2.3(1)]
18. If the intermediate sits beneath a TLS-purpose Apple-trusted Root for an applicant on or after 2024-04-15, the `extKeyUsage` MUST contain only `id-kp-serverAuth`, or only `id-kp-serverAuth` and `id-kp-clientAuth`. [Apple §2.1.3]
19. The intermediate MUST NOT share its public key with any other certificate asserting any EKU OID outside the set permitted for the intermediate's root purpose. [Apple §2.1.3]
20. A LE-issued intermediate's `extKeyUsage` MUST contain `id-kp-serverAuth`, MAY contain `id-kp-clientAuth`, and MUST NOT contain any other key-purpose OID. [LE §7.1 (Subordinate CA profile)] *(LE-issued only)*
21. Microsoft will only enable the following EKUs in its store: `id-kp-serverAuth` (1.3.6.1.5.5.7.3.1), `id-kp-clientAuth` (1.3.6.1.5.5.7.3.2), `id-kp-emailProtection` (1.3.6.1.5.5.7.3.4), `id-kp-timeStamping` (1.3.6.1.5.5.7.3.8), and `1.3.6.1.4.1.311.10.3.12` (Document Signing); EKUs outside this set are not recognized by Microsoft but are not themselves cert-content prohibited by §3.4.2. [Microsoft §3.4.2] *(Informational; for a TLS sub-CA, Microsoft §3.1.13 already prohibits combining serverAuth with the other three.)*
22. If the intermediate sits beneath a Mozilla-trusted Root added to the Mozilla Root Store after 2025-03-15 with the Websites trust bit enabled, the `extKeyUsage` MUST contain only `id-kp-serverAuth`, or both `id-kp-serverAuth` and `id-kp-clientAuth`. [Mozilla §7.5.1]
23. If the intermediate is a delegated OCSP-signing certificate sitting beneath a post-2025-03-15 Mozilla-trusted Root with the Websites trust bit, the `extKeyUsage` MUST contain only `id-kp-OCSPSigning`. [Mozilla §7.5.1]
24. If the intermediate sits beneath a Mozilla-trusted Root added after 2025-03-15 with the email trust bit enabled, the `extKeyUsage` MUST contain `id-kp-emailProtection`. [Mozilla §7.5.2]
25. If the intermediate sits beneath a Mozilla-trusted Root added after 2025-03-15 with the email trust bit enabled, the `extKeyUsage` MUST NOT contain `id-kp-serverAuth`, `id-kp-codeSigning`, `id-kp-timeStamping`, or `anyExtendedKeyUsage`. [Mozilla §7.5.2]
26. If the intermediate sits beneath an S/MIME-purpose Apple-trusted Root (applicant on or after 2024-04-15), the `extKeyUsage` MUST contain only `id-kp-emailProtection`, or only `id-kp-emailProtection` and `id-kp-clientAuth`. [Apple §2.1.3]
27. If the intermediate sits beneath a Client-Authentication-purpose Apple-trusted Root (applicant on or after 2024-04-15), the `extKeyUsage` MUST contain `id-kp-clientAuth` and MUST NOT contain `id-kp-serverAuth`, `id-kp-emailProtection`, or `id-kp-timeStamping`. [Apple §2.1.3]
28. If the intermediate sits beneath a Timestamping-purpose Apple-trusted Root (applicant on or after 2024-04-15), the `extKeyUsage` MUST contain only `id-kp-timeStamping`. [Apple §2.1.3]

### 4.7 `certificatePolicies`

1. The `certificatePolicies` extension MUST be present. [CABF BR §7.1.2.5.1, §7.1.2.6.1]
2. The `certificatePolicies` extension MUST NOT be marked critical. [CABF BR §7.1.2.5.1, §7.1.2.6.1]
3. If the Subordinate CA is an Affiliate of the Issuing CA, the extension MAY contain exactly one `PolicyInformation` with `policyIdentifier = anyPolicy` (2.5.29.32.0); in that case no other `PolicyInformation` MUST be present. [CABF BR §7.1.2.10.5]
4. Otherwise, the extension MUST contain exactly one CABF Reserved Certificate Policy Identifier (one of `2.23.140.1.2.1`, `2.23.140.1.2.2`, `2.23.140.1.2.3`, or `2.23.140.1.1`) associated with each Subscriber Certificate type directly or transitively issued. [CABF BR §7.1.2.10.5]
5. In the non-affiliated case, `anyPolicy` MUST NOT be present. [CABF BR §7.1.2.10.5]
6. The first `PolicyInformation` SHOULD be the Reserved Certificate Policy Identifier. [CABF BR §7.1.2.10.5, footnote `first_policy_note`]
7. `policyQualifiers` are NOT RECOMMENDED; if present, MUST contain only `id-qt-cps` (1.3.6.1.5.5.7.2.1) qualifiers with an HTTP or HTTPS URL. [CABF BR §7.1.2.10.5]
8. `policyQualifiers` MUST NOT include any qualifier other than `id-qt-cps`. [CABF BR §7.1.2.10.5]
9. A LE-issued intermediate's `certificatePolicies` MUST assert `2.23.140.1.2.1` (CABF Domain Validated). [LE §7.1 (Subordinate CA profile)] *(LE-issued only)*

### 4.8 `cRLDistributionPoints`

1. The `cRLDistributionPoints` extension MUST be present. [CABF BR §7.1.2.5.1, §7.1.2.6.1, §7.1.2.11.2]
2. The `cRLDistributionPoints` extension MUST NOT be marked critical. [CABF BR §7.1.2.5.1, §7.1.2.6.1]
3. The extension MUST contain at least one `DistributionPoint`; more than one is NOT RECOMMENDED. [CABF BR §7.1.2.11.2]
4. Each `DistributionPoint`'s `distributionPoint` field MUST be a `fullName`, MUST NOT include `reasons`, and MUST NOT include `cRLIssuer`. [CABF BR §7.1.2.11.2]
5. The `fullName` MUST contain at least one `GeneralName`; every `GeneralName` MUST be `uniformResourceIdentifier`; every URI scheme MUST be `http`. [CABF BR §7.1.2.11.2]
6. The first `GeneralName` MUST be the HTTP URL of the issuing CA's CRL service. [CABF BR §7.1.2.11.2]
7. The URL in `cRLDistributionPoints` MUST match exactly the URL disclosed in CCADB for the issuing CA. [CCADB §6.2]
8. The `cRLDistributionPoints` extension MUST NOT point to a non-operational CRL service. [Mozilla §5.2]
9. The intermediate MUST contain at least one of: a `cRLDistributionPoints` extension with a valid CRL URL, or an `authorityInformationAccess` extension with a valid OCSP URL. [Microsoft §3.1.10]

### 4.9 `authorityInformationAccess`

1. The `authorityInformationAccess` extension SHOULD be present. [CABF BR §7.1.2.5.1, §7.1.2.6.1]
2. If present, the extension MUST NOT be marked critical. [CABF BR §7.1.2.5.1, §7.1.2.6.1]
3. If present, each `AccessDescription` MUST have an `accessMethod` of `id-ad-ocsp` (1.3.6.1.5.5.7.48.1) with an HTTP `uniformResourceIdentifier` `accessLocation`, or `id-ad-caIssuers` (1.3.6.1.5.5.7.48.2) with an HTTP `uniformResourceIdentifier` `accessLocation`. [CABF BR §7.1.2.10.3]
4. No `accessMethod` other than `id-ad-ocsp` or `id-ad-caIssuers` is permitted. [CABF BR §7.1.2.10.3]
5. If an OCSP URL appears in AIA, it MUST point to an operational OCSP responder. [Mozilla §5.2]
6. A LE-issued intermediate's AIA MUST contain a `caIssuers` URL and MAY contain an OCSP URL. [LE §7.1 (Subordinate CA profile)] *(LE-issued only)*

### 4.10 `nameConstraints`

**Note**: `nameConstraints` is OPTIONAL on a §7.1.2.6 TLS Sub-CA but **MUST** be present on a §7.1.2.5 Technically Constrained TLS Sub-CA.

1. If present, the `nameConstraints` extension SHOULD be marked critical; MAY be non-critical for legacy interoperability. [CABF BR §7.1.2.10.8, §7.1.2.5.2]
2. If present, every `GeneralSubtree` MUST omit `minimum` and MUST omit `maximum`. [CABF BR §7.1.2.10.8, §7.1.2.5.2]
3. If present on a generic TLS Sub-CA (§7.1.2.6), `dNSName`, `iPAddress`, and `directoryName` are MAY in `permittedSubtrees`/`excludedSubtrees`; `rfc822Name`, `otherName`, and any other GeneralName type are NOT RECOMMENDED (the MUST NOT rule for other types applies only to Technically Constrained TLS Sub-CA, §7.1.2.5.2). [CABF BR §7.1.2.10.8]

**If the certificate is a Technically Constrained TLS Sub-CA (§7.1.2.5):**

4. The `nameConstraints` extension MUST be present. [CABF BR §7.1.2.5.1]
5. `permittedSubtrees` MUST contain at least one `dNSName` GeneralSubtree, unless `dNSName` is excluded entirely via a zero-length `dNSName` in `excludedSubtrees`. [CABF BR §7.1.2.5.2]
6. `permittedSubtrees` MUST contain at least one `iPAddress` GeneralSubtree, unless `iPAddress` is excluded entirely via 0.0.0.0/0 AND ::/0 GeneralSubtrees in `excludedSubtrees`. [CABF BR §7.1.2.5.2]
7. `permittedSubtrees` MUST contain at least one `directoryName` GeneralSubtree. [CABF BR §7.1.2.5.2]
8. If no `dNSName` GeneralSubtree appears in `permittedSubtrees`, `excludedSubtrees` MUST include a zero-length `dNSName` (i.e., the whole DNS namespace is excluded). [CABF BR §7.1.2.5.2]
9. If no IPv4 `iPAddress` GeneralSubtree appears in `permittedSubtrees`, `excludedSubtrees` MUST include an `iPAddress` of 8 zero octets (0.0.0.0/0). [CABF BR §7.1.2.5.2]
10. If no IPv6 `iPAddress` GeneralSubtree appears in `permittedSubtrees`, `excludedSubtrees` MUST include an `iPAddress` of 32 zero octets (::/0). [CABF BR §7.1.2.5.2]
11. `excludedSubtrees` with `directoryName` is NOT RECOMMENDED. [CABF BR §7.1.2.5.2]
12. Each `dNSName` value in `permittedSubtrees` MUST be a domain the applicant has registered or been authorized to act for. [CABF BR §7.1.2.5.2]
13. Each `iPAddress` range in `permittedSubtrees` MUST be one the applicant has been assigned or authorized to use. [CABF BR §7.1.2.5.2]
14. Each `directoryName` in `permittedSubtrees` MUST be consistent with the subject naming the issuing CA will permit in issued certificates. [CABF BR §7.1.2.5.2]
15. `otherName` GeneralNames are NOT RECOMMENDED; if present they MUST apply in the context of the public Internet (or under an applicant-owned OID arc), MUST NOT mislead the relying party, and MUST be DER-encoded per the ASN.1 module defining the otherName. [CABF BR §7.1.2.5.2]
16. All GeneralName types other than `dNSName`, `iPAddress`, `directoryName`, and `otherName` MUST NOT appear in `permittedSubtrees`/`excludedSubtrees`. [CABF BR §7.1.2.5.2]

**Mozilla cross-cutting rules:**

17. If the intermediate's EKU contains `id-kp-serverAuth` AND the intermediate is intended to be technically constrained, the `nameConstraints` extension MUST be present and shaped per CABF §7.1.2.5.2. [Mozilla §5.3.1]

### 4.11 Signed Certificate Timestamp List

1. If present, the SCT List extension MUST NOT be marked critical. [CABF BR §7.1.2.5.1, §7.1.2.6.1]
2. If present, the `extnValue` MUST be an `OCTET STRING` containing a `SignedCertificateTimestampList` per RFC 6962 §3.3. [CABF BR §7.1.2.11.3]

### 4.12 Other extensions

1. Any extension not listed above is NOT RECOMMENDED. [CABF BR §7.1.2.5.1, §7.1.2.6.1]
2. Any extension present MUST be DER-encoded according to the ASN.1 module defining it. [CABF BR §7.1.2.11.5]
3. Any extension present MUST apply in the context of the public Internet (or fall within an OID arc demonstrably owned by the applicant). [CABF BR §7.1.2.11.5]
4. Any extension present MUST NOT include semantics that mislead the relying party. [CABF BR §7.1.2.11.5]

## 5. CRL profile rules pointed-to by `cRLDistributionPoints`

A linter that fetches and inspects the CRL referenced by an intermediate's `cRLDistributionPoints` MUST verify the following.

1. The CRL MUST be X.509 v2 (`tbsCertList.version` = 1). [CABF BR §7.2.1]
2. The CRL `issuer` MUST be byte-for-byte identical to the `subject` of the issuing CA of this intermediate. [CABF BR §7.2]
3. The CRL MUST be signed using one of the algorithms in CABF BR §7.1.3.2. [CABF BR §7.2]
4. The CRL MUST contain a non-critical `authorityKeyIdentifier` extension. [CABF BR §7.2.2]
5. The CRL MUST contain a non-critical `CRLNumber` extension whose value is an integer in `[0, 2^159)` and strictly increasing. [CABF BR §7.2.2]
6. If the CRL's scope does not include all unexpired certificates issued by the CA, it MUST contain a critical `IssuingDistributionPoint` extension whose `distributionPoint` is a `fullName` containing only `uniformResourceIdentifier` GeneralNames, at least one of which is byte-for-byte identical to a `uniformResourceIdentifier` in the certificate's `cRLDistributionPoints`. [CABF BR §7.2.2.1; Mozilla §6.1.2]
7. The CRL's `IssuingDistributionPoint` MUST NOT assert `indirectCRL` and MUST NOT assert `onlyContainsAttributeCerts`. [CABF BR §7.2.2.1]
8. The CRL's `IssuingDistributionPoint` MUST NOT assert both `onlyContainsUserCerts` and `onlyContainsCACerts`. [CABF BR §7.2.2.1]
9. The CRL `nextUpdate` MUST be at most 12 months after `thisUpdate` for CRLs covering sub-CA certs (10 days for subscriber-cert CRLs). [CABF BR §7.2]
10. The CCADB partitioned-CRL rule applies to the CRL issued by this intermediate: when partitioned, each CRL MUST contain a critical IDP with a `uniformResourceIdentifier` exactly matching a CCADB-disclosed URL. [CCADB §6.2; Apple §2.1.2]
11. When the CCADB record uses a single Full CRL URL, the referenced CRL SHOULD NOT contain an `Issuing Distribution Point` extension. [CCADB §6.2; Apple §2.1.2]

## 6. Technically Constrained Non-TLS Subordinate CA (CABF §7.1.2.3) divergences

If the certificate is a Technically Constrained Non-TLS Subordinate CA (i.e., explicitly *not* issuing TLS certs), the following deltas apply versus §4 above. This profile is **out of scope** for a TLS-content linter unless you choose to flag dual-purpose mistakes.

1. The `extKeyUsage` extension MUST be present. [CABF BR §7.1.2.3.1]
2. The `extKeyUsage` MUST NOT contain `id-kp-serverAuth`. [CABF BR §7.1.2.3.3]
3. The `extKeyUsage` MUST NOT contain `id-kp-OCSPSigning`. [CABF BR §7.1.2.3.3]
4. The `extKeyUsage` MUST NOT contain `anyExtendedKeyUsage`. [CABF BR §7.1.2.3.3]
5. The `extKeyUsage` MUST NOT contain the Precertificate Signing OID `1.3.6.1.4.1.11129.2.4.4`. [CABF BR §7.1.2.3.3]
6. Multiple independent key purposes (e.g., `id-kp-codeSigning` and `id-kp-timeStamping`) in the same Non-TLS Sub-CA are NOT RECOMMENDED. [CABF BR §7.1.2.3.3]
7. `nameConstraints` is OPTIONAL (`MAY`) rather than `MUST` on this profile. [CABF BR §7.1.2.3.1]
8. `certificatePolicies` is OPTIONAL (`MAY`); if present, the CABF Reserved Certificate Policy Identifiers MUST NOT be asserted (since they imply TLS issuance). [CABF BR §7.1.2.3.2]

## 7. Out-of-scope-intermediate signaling

A linter may use the following EKU/nameConstraints shape to determine whether an intermediate is *in scope* for Mozilla's TLS-server-auth policy.

1. An intermediate is treated as out of scope (not capable of TLS/email issuance) if its `extKeyUsage` lacks `anyExtendedKeyUsage`, `id-kp-serverAuth`, and `id-kp-emailProtection`, OR if it carries `nameConstraints` disallowing SANs of types `dNSName`, `iPAddress`, `SRVName`, and `rfc822Name`. [Mozilla §1.1]

## 8. ASN.1 / DER encoding

1. The certificate MUST be valid ASN.1 DER with no encoding errors. [Mozilla §5.2]
2. Each `Name` MUST contain an `RDNSequence`; each `RelativeDistinguishedName` MUST contain exactly one `AttributeTypeAndValue`. [CABF BR §7.1.4.1]

## 9. Notes and intentional non-requirements

- Intermediates are not required to be logged to Certificate Transparency.
- The Chrome §1.3.1.3 maximum sub-CA validity of 3 years is `SHOULD`, not `MUST`. The CABF BR has no explicit maximum on sub-CA validity in §7.1.2.5/§7.1.2.6 beyond it not exceeding the issuing root's `notAfter`.
- The OCSP Responder Certificate profile (CABF §7.1.2.8) is a distinct profile from intermediates, even though both are CA-signed; OCSP responder certs are end-entity certs (cA = FALSE) with EKU `id-kp-OCSPSigning` only. See `leaves.md` (or out-of-scope notes).
- Apple §2.1.3 single-purpose root rules cascade: under a TLS-purpose Apple root, sub-CAs follow the EKU rules in §4.6.18–4.6.19; under S/MIME, Code-Signing, Client-Auth, or Timestamping roots, the equivalent narrowing applies but is out of scope of this TLS-focused document.
- LE-specific items (marked *LE-issued only*) bind LE-issued intermediates; they tighten but never loosen any universal CABF/program rule.
