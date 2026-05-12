# Cross-Certified Subordinate CA Certificate Requirements

This document collects the most restrictive certificate-content requirements that apply to a **cross-certified subordinate CA certificate**: a CA certificate that uses the same `subject` DN and `subjectPublicKeyInfo` as an existing CA certificate (Root or Subordinate) but is signed by a different issuing CA. Cross-signed roots — where a publicly-trusted root is re-issued by another root — are a sub-case of this profile.

Citations point into the policy documents in this directory:

- `[CABF BR §X]` → `cabf_br.md`
- `[Mozilla §X]` → `mozilla.md`
- `[Chrome §X]` → `chrome.md`
- `[Apple §X]` → `apple.md`
- `[Microsoft §X]` → `microsoft.md`
- `[CCADB §X]` → `ccadb.md`
- `[LE §X]` → `letsencrypt_cp_cps.md` (LE-issued certs only)

## 1. Pre-conditions on the existence of a cross-certificate

1. Before issuing a cross-certificate, the issuing CA MUST confirm that the existing CA certificate (whose `subject` and SPKI are being rebound) is subject to the Baseline Requirements and was issued in compliance with the then-current Baseline Requirements at the time of its issuance. [CABF BR §7.1.2.2]
2. The cross-certificate's `subject` DN MUST be byte-for-byte identical to the encoded `subject` of the existing CA certificate (the prerequisite-compliance check in 1.1 is what permits this exception to the general §7.1.4 naming requirements). [CABF BR §7.1.2.2.2]
3. The cross-certificate's `subjectPublicKeyInfo` MUST be byte-for-byte identical to that of the existing CA certificate. [CABF BR §7.1.2.2 (implicit in the definition of a cross-certificate)]

## 2. Structural / `tbsCertificate` fields

### 2.1 Version

1. The certificate `version` field MUST be v3 (integer value 2). [CABF BR §7.1.1, §7.1.2.2]

### 2.2 Serial number

1. The certificate `serialNumber` MUST be greater than zero. [CABF BR §7.1.2.2; Mozilla §5.2]
2. The certificate `serialNumber` MUST be less than 2^159. [CABF BR §7.1.2.2]
3. The certificate `serialNumber` MUST contain at least 64 bits of output from a CSPRNG. [CABF BR §7.1.2.2; Mozilla §5.2]
4. The certificate `serialNumber` MUST be non-sequential. [CABF BR §7.1.2.2]
5. The combination of `issuer` DN and `serialNumber` MUST be unique within the issuing CA (a CT precertificate sharing serial with its final cert is the only exception). [Mozilla §5.2]

### 2.3 Signature (inside `tbsCertificate`)

1. The encoded value of `tbsCertificate.signature` MUST be byte-for-byte identical to the outer `signatureAlgorithm`. [CABF BR §7.1.2.2]
2. The signature `AlgorithmIdentifier` MUST be one of the encodings permitted by CABF BR §7.1.3.2 (see §3 below). [CABF BR §7.1.3.2; LE §7.1.3.2]

### 2.4 Issuer

1. The encoded `issuer` MUST be byte-for-byte identical to the encoded `subject` of the issuing CA certificate. [CABF BR §7.1.2.2, §7.1.4.1]
2. The cross-certificate MUST be verifiable under the issuing CA's public key.

### 2.5 Validity

1. The `notBefore` value MUST be no later than the time of signing. [CABF BR §7.1.2.2.1]
2. The `notBefore` value MUST be no earlier than the earlier of (a) one day prior to the time of signing or (b) the earliest `notBefore` date among existing CA certificates with the same subject+SPKI. [CABF BR §7.1.2.2.1]
3. The `notAfter` value MUST be no earlier than the time of signing. [CABF BR §7.1.2.2.1]
4. The `notAfter` value is otherwise unspecified by the CABF profile and inherits whatever bounds apply via root-program lifecycle rules below.
5. If the cross-certificate is intended to remain compliant with Chrome's subordinate-CA lifecycle guidance, the validity period (`notAfter − notBefore`) SHOULD be no more than 3 years. [Chrome §1.3.1.3]
6. LE-issued cross or subordinate CA certificates MUST have a validity period of at most 8 years. [LE §7.1 (Subordinate CA profile)] *(LE-issued only)*

### 2.6 Subject

1. The cross-certificate's `subject` DN MUST be byte-for-byte identical to the encoded `subject` of the existing CA certificate. [CABF BR §7.1.2.2.2]
2. The pre-existing `subject` DN it copies MUST itself comply with CABF BR §7.1.4 attribute encoding and ordering rules at the time the existing CA certificate was issued. [CABF BR §7.1.2.2.2, §7.1.4]
3. If the existing CA certificate did not comply with the then-current Baseline Requirements at its issuance, this cross-certificate profile MUST NOT be used (the cross-certificate would instead need to be issued under the standard `subject` rules of §7.1.4). [CABF BR §7.1.2.2.2]
4. Because the cross-certificate's `subject` is byte-identical to that of an existing CA certificate (§2.6 #1), it inherits that existing certificate's profile-specific subject restrictions: if the existing certificate was a Root CA (§7.1.2.1), TLS Subordinate CA (§7.1.2.6), or Technically Constrained TLS Subordinate CA (§7.1.2.5), then `organizationalUnitName` MUST NOT appear in the subject; for other CA profiles, `organizationalUnitName` SHOULD NOT appear. [CABF BR §7.1.2.10.2, §7.1.2.2.2]

### 2.7 `subjectPublicKeyInfo`

1. The SPKI algorithm MUST be one of RSA (`rsaEncryption`, OID 1.2.840.113549.1.1.1) or ECDSA (`id-ecPublicKey`, OID 1.2.840.10045.2.1). [CABF BR §7.1.3.1; Mozilla §5.1]
2. EdDSA (Ed25519/Ed448) public keys MUST NOT appear in the SPKI of a cross-certificate trusted for server authentication. [Mozilla §5.1; CABF BR §6.1.5] *(Mozilla §5.1 permits EdDSA only for certificates carrying `id-kp-emailProtection`.)*
3. Curve25519 and Curve448 public keys MUST NOT appear in the SPKI. [CABF BR §6.1.5] *(Mozilla §5.1 describes them as "not prohibited, but not currently supported"; the strict prohibition comes from CABF §6.1.5 which enumerates only RSA and ECDSA P-256/P-384/P-521.)*
4. If the SPKI is RSA, the encoded modulus MUST be at least 2048 bits. [CABF BR §6.1.5; Mozilla §5.1]
5. If the SPKI is RSA, the modulus size in bits MUST be evenly divisible by 8. [CABF BR §6.1.5; Mozilla §5.1]
6. If the SPKI is RSA, the modulus MUST NOT be 1024 bits (a participating Root CA MUST NOT issue new 1024-bit RSA certificates). [Microsoft §3.1.9] *(Also implied by CABF §6.1.5's ≥2048-bit floor.)*
7. If the SPKI is RSA, the public exponent MUST be an odd integer ≥ 3. [CABF BR §6.1.6]
8. If the SPKI is RSA, the encoded `AlgorithmIdentifier` MUST be byte-for-byte identical to `300d06092a864886f70d0101010500` (`rsaEncryption` with explicit NULL). [CABF BR §7.1.3.1.1; Mozilla §5.1.1; LE §7.1.3.1]
9. If the SPKI is RSA, the SPKI algorithm OID MUST NOT be `id-RSASSA-PSS` (1.2.840.113549.1.1.10). [CABF BR §7.1.3.1.1; Mozilla §5.1.1]
10. If the SPKI is ECDSA, the key MUST lie on NIST P-256, P-384, or P-521 in `namedCurve` form. [CABF BR §6.1.5, §7.1.3.1.2; Mozilla §5.1]
11. The ECDSA SPKI `AlgorithmIdentifier` MUST match the prescribed hex encoding for the curve (`301306072a8648ce3d020106082a8648ce3d030107` for P-256; `301006072a8648ce3d020106052b81040022` for P-384; `301006072a8648ce3d020106052b81040023` for P-521). [CABF BR §7.1.3.1.2; Mozilla §5.1.2]
12. If the SPKI is RSA, the public exponent MUST NOT be 1 (i.e., the key MUST be a valid RSA public key). [Mozilla §5.2]
13. A LE-issued cross-certificate's SPKI is RSA with a 2048-bit modulus and exponent 65537, or ECDSA on NIST P-384. [LE §6.1.5, §6.1.6] *(LE-issued only; LE §7.1 frames this as descriptive practice rather than a per-issuance MUST.)*

### 2.8 `issuerUniqueID` / `subjectUniqueID`

1. The `issuerUniqueID` field MUST NOT be present. [CABF BR §7.1.2.2]
2. The `subjectUniqueID` field MUST NOT be present. [CABF BR §7.1.2.2]

## 3. Outer `signatureAlgorithm` field and signature algorithm

1. The outer `signatureAlgorithm` MUST be byte-for-byte identical to `tbsCertificate.signature`. [CABF BR §7.1.2.2]
2. The signature algorithm MUST be one of: RSASSA-PKCS1-v1_5 with SHA-256/384/512, RSASSA-PSS with SHA-256/384/512, or ECDSA with SHA-256/384/512, with the prescribed byte-for-byte `AlgorithmIdentifier` encodings of CABF BR §7.1.3.2. [CABF BR §7.1.3.2; Mozilla §5.1.1, §5.1.2; Microsoft §3.1.20]
3. The signature algorithm MUST NOT use SHA-1, except for the narrow same-key reissuance exception in CABF BR §7.1.3.2.1 (available only "Until 2026-09-15") that permits RSASSA-PKCS1-v1_5 with SHA-1 in a Subordinate CA Certificate that is a Cross-Certificate when an existing same-issuer certificate used SHA-1, the existing serial had ≥64 bits, and the only differences from the existing certificate are limited to: a new subjectPublicKey of the same algorithm/size, a new serial of the same encoded length, an `extKeyUsage` whose key purposes exclude `id-kp-serverAuth` and `anyExtendedKeyUsage`, and/or a `pathLenConstraint` of zero. [CABF BR §7.1.3.2.1]
4. Prior to 2026-09-15, the CA SHALL revoke any unexpired Subordinate CA Certificate (including any cross-certificate functioning as a Subordinate CA Certificate) that contains `RSASSA-PKCS1-v1_5 with SHA-1` within the certificate. [CABF BR §7.1.3.2.1]
5. Effective 2026-09-15, the §3 #3 narrow SHA-1 reissuance exception ceases to be available; any new cross-certificate signed on or after 2026-09-15 MUST NOT use RSASSA-PKCS1-v1_5 with SHA-1. [CABF BR §7.1.3.2.1 ("Until 2026-09-15…")]
6. The signature algorithm MUST NOT be MD5 or any hash other than the enumerated SHA-1 (deprecated) or SHA-2 family. [Microsoft §3.1.20]
7. Mozilla bans SHA-1 on intermediate (and cross) certificates that chain to a Mozilla root, with a narrow duplicate-reissuance exception applicable only when the new certificate is a duplicate of an existing SHA-1 intermediate certificate with the only changes being all of: a new key of the same size, a new serial number of the same length, and/or the addition of an EKU and/or a `pathLenConstraint`. [Mozilla §5.1.3]
8. Mozilla bans SHA-1 on CT precertificates. [Mozilla §5.1.3]
9. Encoding rules for the `AlgorithmIdentifier` (explicit NULL on PKCS#1 v1.5, omitted parameter on ECDSA, omitted `trailerField` on PSS, explicit NULL on inner PSS hash AlgorithmIdentifiers) apply identically as for roots. [Mozilla §5.1.1, §5.1.2]

## 4. Extensions

### 4.1 Extensions table — presence and criticality

| Extension | Presence | Critical | Notes / source |
|---|---|---|---|
| `authorityKeyIdentifier` (2.5.29.35) | MUST | N | [CABF BR §7.1.2.2.3, §7.1.2.11.1] |
| `basicConstraints` (2.5.29.19) | MUST | Y | [CABF BR §7.1.2.2.3, §7.1.2.10.4] |
| `certificatePolicies` (2.5.29.32) | MUST | N | [CABF BR §7.1.2.2.3, §7.1.2.2.6] |
| `cRLDistributionPoints` (2.5.29.31) | MUST | N | [CABF BR §7.1.2.2.3, §7.1.2.11.2] |
| `keyUsage` (2.5.29.15) | MUST | Y | [CABF BR §7.1.2.2.3, §7.1.2.10.7] |
| `subjectKeyIdentifier` (2.5.29.14) | MUST | N | [CABF BR §7.1.2.2.3, §7.1.2.11.4] |
| `authorityInformationAccess` (1.3.6.1.5.5.7.1.1) | SHOULD | N | [CABF BR §7.1.2.2.3, §7.1.2.10.3] |
| `nameConstraints` (2.5.29.30) | MAY | SHOULD be Y (MAY be N) | [CABF BR §7.1.2.2.3, §7.1.2.10.8] |
| `extKeyUsage` (2.5.29.37) | MUST or SHOULD (per affiliation) | N | [CABF BR §7.1.2.2.3, §7.1.2.2.4, §7.1.2.2.5, footnote `^eku_ca`] |
| SCT List (1.3.6.1.4.1.11129.2.4.2) | MAY | N | [CABF BR §7.1.2.2.3, §7.1.2.11.3] |
| Any other extension | NOT RECOMMENDED | – | [CABF BR §7.1.2.2.3, §7.1.2.11.5] |

### 4.2 `authorityKeyIdentifier`

1. The `authorityKeyIdentifier` extension MUST be present. [CABF BR §7.1.2.2.3]
2. The `authorityKeyIdentifier` MUST NOT be marked critical. [CABF BR §7.1.2.2.3]
3. The `keyIdentifier` field MUST be present and MUST equal the issuing CA's `subjectKeyIdentifier`. [CABF BR §7.1.2.11.1]
4. The `authorityCertIssuer` field MUST NOT be present. [CABF BR §7.1.2.11.1]
5. The `authorityCertSerialNumber` field MUST NOT be present. [CABF BR §7.1.2.11.1]

### 4.3 `basicConstraints`

1. The `basicConstraints` extension MUST be present. [CABF BR §7.1.2.2.3]
2. The `basicConstraints` extension MUST be marked critical. [CABF BR §7.1.2.2.3]
3. The `cA` boolean MUST be set to TRUE. [CABF BR §7.1.2.10.4]
4. The `pathLenConstraint` field MAY be present. [CABF BR §7.1.2.10.4]

### 4.4 `keyUsage`

1. The `keyUsage` extension MUST be present. [CABF BR §7.1.2.2.3]
2. The `keyUsage` extension MUST be marked critical. [CABF BR §7.1.2.2.3]
3. The `keyCertSign` bit MUST be asserted. [CABF BR §7.1.2.10.7]
4. The `cRLSign` bit MUST be asserted. [CABF BR §7.1.2.10.7]
5. If the cross-CA private key is used to sign OCSP responses, the `digitalSignature` bit MUST be asserted. [CABF BR §7.1.2.10.7]
6. The `nonRepudiation`, `keyEncipherment`, `dataEncipherment`, `keyAgreement`, `encipherOnly`, and `decipherOnly` bits MUST NOT be asserted. [CABF BR §7.1.2.10.7]

### 4.5 `subjectKeyIdentifier`

1. The `subjectKeyIdentifier` extension MUST be present. [CABF BR §7.1.2.2.3]
2. The `subjectKeyIdentifier` extension MUST NOT be marked critical. [CABF BR §7.1.2.2.3]
3. The `subjectKeyIdentifier` value MUST be set per RFC 5280 §4.2.1.2 and MUST be unique within the issuing CA for the given public key. [CABF BR §7.1.2.11.4]

### 4.6 `extKeyUsage` — affiliation drives the EKU shape

1. The `extKeyUsage` extension MUST be marked non-critical when present. [CABF BR §7.1.2.2.3]
2. If the cross-certificate's Issuer and Subject organizations are the same (or Subject is an Affiliate of Issuer) AND the cross-certificate's Subject CA is operated by the same organization as the Issuing CA (or an Affiliate), the `extKeyUsage` extension MAY be "unrestricted" containing only `anyExtendedKeyUsage` (2.5.29.37.0). In that case, no other key purpose OID MUST appear alongside `anyExtendedKeyUsage`. [CABF BR §7.1.2.2.3, §7.1.2.2.4]
3. In all other cases (issuer and subject organizations are not affiliated), the `extKeyUsage` extension MUST be "restricted" — `anyExtendedKeyUsage` MUST NOT be present and per-purpose rules in 4.6.4–4.6.6 below apply. [CABF BR §7.1.2.2.3, §7.1.2.2.5]
4. If the cross-certificate's subordinate hierarchy issues TLS certificates directly or transitively, then `id-kp-serverAuth` (1.3.6.1.5.5.7.3.1) MUST be present; `id-kp-clientAuth` (1.3.6.1.5.5.7.3.2) MAY be present; `id-kp-emailProtection` (1.3.6.1.5.5.7.3.4), `id-kp-codeSigning` (1.3.6.1.5.5.7.3.3), `id-kp-timeStamping` (1.3.6.1.5.5.7.3.8), and `anyExtendedKeyUsage` MUST NOT be present; any other OID is NOT RECOMMENDED. [CABF BR §7.1.2.2.5]
5. If the cross-certificate's subordinate hierarchy does not issue TLS certificates directly or transitively, then `id-kp-serverAuth` MUST NOT be present, `anyExtendedKeyUsage` MUST NOT be present, and any other key purpose MAY be present. [CABF BR §7.1.2.2.5]
6. Every key-purpose OID included MUST apply in the context of the public Internet (or fall within an OID arc demonstrably owned by the applicant). [CABF BR §7.1.2.2.5]
7. Every key-purpose OID included MUST be one the issuing CA has verified the subordinate CA is authorized to assert. [CABF BR §7.1.2.2.5]
8. The CA MUST NOT include a key-purpose OID unless it has a reason to do so. [CABF BR §7.1.2.2.5]
9. The CABF unrestricted "anyExtendedKeyUsage" form is treated as in-scope for TLS audit if also accompanied by no EKU, by Chrome — see §6 below. [Chrome §1.4]

#### CCADB §6.3 dedicated-EKU rules for cross-certificates issued on or after 2025-06-15

CCADB §6.3 establishes per-purpose mandatory EKU shapes for cross-certificates issued on or after 2025-06-15. These rules apply only when the Subject CA's public key already exists in (or might exist in) a publicly-trusted self-signed Root CA Certificate whose hierarchy is considered dedicated to a specific PKI use case. When that condition is met, the rules tighten the restricted-EKU table above. A linter MUST select the rule that matches the Subject hierarchy's dedication.

10. If the cross-certificate is issued on or after 2025-06-15 and the Subject CA's public key exists or might exist in a publicly-trusted self-signed Root CA dedicated to TLS server authentication, the cross-certificate's `extKeyUsage` MUST contain exactly the single OID `1.3.6.1.5.5.7.3.1` (`id-kp-serverAuth`). [CCADB §6.3]
11. If the cross-certificate is issued on or after 2025-06-15 and the Subject CA's public key exists or might exist in a publicly-trusted self-signed Root CA dedicated to TLS client authentication, the cross-certificate's `extKeyUsage` MUST contain exactly the single OID `1.3.6.1.5.5.7.3.2` (`id-kp-clientAuth`). [CCADB §6.3]
12. If the cross-certificate is issued on or after 2025-06-15 and the Subject CA's public key exists or might exist in a publicly-trusted self-signed Root CA dedicated to TLS (generic), the cross-certificate's `extKeyUsage` MUST contain exactly `1.3.6.1.5.5.7.3.1` and `1.3.6.1.5.5.7.3.2` and no other key-purpose OID. [CCADB §6.3]
13. If the cross-certificate is issued on or after 2025-06-15 and the Subject CA's public key exists or might exist in a publicly-trusted self-signed Root CA dedicated to S/MIME, the cross-certificate's `extKeyUsage` MUST contain exactly the single OID `1.3.6.1.5.5.7.3.4` (`id-kp-emailProtection`). [CCADB §6.3]
14. If the cross-certificate is issued on or after 2025-06-15 and the Subject CA's public key exists or might exist in a publicly-trusted self-signed Root CA dedicated to S/MIME (generic), the cross-certificate's `extKeyUsage` MUST contain exactly `1.3.6.1.5.5.7.3.4` and `1.3.6.1.5.5.7.3.2` and no other key-purpose OID. [CCADB §6.3]
15. If the cross-certificate is issued on or after 2025-06-15 and the Subject CA's public key exists or might exist in a publicly-trusted self-signed Root CA dedicated to Code Signing, the cross-certificate's `extKeyUsage` MUST contain exactly the single OID `1.3.6.1.5.5.7.3.3` (`id-kp-codeSigning`). [CCADB §6.3]
16. If both the Issuer and Subject hierarchies of the cross-certificate are capable of issuing Extended Validation (EV) certificates, the `certificatePolicies` extension MUST include the CABF EV Reserved Certificate Policy Identifier `2.23.140.1.1` as a `policyIdentifier` (additional `policyIdentifier`s MAY be present). [CCADB §6.3]

#### Mozilla §5.3 intermediate-EKU rules (apply to any cross-cert that functions as an intermediate)

17. If the cross-certificate was created after 2019-01-01, it MUST contain an `extKeyUsage` extension. [Mozilla §5.3]
18. If the cross-certificate was created after 2019-01-01, the `extKeyUsage` extension MUST NOT contain `anyExtendedKeyUsage`. [Mozilla §5.3]
19. If the cross-certificate was created after 2019-01-01, the `extKeyUsage` extension MUST NOT contain both `id-kp-serverAuth` and `id-kp-emailProtection` in the same certificate. [Mozilla §5.3]
20. Exception to 4.6.17–4.6.19: the Mozilla §5.3 post-2019 EKU requirement does not apply to a cross-certificate that shares its private key with a corresponding root certificate; such a cross-certificate is exempt from the EKU-presence requirement and may omit the `extKeyUsage` extension entirely. [Mozilla §5.3]

#### Chrome §1.3.2 dedicated-TLS hierarchy EKU rules

21. If the cross-certificate operates beneath a Chrome Root Store root and was disclosed to CCADB before 2026-06-15, the `extKeyUsage` MUST contain only `id-kp-serverAuth`, or only `id-kp-serverAuth` and `id-kp-clientAuth`. [Chrome §1.3.2(1)]
22. If the cross-certificate operates beneath a Chrome Root Store root and was disclosed to CCADB on or after 2026-06-15, the `extKeyUsage` MUST contain only `id-kp-serverAuth`. [Chrome §1.3.2(1)]
23. The cross-certificate MUST NOT contain a public key (SPKI) that also appears in any other unexpired, unrevoked certificate asserting different `extKeyUsage` values. [Chrome §1.3.2(1)]
24. If the cross-certificate is part of an Applicant PKI hierarchy and was disclosed to CCADB before 2025-06-15, the `extKeyUsage` MUST contain only `id-kp-serverAuth`, or only `id-kp-serverAuth` and `id-kp-clientAuth`. [Chrome §2.3(1)]
25. If the cross-certificate is part of an Applicant PKI hierarchy and was disclosed to CCADB on or after 2025-06-15, the `extKeyUsage` MUST contain only `id-kp-serverAuth`. [Chrome §2.3(1)]

#### Mozilla §7.5 dedicated-root cascade (roots added to Mozilla Root Store after 2025-03-15)

26. If the cross-certificate sits beneath a Mozilla-trusted Root added to the Mozilla Root Store after 2025-03-15 with the Websites trust bit enabled, the `extKeyUsage` MUST contain only `id-kp-serverAuth`, or both `id-kp-serverAuth` and `id-kp-clientAuth`. [Mozilla §7.5.1]
27. If the cross-certificate is a delegated OCSP-signing certificate sitting beneath a post-2025-03-15 Mozilla-trusted Root with the Websites trust bit, the `extKeyUsage` MUST contain only `id-kp-OCSPSigning`. [Mozilla §7.5.1]
28. If the cross-certificate sits beneath a Mozilla-trusted Root added after 2025-03-15 with the email trust bit enabled, the `extKeyUsage` MUST contain `id-kp-emailProtection`. [Mozilla §7.5.2]
29. If the cross-certificate sits beneath a Mozilla-trusted Root added after 2025-03-15 with the email trust bit enabled, the `extKeyUsage` MUST NOT contain `id-kp-serverAuth`, `id-kp-codeSigning`, `id-kp-timeStamping`, or `anyExtendedKeyUsage`. [Mozilla §7.5.2]

#### Apple §2.1.3 single-purpose root cascade (post-2024-04-15 applicants)

30. If the cross-certificate sits beneath a TLS-purpose Apple-trusted Root (applicant on or after 2024-04-15), the `extKeyUsage` MUST contain only `id-kp-serverAuth`, or only `id-kp-serverAuth` and `id-kp-clientAuth`. [Apple §2.1.3]
31. If the cross-certificate sits beneath a TLS-purpose Apple-trusted Root (applicant on or after 2024-04-15), it MUST NOT share its public key with any other certificate asserting any EKU OID other than `id-kp-serverAuth` or `id-kp-clientAuth`. [Apple §2.1.3]
32. If the cross-certificate sits beneath an S/MIME-purpose Apple-trusted Root (applicant on or after 2024-04-15), the `extKeyUsage` MUST contain only `id-kp-emailProtection`, or only `id-kp-emailProtection` and `id-kp-clientAuth`. [Apple §2.1.3]
33. If the cross-certificate sits beneath a Client-Authentication-purpose Apple-trusted Root (applicant on or after 2024-04-15), the `extKeyUsage` MUST contain `id-kp-clientAuth` and MUST NOT contain `id-kp-serverAuth`, `id-kp-emailProtection`, or `id-kp-timeStamping`. [Apple §2.1.3]
34. If the cross-certificate sits beneath a Timestamping-purpose Apple-trusted Root (applicant on or after 2024-04-15), the `extKeyUsage` MUST contain only `id-kp-timeStamping`. [Apple §2.1.3]
35. If the cross-certificate sits beneath any single-purpose Apple-trusted Root (applicant on or after 2024-04-15), it MUST NOT share its public key with any other certificate asserting any EKU OID outside the set permitted for the root's single purpose. [Apple §2.1.3]

#### Microsoft §3.1.13 EKU separation

36. The cross-certificate's `extKeyUsage` MUST NOT combine any two or more of Server Authentication (`id-kp-serverAuth`), S/MIME (`id-kp-emailProtection`), Code Signing (`id-kp-codeSigning`), and Time Stamping (`id-kp-timeStamping`); each of these four uses MUST live in a separate Issuing CA. [Microsoft §3.1.13]

#### Microsoft §3.4.2 — informational

37. Microsoft will only enable the following EKUs in its store: `id-kp-serverAuth` (1.3.6.1.5.5.7.3.1), `id-kp-clientAuth` (1.3.6.1.5.5.7.3.2), `id-kp-emailProtection` (1.3.6.1.5.5.7.3.4), `id-kp-timeStamping` (1.3.6.1.5.5.7.3.8), and `1.3.6.1.4.1.311.10.3.12` (Document Signing); EKUs outside this set are not recognized by Microsoft but are not themselves cert-content prohibited by §3.4.2. [Microsoft §3.4.2] *(Informational; prohibitions on specific EKUs in TLS cross-certs derive from CABF §7.1.2.2.5 and Microsoft §3.1.13 rather than from §3.4.2.)*

### 4.7 `certificatePolicies`

1. The `certificatePolicies` extension MUST be present. [CABF BR §7.1.2.2.3]
2. The `certificatePolicies` extension MUST NOT be marked critical. [CABF BR §7.1.2.2.3]
3. If the Subordinate CA is an Affiliate of the Issuing CA and the Issuing CA wishes to express no policy restrictions, the extension MAY contain exactly one `PolicyInformation` whose `policyIdentifier` is `anyPolicy` (2.5.29.32.0); in that case no other `PolicyInformation` MUST be present. [CABF BR §7.1.2.2.6]
4. Otherwise, the `certificatePolicies` extension MUST contain at least one CABF Reserved Certificate Policy Identifier (from §7.1.6.1: `2.23.140.1.2.1`, `2.23.140.1.2.2`, `2.23.140.1.2.3`, or `2.23.140.1.1`) associated with the given Subscriber Certificate type transitively issued by this Certificate. [CABF BR §7.1.2.2.6]
5. In the non-affiliated case, `anyPolicy` MUST NOT be present. [CABF BR §7.1.2.2.6]
6. If any subscriber certificate directly chains up to this cross-certificate, exactly one Reserved Certificate Policy Identifier MUST be present. [CABF BR §7.1.2.2.6]
7. Additional CA-defined OIDs MAY appear and MUST be documented in the issuing CA's CP/CPS. [CABF BR §7.1.2.2.6]
8. The first `PolicyInformation` SHOULD be the Reserved Certificate Policy Identifier. [CABF BR §7.1.2.2.6, footnote `first_policy_note`]
9. `policyQualifiers` are NOT RECOMMENDED; if present, MUST contain only `id-qt-cps` (1.3.6.1.5.5.7.2.1) qualifiers with an HTTP or HTTPS URL pointing to the issuing CA's policy materials. [CABF BR §7.1.2.2.6]
10. `policyQualifiers` MUST NOT include any qualifier other than `id-qt-cps`. [CABF BR §7.1.2.2.6]

### 4.8 `cRLDistributionPoints`

1. The `cRLDistributionPoints` extension MUST be present. [CABF BR §7.1.2.2.3, §7.1.2.11.2]
2. The `cRLDistributionPoints` extension MUST NOT be marked critical. [CABF BR §7.1.2.2.3]
3. The extension MUST contain at least one `DistributionPoint`; containing more than one is NOT RECOMMENDED. [CABF BR §7.1.2.11.2]
4. Each `DistributionPoint`'s `distributionPoint` field MUST be a `fullName`, MUST NOT include `reasons`, and MUST NOT include `cRLIssuer`. [CABF BR §7.1.2.11.2]
5. The `fullName` MUST contain at least one `GeneralName`, every `GeneralName` MUST be of type `uniformResourceIdentifier`, and every URI scheme MUST be `http`. [CABF BR §7.1.2.11.2]
6. The first `GeneralName` MUST be the HTTP URL of the Issuing CA's CRL service. [CABF BR §7.1.2.11.2]
7. The URL in `cRLDistributionPoints` MUST match exactly the URL disclosed in CCADB for the issuing CA. [CCADB §6.2]
8. The CA MUST NOT include `cRLDistributionPoints` URIs that point to a CRL service that does not exist. [Mozilla §5.2]
9. The CRL targeted by this URL MUST conform to the partition/IDP rules of CCADB §6.2 and Mozilla §6.1.2. [CCADB §6.2; Mozilla §6.1.2]

### 4.9 `authorityInformationAccess`

1. The `authorityInformationAccess` extension SHOULD be present. [CABF BR §7.1.2.2.3]
2. If present, the extension MUST NOT be marked critical. [CABF BR §7.1.2.2.3]
3. If present, each `AccessDescription` MUST have an `accessMethod` of `id-ad-ocsp` (1.3.6.1.5.5.7.48.1) with an HTTP `uniformResourceIdentifier` `accessLocation`, or `id-ad-caIssuers` (1.3.6.1.5.5.7.48.2) with an HTTP `uniformResourceIdentifier` `accessLocation`; no other `accessMethod` MUST appear. [CABF BR §7.1.2.10.3]
4. When multiple `AccessDescription`s share an `accessMethod`, each `accessLocation` MUST be unique and they MUST be ordered by priority with the most-preferred first. [CABF BR §7.1.2.10.3]
5. If an OCSP URL appears in AIA, that URL MUST point to an operational OCSP responder. [Mozilla §5.2; Microsoft §3.1.10]
6. The cross-certificate MUST contain at least one of: a `cRLDistributionPoints` extension with a valid CRL URL, or an `authorityInformationAccess` extension with a valid OCSP URL (Microsoft requires at least one of these on all issuing CAs). [Microsoft §3.1.10]

### 4.10 `nameConstraints`

1. If present, the `nameConstraints` extension SHOULD be marked critical (MAY be non-critical for legacy interoperability). [CABF BR §7.1.2.10.8]
2. If present, each `GeneralSubtree` MUST omit `minimum` and MUST omit `maximum`. [CABF BR §7.1.2.10.8]
3. If present, `dNSName`, `iPAddress`, and `directoryName` `GeneralName` types are MAY in `permittedSubtrees`/`excludedSubtrees`; `rfc822Name`, `otherName`, and any other `GeneralName` type are NOT RECOMMENDED. [CABF BR §7.1.2.10.8]
4. If the cross-certificate is being used to make the subordinate hierarchy Technically Constrained for TLS, the `nameConstraints` extension MUST be present, MUST contain `permittedSubtrees` entries for both `dNSName` and `iPAddress` (or explicit zero-length/zero-octet exclusions), MUST contain at least one `directoryName` entry in `permittedSubtrees`, and MUST follow the full §7.1.2.5.2 shape. [CABF BR §7.1.2.5.2]

### 4.11 Signed Certificate Timestamp List

1. If present, the SCT List extension MUST NOT be marked critical. [CABF BR §7.1.2.2.3]
2. If present, the `extnValue` MUST be an `OCTET STRING` containing a `SignedCertificateTimestampList` per RFC 6962 §3.3. [CABF BR §7.1.2.11.3]

### 4.12 Other extensions

1. Any extension not listed above is NOT RECOMMENDED. [CABF BR §7.1.2.2.3]
2. Any extension present MUST be DER-encoded according to the ASN.1 module defining it. [CABF BR §7.1.2.11.5]
3. Any extension present MUST apply in the context of the public Internet (or fall within an OID arc demonstrably owned by the applicant). [CABF BR §7.1.2.11.5]
4. Any extension present MUST NOT include semantics that mislead the relying party. [CABF BR §7.1.2.11.5]

## 5. CRL profile rules pointed-to by `cRLDistributionPoints`

A linter that fetches and inspects the CRL referenced by this certificate MUST check the following CRL-content rules.

1. The CRL MUST be X.509 v2 (`tbsCertList.version` = 1). [CABF BR §7.2.1]
2. The CRL's `issuer` MUST be byte-for-byte identical to the `subject` of the issuing CA of the cross-certificate. [CABF BR §7.2]
3. The CRL MUST be signed using one of the algorithms in CABF BR §7.1.3.2. [CABF BR §7.2]
4. The CRL MUST contain an `authorityKeyIdentifier` extension (non-critical). [CABF BR §7.2.2]
5. The CRL MUST contain a `CRLNumber` extension (non-critical) whose value is an integer in `[0, 2^159)` and strictly increasing across CRL issuances. [CABF BR §7.2.2]
6. If the CRL's scope does not include all unexpired certificates issued by the CA, it MUST contain a critical `IssuingDistributionPoint` extension whose `distributionPoint` is a `fullName` containing only `uniformResourceIdentifier` GeneralNames, at least one of which is byte-for-byte identical to a `uniformResourceIdentifier` in the certificate's `cRLDistributionPoints`. [CABF BR §7.2.2.1; Mozilla §6.1.2]
7. The CRL's `IssuingDistributionPoint` MUST NOT assert `indirectCRL` and MUST NOT assert `onlyContainsAttributeCerts`. [CABF BR §7.2.2.1]
8. The CRL's `IssuingDistributionPoint` MUST NOT assert both `onlyContainsUserCerts` and `onlyContainsCACerts`. [CABF BR §7.2.2.1]
9. The CRL `nextUpdate` for a CRL covering subordinate-CA certs MUST be no more than 12 months after `thisUpdate`. [CABF BR §7.2]
10. Each revocation entry for a revoked subordinate CA certificate MUST include a `reasonCode` extension. [CCADB §3.2]
11. The Apple-mandated CRL shape: when the CCADB record uses a JSON array of partitioned CRLs, each referenced CRL MUST contain a critical `Issuing Distribution Point` extension whose distributionPoint field URL exactly matches a CCADB-disclosed URL. [Apple §2.1.2; CCADB §6.2]
12. When the CCADB record uses a single Full CRL URL, the referenced CRL SHOULD NOT contain an `Issuing Distribution Point` extension. [Apple §2.1.2; CCADB §6.2]

## 6. Audit-scope shape (knowable from EKU bytes)

1. A cross-certificate that omits the EKU extension entirely, or whose EKU includes `id-kp-serverAuth` or `anyExtendedKeyUsage`, is in-scope for full WebTrust/ETSI TLS audit; linters MAY flag this shape to clarify audit scope. [Chrome §1.4 audit table]
2. A cross-certificate whose EKU is present and does NOT include `id-kp-serverAuth` or `anyExtendedKeyUsage` is treated as Technically Constrained Non-TLS for audit purposes. [Chrome §1.4 audit table]

## 7. ASN.1 / DER encoding

1. The certificate MUST be valid ASN.1 DER with no encoding errors. [Mozilla §5.2]
2. Each `Name` MUST contain an `RDNSequence`, and each `RelativeDistinguishedName` MUST contain exactly one `AttributeTypeAndValue` — except that the existing-subject byte-identical exception of §2.6 takes precedence. [CABF BR §7.1.4.1, §7.1.2.2.2]

## 8. Notes and intentional non-requirements

- The cross-certificate's validity period is bounded by both the issuing CA's notAfter and the subordinate hierarchy's continued use; CABF imposes no explicit maximum, but Chrome §1.3.1.3 encourages ≤ 3 years and LE §7.1 caps LE-issued sub-CA validity at 8 years.
- Mozilla §7.5 single-purpose root rules cascade onto cross-certificates issued under post-2025-03-15 Mozilla roots: TLS-purpose cross-certificates under such roots MUST follow the server-auth EKU rules of `intermediates.md`; S/MIME-purpose cross-certificates MUST follow the email-protection rules and MUST NOT carry server-auth EKUs.
- A cross-certificate that becomes Technically Constrained for TLS (carries `nameConstraints` per §4.10.4) inherits the `intermediates.md` Technically-Constrained TLS sub-CA name-constraint rules.
- Cross-certificates are not required to be logged to Certificate Transparency.
