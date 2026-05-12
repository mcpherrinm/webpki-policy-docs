# Root CA Certificate Requirements

This document collects the most restrictive certificate-content requirements that apply to a **publicly-trusted root CA certificate** — i.e., a self-signed CA certificate intended for inclusion in browser/OS trust stores. Each requirement is phrased so a linter author can implement it directly against an encoded X.509 certificate.

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

1. The certificate `version` field MUST be v3 (integer value 2). [CABF BR §7.1.1, §7.1.2.1; Microsoft §3.1.1; LE §7.1.1]

### 1.2 Serial number

1. The certificate `serialNumber` MUST be greater than zero. [CABF BR §7.1.2.1; Mozilla §5.2]
2. The certificate `serialNumber` MUST be less than 2^159. [CABF BR §7.1.2.1]
3. The certificate `serialNumber` MUST contain at least 64 bits of output from a CSPRNG. [CABF BR §7.1.2.1; Mozilla §5.2; LE §7.1 (Root CA profile)]
4. The certificate `serialNumber` MUST be non-sequential. [CABF BR §7.1.2.1]
5. The combination of `issuer` DN and `serialNumber` MUST be unique across all certificates issued by the issuing CA (a CT precertificate sharing the serial of its corresponding final certificate is the only exception, but is not applicable for roots). [Mozilla §5.2]

### 1.3 Signature (inside `tbsCertificate`)

1. The encoded value of the `tbsCertificate.signature` field MUST be byte-for-byte identical to the outer `signatureAlgorithm` field. [CABF BR §7.1.2.1]
2. The signature `AlgorithmIdentifier` MUST be one of the encodings permitted by CABF BR §7.1.3.2. [CABF BR §7.1.3.2; LE §7.1.3.2] — see §3 below.

### 1.4 Issuer

1. The encoded `issuer` field MUST be byte-for-byte identical to the encoded `subject` field of the same certificate (i.e., the root is self-issued). [CABF BR §7.1.2.1; Microsoft §3.1.2; LE §7.1 (Root CA profile)]
2. The certificate's signature MUST verify under the public key in its own `subjectPublicKeyInfo` (i.e., the root is self-signed). [Microsoft §3.1.2]

### 1.5 Validity

1. The `notBefore` value MUST be no earlier than one day prior to the time of signing. [CABF BR §7.1.2.1.1]
2. The `notBefore` value MUST be no later than the time of signing. [CABF BR §7.1.2.1.1]
3. The difference `notAfter − notBefore` MUST be at least 2922 days (approximately 8 years). [CABF BR §7.1.2.1.1; Microsoft §3.1.8]
4. The difference `notAfter − notBefore` MUST be at most 9132 days (approximately 25 years). [CABF BR §7.1.2.1.1; Microsoft §3.1.8; LE §7.1 (Root CA profile)]
5. The validity-period rules in items 1.5.3–1.5.4 apply even when reissuing a root with an existing `subject` and `subjectPublicKeyInfo`. [CABF BR §7.1.2.1.1]

### 1.6 Subject

1. All `subject` attribute encodings MUST conform to CABF BR §7.1.4. [CABF BR §7.1.2.1, §7.1.4]
2. The `subject` MUST contain a `countryName` attribute. [CABF BR §7.1.2.10.2]
3. The `countryName` MUST be a two-letter ISO 3166-1 alpha-2 country code for the country in which the CA's place of business is located; the `XX` user-assigned code exception in §7.1.2.7.3/§7.1.2.7.4 applies only to subscriber profiles and MUST NOT be used in a CA certificate. [CABF BR §7.1.2.10.2]
4. The `countryName` attribute MUST be encoded as `PrintableString` and MUST be at most 2 characters. [CABF BR §7.1.4.2]
5. The `subject` MUST contain an `organizationName` attribute. [CABF BR §7.1.2.10.2]
6. The `organizationName` attribute MUST be encoded as `UTF8String` or `PrintableString` and MUST be at most 64 characters. [CABF BR §7.1.4.2]
7. The `subject` MUST contain a `commonName` attribute that uniquely identifies the certificate within the issuing CA. [CABF BR §7.1.2.10.2; Microsoft §3.1.3]
8. The `commonName` attribute MUST be encoded as `UTF8String` or `PrintableString` and MUST be at most 64 characters. [CABF BR §7.1.4.2]
9. The `subject` MUST NOT contain an `organizationalUnitName` attribute. [CABF BR §7.1.2.10.2]
10. Each `RelativeDistinguishedName` in the `subject` MUST contain exactly one `AttributeTypeAndValue`. [CABF BR §7.1.4.1]
11. The `RDNSequence` MUST order attributes as listed in CABF BR §7.1.4.2 (`countryName`, `stateOrProvinceName`, `localityName`, `postalCode`, `streetAddress`, `organizationName`, `surname`, `givenName`, `organizationalUnitName`, `commonName`, plus EV-specific attributes). [CABF BR §7.1.4.1, §7.1.4.2]
12. The `subject` MUST NOT contain more than one instance of any given `AttributeTypeAndValue` (except where explicitly allowed for `domainComponent` or `streetAddress`). [CABF BR §7.1.4.1]
13. Any optional attribute (`stateOrProvinceName`, `localityName`, `postalCode`, `streetAddress`) included in `subject` MUST be encoded as `UTF8String` or `PrintableString` and MUST respect the per-attribute length cap in CABF BR §7.1.4.2. [CABF BR §7.1.4.2]
14. The `subject` MUST be byte-for-byte identical across all certificates whose subject DN is equal under RFC 5280 §7.1, including expired and revoked certificates. [CABF BR §7.1.4.1]
15. A LE-operated root's `subject` MUST be `C=US, O=Internet Security Research Group` or `O=ISRG`, plus a meaningful `CN`. [LE §7.1 (Root CA profile)] *(LE-issued only)*

### 1.7 `subjectPublicKeyInfo`

1. The SPKI algorithm MUST be RSA (`rsaEncryption`, OID 1.2.840.113549.1.1.1) or ECDSA (`id-ecPublicKey`, OID 1.2.840.10045.2.1). [CABF BR §7.1.3.1, §6.1.5; Mozilla §5.1; Microsoft §3.1.20]
2. EdDSA (Ed25519/Ed448) public keys MUST NOT appear in a root CA certificate trusted for server authentication. [Mozilla §5.1; CABF BR §6.1.5] *(Mozilla §5.1 permits EdDSA only when the cert carries `id-kp-emailProtection`, which a root cannot since roots carry no EKU; CABF §6.1.5 permits only RSA and ECDSA on P-256/P-384/P-521.)*
3. Curve25519 and Curve448 public keys MUST NOT appear in the SPKI. [CABF BR §6.1.5] *(Mozilla §5.1 notes Curve25519/Curve448 are "not prohibited, but are not currently supported"; the strict prohibition derives from CABF §6.1.5 which enumerates only RSA and ECDSA P-256/P-384/P-521.)*
4. If the SPKI is RSA, the encoded modulus MUST be at least 2048 bits. [CABF BR §6.1.5; Mozilla §5.1; Microsoft §3.1.20]
5. If the SPKI is RSA, the modulus size in bits MUST be evenly divisible by 8. [CABF BR §6.1.5; Mozilla §5.1]
6. If the SPKI is RSA, the public exponent MUST be an odd integer ≥ 3. [CABF BR §6.1.6]
7. If the SPKI is RSA, the public exponent SHOULD be in the range `2^16 + 1` to `2^256 − 1`. [CABF BR §6.1.6]
8. If the SPKI is RSA, the public exponent MUST NOT be 1 (i.e., the key MUST be a valid RSA public key). [Mozilla §5.2]
9. If the SPKI is RSA, the encoded `AlgorithmIdentifier` MUST be byte-for-byte identical to the hex bytes `300d06092a864886f70d0101010500` (`rsaEncryption` OID with explicit NULL parameters). [CABF BR §7.1.3.1.1; Mozilla §5.1.1; LE §7.1.3.1]
10. If the SPKI is RSA, the algorithm OID MUST NOT be `id-RSASSA-PSS` (1.2.840.113549.1.1.10). [CABF BR §7.1.3.1.1; Mozilla §5.1.1]
11. If the SPKI is ECDSA, the key MUST lie on one of NIST P-256 (`secp256r1`), P-384 (`secp384r1`), or P-521 (`secp521r1`). [CABF BR §6.1.5, §7.1.3.1.2; Mozilla §5.1; Microsoft §3.1.20]
12. If the SPKI is ECDSA, the `AlgorithmIdentifier` parameters MUST use the `namedCurve` encoding and MUST NOT use `implicitCurve` or `specifiedCurve` forms. [CABF BR §7.1.3.1.2; Mozilla §5.1.2]
13. If the SPKI is ECDSA P-256, the encoded `AlgorithmIdentifier` MUST be byte-for-byte identical to `301306072a8648ce3d020106082a8648ce3d030107`. [CABF BR §7.1.3.1.2; Mozilla §5.1.2; LE §7.1.3.1]
14. If the SPKI is ECDSA P-384, the encoded `AlgorithmIdentifier` MUST be byte-for-byte identical to `301006072a8648ce3d020106052b81040022`. [CABF BR §7.1.3.1.2; Mozilla §5.1.2; LE §7.1.3.1]
15. If the SPKI is ECDSA P-521, the encoded `AlgorithmIdentifier` MUST be byte-for-byte identical to `301006072a8648ce3d020106052b81040023`. [CABF BR §7.1.3.1.2; Mozilla §5.1.2; LE §7.1.3.1]
16. ECDSA keys SHOULD be confirmed valid using ECC Full or Partial Public Key Validation (NIST SP 800-56A). [CABF BR §6.1.6; LE §6.1.6]
17. A LE-operated root has an RSA-4096-bit key (with public exponent 65537) or an ECDSA P-384 key. [LE §6.1.5, §6.1.6] *(LE-issued only; LE CP/CPS §7.1 frames this descriptively rather than as a per-issuance MUST, but it constrains LE-issued root cert content.)*

### 1.8 `issuerUniqueID` / `subjectUniqueID`

1. The `issuerUniqueID` field MUST NOT be present. [CABF BR §7.1.2.1]
2. The `subjectUniqueID` field MUST NOT be present. [CABF BR §7.1.2.1]

## 2. Outer `signatureAlgorithm` field

1. The outer `signatureAlgorithm` field MUST be byte-for-byte identical to the `tbsCertificate.signature` field. [CABF BR §7.1.2.1]

## 3. Signature algorithm (the algorithm used to sign the certificate)

1. The signature algorithm MUST be one of: RSASSA-PKCS1-v1_5 with SHA-256/384/512, RSASSA-PSS with SHA-256/384/512, or ECDSA with SHA-256/384/512. [CABF BR §7.1.3.2; Mozilla §5.1.1, §5.1.2; Microsoft §3.1.20]
2. The signature hash function MUST be in the SHA-2 family (SHA-256, SHA-384, or SHA-512). [Microsoft §3.1.20]
3. The signature algorithm MUST NOT be MD5 or any hash other than those enumerated. [Mozilla §5.1.1, §5.1.2; Microsoft §3.1.20]
4. The signature algorithm MUST NOT be RSASSA-PKCS1-v1_5 with SHA-1, except that until 2026-09-15 CABF BR §7.1.3.2.1 permits a narrow same-key reissuance of a Root CA Certificate (or a Subordinate CA Certificate that is a Cross-Certificate) when an existing certificate from the same issuing CA used SHA-1, the existing serial has ≥64 bits, and the only differences from the existing certificate are a new subjectPublicKey of the same algorithm/size, a new serial of the same encoded length, an `extKeyUsage` whose key purposes exclude `id-kp-serverAuth` and `anyExtendedKeyUsage`, and/or a `pathLenConstraint` of zero. [CABF BR §7.1.3.2.1]
5. Effective 2026-09-15, the narrow SHA-1 reissuance exception in §3 #4 ceases to apply; any new Root CA Certificate signed on or after 2026-09-15 MUST NOT use RSASSA-PKCS1-v1_5 with SHA-1. [CABF BR §7.1.3.2.1 ("Until 2026-09-15…")]
6. If the signature uses an RSASSA-PKCS1-v1_5 `AlgorithmIdentifier`, the parameters field MUST be explicit NULL (not omitted). [CABF BR §7.1.3.2.1; Mozilla §5.1.1]
7. If the signature uses RSASSA-PKCS1-v1_5 with SHA-256, the encoded `AlgorithmIdentifier` MUST be exactly `300d06092a864886f70d01010b0500`. [CABF BR §7.1.3.2.1; Mozilla §5.1.1]
8. If the signature uses RSASSA-PKCS1-v1_5 with SHA-384, the encoded `AlgorithmIdentifier` MUST be exactly `300d06092a864886f70d01010c0500`. [CABF BR §7.1.3.2.1; Mozilla §5.1.1]
9. If the signature uses RSASSA-PKCS1-v1_5 with SHA-512, the encoded `AlgorithmIdentifier` MUST be exactly `300d06092a864886f70d01010d0500`. [CABF BR §7.1.3.2.1; Mozilla §5.1.1]
10. If the signature uses RSASSA-PSS with SHA-256, MGF-1 with SHA-256, and salt length 32, the encoded `AlgorithmIdentifier` MUST be the prescribed PSS-SHA256 DER (CABF BR §7.1.3.2.1: starts `304106092a864886f70d01010a3034…0500a203020120`). [CABF BR §7.1.3.2.1; Mozilla §5.1.1]
11. If the signature uses RSASSA-PSS with SHA-384, MGF-1 with SHA-384, and salt length 48, the encoded `AlgorithmIdentifier` MUST be the prescribed PSS-SHA384 DER. [CABF BR §7.1.3.2.1; Mozilla §5.1.1]
12. If the signature uses RSASSA-PSS with SHA-512, MGF-1 with SHA-512, and salt length 64, the encoded `AlgorithmIdentifier` MUST be the prescribed PSS-SHA512 DER. [CABF BR §7.1.3.2.1; Mozilla §5.1.1]
13. If an RSASSA-PSS `AlgorithmIdentifier` is used, the `trailerField` MUST be omitted (default value). [Mozilla §5.1.1]
14. If an RSASSA-PSS `AlgorithmIdentifier` is used, the inner `hashAlgorithm` and `maskGenAlgorithm`-inner `AlgorithmIdentifier`s MUST each include an explicit NULL parameter. [Mozilla §5.1.1]
15. If the signing key is ECDSA P-256, the signature algorithm MUST be ECDSA with SHA-256 and the encoded `AlgorithmIdentifier` MUST be exactly `300a06082a8648ce3d040302`. [CABF BR §7.1.3.2.2; Mozilla §5.1.2]
16. If the signing key is ECDSA P-384, the signature algorithm MUST be ECDSA with SHA-384 and the encoded `AlgorithmIdentifier` MUST be exactly `300a06082a8648ce3d040303`. [CABF BR §7.1.3.2.2; Mozilla §5.1.2]
17. If the signing key is ECDSA P-521, the signature algorithm MUST be ECDSA with SHA-512 and the encoded `AlgorithmIdentifier` MUST be exactly `300a06082a8648ce3d040304`. [CABF BR §7.1.3.2.2; Mozilla §5.1.2]
18. An ECDSA signature `AlgorithmIdentifier` MUST omit the parameters field (it MUST NOT include an explicit NULL parameter). [Mozilla §5.1.2]

## 4. Extensions

### 4.1 Extensions table — presence and criticality

The following extension presence/criticality matrix applies to root CA certificates. A linter MUST verify each entry.

| Extension | Presence | Critical | Notes / source |
|---|---|---|---|
| `basicConstraints` (2.5.29.19) | MUST | Y | [CABF BR §7.1.2.1.2, §7.1.2.1.4; Microsoft §3.1.5] |
| `keyUsage` (2.5.29.15) | MUST | Y | [CABF BR §7.1.2.1.2, §7.1.2.10.7; Microsoft §3.1.6] |
| `subjectKeyIdentifier` (2.5.29.14) | MUST | N | [CABF BR §7.1.2.1.2, §7.1.2.11.4] |
| `authorityKeyIdentifier` (2.5.29.35) | RECOMMENDED | N | [CABF BR §7.1.2.1.2, §7.1.2.1.3] |
| `extKeyUsage` (2.5.29.37) | MUST NOT | – | [CABF BR §7.1.2.1.2] |
| `certificatePolicies` (2.5.29.32) | NOT RECOMMENDED | N | [CABF BR §7.1.2.1.2] |
| `cRLDistributionPoints` (2.5.29.31) | SHOULD NOT | N | [CABF BR §7.1.2.11.2] |
| `subjectAltName` (2.5.29.17) | OPTIONAL (NOT RECOMMENDED) | – | [CABF BR §7.1.2.11.5] |
| `nameConstraints` (2.5.29.30) | OPTIONAL (NOT RECOMMENDED for roots) | SHOULD be Y if present | [CABF BR §7.1.2.11.5, §7.1.2.10.8] |
| SCT List (1.3.6.1.4.1.11129.2.4.2) | MAY | N | [CABF BR §7.1.2.1.2, §7.1.2.11.3] |
| Any other extension | NOT RECOMMENDED | – | [CABF BR §7.1.2.1.2, §7.1.2.11.5] |

### 4.2 `basicConstraints`

1. The `basicConstraints` extension MUST be present. [CABF BR §7.1.2.1.2; Microsoft §3.1.5]
2. The `basicConstraints` extension MUST be marked critical. [CABF BR §7.1.2.1.2]
3. The `cA` boolean MUST be set to TRUE. [CABF BR §7.1.2.1.4; Microsoft §3.1.5]
4. The `pathLenConstraint` field is NOT RECOMMENDED. [CABF BR §7.1.2.1.4]

### 4.3 `keyUsage`

1. The `keyUsage` extension MUST be present. [CABF BR §7.1.2.1.2; Microsoft §3.1.6]
2. The `keyUsage` extension MUST be marked critical. [CABF BR §7.1.2.1.2; Microsoft §3.1.6]
3. The `keyCertSign` bit MUST be asserted. [CABF BR §7.1.2.10.7; Microsoft §3.1.6]
4. The `cRLSign` bit MUST be asserted. [CABF BR §7.1.2.10.7; Microsoft §3.1.6]
5. If the root's private key is ever used to sign OCSP responses, the `digitalSignature` bit MUST be asserted; otherwise the `digitalSignature` bit MAY be omitted. [CABF BR §7.1.2.10.7; Microsoft §3.1.6]
6. The `nonRepudiation`, `keyEncipherment`, `dataEncipherment`, `keyAgreement`, `encipherOnly`, and `decipherOnly` bits MUST NOT be asserted. [CABF BR §7.1.2.10.7]

### 4.4 `subjectKeyIdentifier`

1. The `subjectKeyIdentifier` extension MUST be present. [CABF BR §7.1.2.1.2]
2. The `subjectKeyIdentifier` extension MUST NOT be marked critical. [CABF BR §7.1.2.1.2]
3. The `subjectKeyIdentifier` value MUST be set as defined in RFC 5280 §4.2.1.2 and MUST be unique across all certificates the CA has issued for any given public key. [CABF BR §7.1.2.11.4]

### 4.5 `authorityKeyIdentifier`

1. If present, the `authorityKeyIdentifier` extension MUST NOT be marked critical. [CABF BR §7.1.2.1.2]
2. If present, the `keyIdentifier` field MUST be present and MUST equal the certificate's `subjectKeyIdentifier`. [CABF BR §7.1.2.1.3]
3. If present, the `authorityCertIssuer` field MUST NOT be present. [CABF BR §7.1.2.1.3]
4. If present, the `authorityCertSerialNumber` field MUST NOT be present. [CABF BR §7.1.2.1.3]

### 4.6 `extKeyUsage`

1. The `extKeyUsage` extension MUST NOT be present. [CABF BR §7.1.2.1.2]

### 4.7 `certificatePolicies`

1. The `certificatePolicies` extension is NOT RECOMMENDED in a root CA certificate. [CABF BR §7.1.2.1.2]
2. If present, the `certificatePolicies` extension MUST contain at most 2 distinct `policyIdentifier` values. [Microsoft §3.1.16]
3. If present, the `certificatePolicies` extension MUST NOT be marked critical. [CABF BR §7.1.2.1.2]
4. If present, each `PolicyInformation` MUST conform to CABF BR §7.1.2.10.5 (`anyPolicy` only if asserting no restriction; otherwise exactly one CABF Reserved Certificate Policy Identifier plus optional CA-defined OIDs). [CABF BR §7.1.2.10.5]
5. If `policyQualifiers` are present within any `PolicyInformation`, they MUST contain only the `id-qt-cps` qualifier (OID 1.3.6.1.5.5.7.2.1) with an HTTP or HTTPS URL pointing to the issuing CA's policy materials. [CABF BR §7.1.2.10.5]
6. If `policyQualifiers` are present, they MUST NOT include any qualifier other than `id-qt-cps`. [CABF BR §7.1.2.10.5]
7. The presence of `policyQualifiers` is NOT RECOMMENDED. [CABF BR §7.1.2.10.5]

### 4.8 `cRLDistributionPoints`

1. The `cRLDistributionPoints` extension SHOULD NOT be present in a root CA certificate. [CABF BR §7.1.2.11.2]

### 4.9 `subjectAltName`

1. The `subjectAltName` extension is NOT RECOMMENDED. [CABF BR §7.1.2.11.5]

### 4.10 `nameConstraints`

1. The `nameConstraints` extension is NOT RECOMMENDED on a root. [CABF BR §7.1.2.11.5]
2. If present, the `nameConstraints` extension SHOULD be marked critical (MAY be non-critical for legacy interoperability). [CABF BR §7.1.2.10.8]
3. If present, every `GeneralSubtree` MUST omit `minimum` and MUST omit `maximum`. [CABF BR §7.1.2.10.8]
4. If present, only `dNSName`, `iPAddress`, and `directoryName` `GeneralName` types are MAY in `permittedSubtrees`/`excludedSubtrees`; `rfc822Name`, `otherName`, and any other `GeneralName` type are NOT RECOMMENDED. [CABF BR §7.1.2.10.8]

### 4.11 Signed Certificate Timestamp List

1. If present, the SCT List extension MUST NOT be marked critical. [CABF BR §7.1.2.1.2]
2. If present, the SCT List `extnValue` MUST be an `OCTET STRING` containing a `SignedCertificateTimestampList` per RFC 6962 §3.3. [CABF BR §7.1.2.11.3]

### 4.12 `authorityInformationAccess` (if present)

The `authorityInformationAccess` extension is NOT RECOMMENDED in a root CA certificate (it falls under "Any other extension" in §7.1.2.1.2's table), but if present it MUST conform to the common CA AIA profile:

1. If the `authorityInformationAccess` extension is present, it MUST NOT be marked critical. [CABF BR §7.1.2.10.3]
2. If present, each `AccessDescription` MUST have an `accessMethod` of `id-ad-ocsp` (1.3.6.1.5.5.7.48.1) with an HTTP `uniformResourceIdentifier` `accessLocation`, or `id-ad-caIssuers` (1.3.6.1.5.5.7.48.2) with an HTTP `uniformResourceIdentifier` `accessLocation`. [CABF BR §7.1.2.10.3]
3. No `accessMethod` other than `id-ad-ocsp` or `id-ad-caIssuers` MUST appear. [CABF BR §7.1.2.10.3]

### 4.13 Other extensions

1. Any extension not listed above is NOT RECOMMENDED. [CABF BR §7.1.2.1.2, §7.1.2.11.5]
2. Any extension present MUST be DER-encoded according to the ASN.1 module defining that extension. [CABF BR §7.1.2.11.5]
3. Any extension present MUST apply in the context of the public Internet (or fall within an OID arc demonstrably owned by the applicant). [CABF BR §7.1.2.11.5]

## 5. Root-program lifecycle constraints (knowable from cert + issuance context)

1. The CA key material associated with the root MUST NOT be older than 15 years as measured from the earliest of the Qualified Auditor key-generation report or the `notBefore` of the earliest certificate carrying the same public key; once exceeded, Chrome will distrust the root. [Chrome §1.3.1.2]
2. A root whose key was generated between 2006-01-01 and 2007-12-31 will be removed from the Chrome Root Store on or before 2026-04-15. [Chrome §1.3.1.2]
3. A root whose key was generated between 2008-01-01 and 2009-12-31 will be removed from the Chrome Root Store on or before 2027-04-15. [Chrome §1.3.1.2]
4. A root whose key was generated between 2010-01-01 and 2011-12-31 will be removed from the Chrome Root Store on or before 2028-04-15. [Chrome §1.3.1.2]
5. A root whose key was generated between 2012-01-01 and 2014-04-14 will be removed from the Chrome Root Store on or before 2029-04-15. [Chrome §1.3.1.2]
6. An applicant root submitted for inclusion to the Chrome Root Store MUST have key material generated within 5 years of the CCADB Root Inclusion Request. [Chrome §2.2]
7. Mozilla will remove the Websites trust bit from a root once its key material is more than 15 years from the CA key-material generation date. [Mozilla §7.4]
8. Mozilla will set the "Distrust for S/MIME After Date" of a root to 18 years from the CA key-material generation date. [Mozilla §7.4]
9. A root added to Mozilla's Root Store after 2025-03-15 MUST be configured for a single purpose (server authentication OR S/MIME email protection), not both. [Mozilla §7.5]
10. A root added to a Chrome PKI hierarchy after 2022-09-01 MUST be dedicated to TLS server authentication. [Chrome §1.4 footnote **]
11. A root used as a Microsoft Trusted Root MUST be a freshly generated key pair and Subject DN distinct from any prior root of the same CA when it is added. [Microsoft §3.1.11]
12. A root certificate MUST NOT directly issue end-entity (subscriber) certificates; an intermediate must intervene. [Mozilla §5.2; Microsoft §3.2.4]
13. If the root is a newly-minted Microsoft Code-Signing or Time-Stamping root, the SPKI MUST be RSA (ECC/ECDSA not supported), and the RSA modulus MUST be exactly 4096 bits (no smaller, no larger). [Microsoft §3.1.20] *(Applies to "new roots only" per the Microsoft §3.1.20 table; legacy code-signing/timestamping roots are not retroactively required. Out-of-scope for TLS-only roots.)*

## 6. ASN.1 / DER encoding

1. The certificate MUST be valid ASN.1 DER with no encoding errors. [Mozilla §5.2]
2. Each `Name` MUST contain an `RDNSequence`. [CABF BR §7.1.4.1]
3. Each `RelativeDistinguishedName` MUST contain exactly one `AttributeTypeAndValue`. [CABF BR §7.1.4.1]

## 7. Notes and intentional non-requirements

- Root certificates carry no `extKeyUsage`; per-EKU-driven program scoping (Mozilla §7.5, Apple §2.1.3 dedicated-root rules, Chrome §1.3.2) applies to issued subordinate certificates rather than the root itself.
- Roots are not required to be logged to Certificate Transparency.
- Apple §2.1.3 establishes "single-purpose Root CAs" with EKU-driven scoping applied to subordinate CAs beneath the root. See `intermediates.md` for those requirements.
- CCADB §6.3 cross-cert dedicated-EKU rules apply to cross certificates, not to the root itself. See `cross-certs.md`.
- LE-specific items in §1.6 and §1.7 (marked *LE-issued only*) bind ISRG-operated roots; they tighten but do not loosen any universal CABF/program rule.
