# TLS Subscriber (Leaf) Certificate Requirements

This document collects the most restrictive certificate-content requirements that apply to a **TLS server subscriber certificate** — a leaf certificate issued under a publicly-trusted CA hierarchy carrying `id-kp-serverAuth` and identifying server endpoints by `dNSName` or `iPAddress`. CABF BR §7.1.2.7 (Subscriber Server) is the foundational profile, with §7.1.2.9 (Precertificate) layered for CT precertificates.

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

1. The certificate `version` field MUST be v3 (integer value 2). [CABF BR §7.1.1, §7.1.2.7; LE §7.1.1]

### 1.2 Serial number

1. The certificate `serialNumber` MUST be greater than zero. [CABF BR §7.1.2.7; Mozilla §5.2; LE §7.1]
2. The certificate `serialNumber` MUST be less than 2^159. [CABF BR §7.1.2.7]
3. The certificate `serialNumber` MUST contain at least 64 bits of output from a CSPRNG. [CABF BR §7.1.2.7; Mozilla §5.2; LE §7.1]
4. The certificate `serialNumber` MUST be non-sequential. [CABF BR §7.1.2.7]
5. The combination of `issuer` DN and `serialNumber` MUST be unique within the issuing CA, with one exception: a CT precertificate (§4.12) MAY share the same `serialNumber` as its corresponding final certificate, but no other duplication is allowed. [Mozilla §5.2; CABF BR §7.1.2.9]
6. A precertificate's `serialNumber` MUST be byte-for-byte identical to the corresponding final certificate's `serialNumber`. [CABF BR §7.1.2.9]

### 1.3 Signature (inside `tbsCertificate`)

1. The encoded `tbsCertificate.signature` MUST be byte-for-byte identical to the outer `signatureAlgorithm`. [CABF BR §7.1.2.7]
2. The signature `AlgorithmIdentifier` MUST be one of the encodings permitted by CABF BR §7.1.3.2 (see §3 below). [CABF BR §7.1.3.2; LE §7.1.3.2]

### 1.4 Issuer

1. The encoded `issuer` field MUST be byte-for-byte identical to the encoded `subject` field of the issuing CA. [CABF BR §7.1.2.7, §7.1.4.1]
2. The certificate's signature MUST verify under the issuing CA's public key.
3. The certificate MUST NOT be issued directly by a root CA included in any major trust store; an intermediate must intervene. [Mozilla §5.2; Microsoft §3.2.4]

### 1.5 Validity

1. The `notBefore` value MUST be within 48 hours of the certificate signing operation. [CABF BR §7.1.2.7]
2. The certificate's validity period (`notAfter − notBefore`) MUST NOT exceed 398 days if the certificate is issued before 2026-03-15. [CABF BR §6.3.2]
3. The certificate's validity period MUST NOT exceed 200 days if the certificate is issued on or after 2026-03-15 and before 2027-03-15. [CABF BR §6.3.2]
4. The certificate's validity period MUST NOT exceed 100 days if the certificate is issued on or after 2027-03-15 and before 2029-03-15. [CABF BR §6.3.2]
5. The certificate's validity period MUST NOT exceed 47 days if the certificate is issued on or after 2029-03-15. [CABF BR §6.3.2]
6. In addition to the MUST NOT thresholds in §1.5 #2–#5, CABF BR §6.3.2 sets SHOULD NOT thresholds of 397/199/99/46 days for the same respective issuance windows; certificates SHOULD NOT be issued at the maximum permissible time. [CABF BR §6.3.2]
7. For the purpose of validity-period calculation, a day MUST be treated as exactly 86,400 seconds; any fractional or leap-second overflow counts as an additional day. [CABF BR §6.3.2]
8. A LE-issued subscriber certificate's validity period is at most 100 days. [LE §7.1 (DV-SSL Subscriber profile)] *(LE-issued only; LE §7.1 frames this as descriptive practice.)*
9. A short-lived subscriber certificate (one for which `cRLDistributionPoints` may be omitted per §4.10) is defined as having a validity period of at most 10 days (864,000 s) for certificates issued on or after 2024-03-15 and prior to 2026-03-15, and at most 7 days (604,800 s) for certificates issued on or after 2026-03-15. [CABF BR §1.6.1]

### 1.6 Subject

The `subject` content depends on the validation type (DV/IV/OV/EV). All four types share the §1.6 encoding rules below; type-specific rules follow in §1.6.4 onward.

#### 1.6.1 Common subject rules

1. All `subject` attribute encodings MUST conform to CABF BR §7.1.4. [CABF BR §7.1.4]
2. Each `RelativeDistinguishedName` in the `subject` MUST contain exactly one `AttributeTypeAndValue`. [CABF BR §7.1.4.1]
3. The `RDNSequence` MUST order attributes as listed in CABF BR §7.1.4.2. [CABF BR §7.1.4.1]
4. The `subject` MUST NOT contain more than one instance of any given `AttributeTypeAndValue` (except `domainComponent` and `streetAddress`, which MAY have multiple instances). [CABF BR §7.1.4.1, §7.1.2.7.4]
5. For IV, OV, and EV subscriber certificates, `subject` attributes MUST NOT contain only metadata such as `.`, `-`, or whitespace, nor any value indicating absent, incomplete, or not-applicable data. [CABF BR §7.1.2.7.3, §7.1.2.7.4, §7.1.2.7.5] *(DV certificates' subject is restricted to `countryName` and `commonName` and is not subject to this metadata-only rule.)*
6. If a `commonName` attribute is present, its value MUST exactly correspond to one entry in the `subjectAltName` extension and MUST be encoded per CABF BR §7.1.4.3 (IPv4 in dotted-decimal, IPv6 in RFC 5952 §4 form, FQDNs in LDH-label form character-identical to the SAN entry). [CABF BR §7.1.4.3; LE §7.1 (DV-SSL Subscriber profile)]
7. The `commonName` attribute MUST be encoded as `UTF8String` or `PrintableString`, with length at most 64 characters. [CABF BR §7.1.4.2]
8. The `countryName` attribute, if present, MUST be encoded as `PrintableString` with length 2, containing either an official ISO 3166-1 alpha-2 country code or `XX`. [CABF BR §7.1.4.2, §7.1.2.7.3, §7.1.2.7.4]
9. The `organizationName` attribute, if present, MUST be encoded as `UTF8String` or `PrintableString` with length at most 64. [CABF BR §7.1.4.2]
10. The `stateOrProvinceName`, `localityName`, `postalCode`, `streetAddress`, `businessCategory`, `jurisdictionStateOrProvince`, `jurisdictionLocality`, `organizationalUnitName` (where permitted), `surname`, and `givenName` attributes, if present, MUST follow the per-attribute encoding/length rules in CABF BR §7.1.4.2. [CABF BR §7.1.4.2]
11. The `jurisdictionCountry` attribute, if present, MUST be encoded as `PrintableString` and at most 2 characters. [CABF BR §7.1.4.2]
12. The `serialNumber` (OID 2.5.4.5) attribute, if present, MUST be encoded as `PrintableString` with length at most 64. [CABF BR §7.1.4.2]
13. The `organizationIdentifier` (OID 2.5.4.97) attribute, if present, MUST be encoded as `UTF8String` or `PrintableString` (no length limit). [CABF BR §7.1.4.2]
14. Any attribute present in `subject` MUST have its content verified per CABF BR §7.1.2.7.x for the certificate type (DV/IV/OV/EV). [CABF BR §7.1.4.4]

#### 1.6.2 Domain Validated (DV)

15. For a DV certificate (`certificatePolicies` asserting `2.23.140.1.2.1`), the only `subject` attributes permitted are `countryName` (MAY) and `commonName` (NOT RECOMMENDED). [CABF BR §7.1.2.7.2]
16. No other `subject` attribute MUST appear in a DV certificate. [CABF BR §7.1.2.7.2]

#### 1.6.3 Individual Validated (IV)

17. For an IV certificate (`certificatePolicies` asserting `2.23.140.1.2.3`), the `subject` MUST contain `countryName`, `surname`, and `givenName`. [CABF BR §7.1.2.7.3]
18. For an IV certificate, the `subject` MUST contain at least one of `stateOrProvinceName` or `localityName`. [CABF BR §7.1.2.7.3]
19. For an IV certificate, the `subject` MUST NOT contain `organizationalUnitName`. [CABF BR §7.1.2.7.3]
20. For an IV certificate, `postalCode`, `streetAddress`, `organizationName`, and `commonName` are NOT RECOMMENDED. [CABF BR §7.1.2.7.3]

#### 1.6.4 Organization Validated (OV)

21. For an OV certificate (`certificatePolicies` asserting `2.23.140.1.2.2`), the `subject` MUST contain `countryName` and `organizationName`. [CABF BR §7.1.2.7.4]
22. For an OV certificate, the `subject` MUST contain at least one of `stateOrProvinceName` or `localityName`. [CABF BR §7.1.2.7.4]
23. For an OV certificate, the `subject` MUST NOT contain `surname`, `givenName`, or `organizationalUnitName`. [CABF BR §7.1.2.7.4]
24. For an OV certificate, `postalCode`, `streetAddress`, and `commonName` are NOT RECOMMENDED. [CABF BR §7.1.2.7.4]
25. For an OV certificate, `domainComponent` MAY be present and, if so, MUST appear as a contiguous sequence of all domain labels, in the reverse order from the on-wire DNS encoding. [CABF BR §7.1.2.7.4]

#### 1.6.5 Extended Validation (EV)

26. For an EV certificate (`certificatePolicies` asserting `2.23.140.1.1`), the `subject` MUST also conform to §7.1.4.2 of the CABF EV Guidelines (out of scope of this document). [CABF BR §7.1.2.7.5]

#### 1.6.6 LE-issued subscriber certificates

27. A LE-issued subscriber certificate's `subject` MUST NOT contain `organizationName`, `givenName`, `surname`, `streetAddress`, `localityName`, `stateOrProvinceName`, `postalCode`, `countryName`, or `organizationalUnitName`. [LE §7.1.4] *(LE-issued only)*
28. A LE-issued subscriber certificate's `subject` MUST either omit `commonName` or set `commonName` to one of the values present in the `subjectAltName` extension. [LE §7.1 (DV-SSL Subscriber profile)] *(LE-issued only)*

### 1.7 `subjectPublicKeyInfo`

1. The SPKI algorithm MUST be RSA (`rsaEncryption`, OID 1.2.840.113549.1.1.1) or ECDSA (`id-ecPublicKey`, OID 1.2.840.10045.2.1). [CABF BR §7.1.3.1, §6.1.5; Mozilla §5.1]
2. EdDSA (Ed25519/Ed448) public keys MUST NOT appear in the SPKI of a TLS server subscriber certificate. [Mozilla §5.1; CABF BR §6.1.5] *(Mozilla §5.1 permits EdDSA only when the certificate carries `id-kp-emailProtection`, which a TLS server subscriber certificate cannot.)*
3. Curve25519 and Curve448 public keys MUST NOT appear in the SPKI. [CABF BR §6.1.5] *(Mozilla §5.1 says these curves are "not prohibited, but not currently supported"; the strict prohibition comes from CABF §6.1.5 enumerating only RSA and ECDSA P-256/P-384/P-521.)*
4. If the SPKI is RSA, the encoded modulus MUST be at least 2048 bits. [CABF BR §6.1.5; Mozilla §5.1]
5. If the SPKI is RSA, the modulus size in bits MUST be evenly divisible by 8. [CABF BR §6.1.5; Mozilla §5.1]
6. If the SPKI is RSA, the modulus MUST NOT be 1024 bits. [Microsoft §3.1.9] *(Redundant with CABF §6.1.5's ≥2048-bit floor.)*
7. If the SPKI is RSA, the public exponent MUST be an odd integer ≥ 3. [CABF BR §6.1.6]
8. If the SPKI is RSA, the public exponent SHOULD be in the range `2^16 + 1` to `2^256 − 1`. [CABF BR §6.1.6]
9. If the SPKI is RSA, the modulus MUST NOT correspond to a known weak key (Debian-weak-keys, ROCA, Close-Primes/Fermat-factorable within 100 rounds). [CABF BR §6.1.1.3]
10. If the SPKI is RSA, the public exponent MUST NOT be 1 (i.e., the key MUST be a valid RSA public key). [Mozilla §5.2]
11. If the SPKI is RSA, the encoded `AlgorithmIdentifier` MUST be byte-for-byte identical to `300d06092a864886f70d0101010500`. [CABF BR §7.1.3.1.1; Mozilla §5.1.1; LE §7.1.3.1]
12. If the SPKI is RSA, the algorithm OID MUST NOT be `id-RSASSA-PSS` (1.2.840.113549.1.1.10). [CABF BR §7.1.3.1.1; Mozilla §5.1.1]
13. If the SPKI is ECDSA, the key MUST lie on NIST P-256, P-384, or P-521 in `namedCurve` form. [CABF BR §6.1.5, §7.1.3.1.2; Mozilla §5.1]
14. The ECDSA SPKI `AlgorithmIdentifier` MUST match the prescribed hex encoding for the curve (P-256: `301306072a8648ce3d020106082a8648ce3d030107`; P-384: `301006072a8648ce3d020106052b81040022`; P-521: `301006072a8648ce3d020106052b81040023`). [CABF BR §7.1.3.1.2; Mozilla §5.1.2]
15. ECDSA SPKI MUST use `namedCurve` form and MUST NOT use `implicitCurve` or `specifiedCurve` forms. [Mozilla §5.1.2]
16. ECDSA keys SHOULD be validated using ECC Full or Partial Public Key Validation (NIST SP 800-56A). [CABF BR §6.1.6; LE §6.1.6]
17. A LE-issued subscriber certificate's SPKI is RSA with a 2048-, 3072-, or 4096-bit encoded modulus, or ECDSA on NIST P-256, P-384, or P-521. [LE §6.1.5] *(LE-issued only; LE §7.1 frames this as descriptive practice.)*
18. LE-issued certificates with RSA keys have public exponent 65537 and an odd modulus with no factors smaller than 752. [LE §6.1.6] *(LE-issued only.)*
19. The CA MUST NOT generate the subscriber key pair for a certificate carrying `id-kp-serverAuth` or `anyExtendedKeyUsage` (the subscriber must supply the key pair). [CABF BR §6.1.1.3; Mozilla §5.2]

### 1.8 `issuerUniqueID` / `subjectUniqueID`

1. The `issuerUniqueID` field MUST NOT be present. [CABF BR §7.1.2.7]
2. The `subjectUniqueID` field MUST NOT be present. [CABF BR §7.1.2.7]

## 2. Outer `signatureAlgorithm` field

1. The outer `signatureAlgorithm` field MUST be byte-for-byte identical to `tbsCertificate.signature`. [CABF BR §7.1.2.7]

## 3. Signature algorithm

1. The signature algorithm MUST be one of: RSASSA-PKCS1-v1_5 with SHA-256/384/512, RSASSA-PSS with SHA-256/384/512, or ECDSA with SHA-256/384/512, with prescribed byte-for-byte `AlgorithmIdentifier` encodings. [CABF BR §7.1.3.2; Mozilla §5.1.1, §5.1.2]
2. The signature algorithm MUST NOT use SHA-1. [Mozilla §5.1.3]
3. The signature algorithm MUST NOT be MD5 or any hash other than the SHA-2 family. [Mozilla §5.1.1, §5.1.2]
4. If the signature uses an RSASSA-PKCS1-v1_5 `AlgorithmIdentifier`, the parameters field MUST be explicit NULL. [Mozilla §5.1.1]
5. RSASSA-PSS signature `AlgorithmIdentifier`s MUST omit the `trailerField` and MUST include explicit NULL parameters in inner hash AlgorithmIdentifiers. [Mozilla §5.1.1]
6. ECDSA signature `AlgorithmIdentifier`s MUST omit the parameters field. [Mozilla §5.1.2]
7. The exact `AlgorithmIdentifier` byte encodings for each algorithm/hash combination MUST match CABF BR §7.1.3.2 (see `roots.md` §3 for the enumeration of hex values). [CABF BR §7.1.3.2]
8. A CT precertificate MUST NOT be signed using SHA-1. [Mozilla §5.1.3]

## 4. Extensions

### 4.1 Extensions table — presence and criticality

| Extension | Presence | Critical | Notes / source |
|---|---|---|---|
| `subjectAltName` (2.5.29.17) | MUST | conditional* | [CABF BR §7.1.2.7.6, §7.1.2.7.12] |
| `authorityInformationAccess` (1.3.6.1.5.5.7.1.1) | MUST | N | [CABF BR §7.1.2.7.6, §7.1.2.7.7] |
| `authorityKeyIdentifier` (2.5.29.35) | MUST | N | [CABF BR §7.1.2.7.6, §7.1.2.11.1] |
| `certificatePolicies` (2.5.29.32) | MUST | N | [CABF BR §7.1.2.7.6, §7.1.2.7.9] |
| `extKeyUsage` (2.5.29.37) | MUST | N | [CABF BR §7.1.2.7.6, §7.1.2.7.10] |
| `keyUsage` (2.5.29.15) | SHOULD | Y | [CABF BR §7.1.2.7.6, §7.1.2.7.11] |
| `basicConstraints` (2.5.29.19) | MAY | Y | [CABF BR §7.1.2.7.6, §7.1.2.7.8] |
| `cRLDistributionPoints` (2.5.29.31) | conditional** | N | [CABF BR §7.1.2.7.6, §7.1.2.11.2] |
| SCT List (1.3.6.1.4.1.11129.2.4.2) | MAY (final), **MUST NOT** (precert) | N | [CABF BR §7.1.2.7.6, §7.1.2.11.3, §7.1.2.9.1] |
| Precertificate Poison (1.3.6.1.4.1.11129.2.4.3) | MUST NOT (final), **MUST** (precert) | Y (precert) | [CABF BR §7.1.2.9.1, §7.1.2.9.3] |
| `subjectKeyIdentifier` (2.5.29.14) | NOT RECOMMENDED | N | [CABF BR §7.1.2.7.6, §7.1.2.11.4] |
| `nameConstraints` (2.5.29.30) | **MUST NOT** | – | [CABF BR §7.1.2.7.6] |
| Any other extension | NOT RECOMMENDED | – | [CABF BR §7.1.2.11.5] |

\* `subjectAltName` MUST be marked critical if the `subject` field is an empty SEQUENCE; otherwise it MUST NOT be marked critical.
\*\* `cRLDistributionPoints` is required unless the certificate is a "Short-lived Subscriber Certificate" (per §1.5 above) and does not include an AIA OCSP URL — see §4.10.

### 4.2 `subjectAltName`

1. The `subjectAltName` extension MUST be present. [CABF BR §7.1.2.7.6, §7.1.2.7.12; Mozilla §5.2]
2. The `subjectAltName` extension MUST contain at least one `dNSName` or `iPAddress` `GeneralName`. [CABF BR §7.1.2.7.12]
3. The `subjectAltName` extension MUST be marked critical if the `subject` field is an empty SEQUENCE. [CABF BR §7.1.2.7.12]
4. The `subjectAltName` extension MUST NOT be marked critical if the `subject` field is not empty. [CABF BR §7.1.2.7.12]
5. The `subjectAltName` MUST NOT contain `otherName`, `rfc822Name`, `x400Address`, `directoryName`, `ediPartyName`, `uniformResourceIdentifier`, or `registeredID` GeneralName types. [CABF BR §7.1.2.7.12]
6. Each `dNSName` value MUST be a Fully-Qualified Domain Name or Wildcard Domain Name, MUST NOT be an Internal Name, and MUST be composed entirely of P-Labels or Non-Reserved LDH Labels joined by `U+002E FULL STOP`. [CABF BR §7.1.2.7.12]
7. Each `dNSName` value MUST NOT be encoded with a trailing zero-length root label (e.g., `example.com`, not `example.com.`). [CABF BR §7.1.2.7.12]
8. Effective 2026-03-15, each `dNSName` value MUST NOT end in an IP Address Reverse Zone Suffix (`.in-addr.arpa` or `.ip6.arpa`). [CABF BR §7.1.2.7.12]
9. A `Wildcard Domain Name` (starting with `*.` followed by an FQDN) MUST have been validated per CABF BR §3.2.2.6 wildcard rules. [CABF BR §7.1.2.7.12]
10. Each `iPAddress` value MUST be an IPv4 or IPv6 address that the CA has confirmed the applicant controls. [CABF BR §7.1.2.7.12]
11. Each `iPAddress` value MUST NOT be a Reserved IP Address (those in the IANA IPv4/IPv6 special-purpose registries). [CABF BR §7.1.2.7.12]
12. A LE-issued subscriber certificate's `subjectAltName` MUST contain at least 1 and at most 100 GeneralName entries, each being a `dNSName` or `iPAddress`. [LE §7.1 (DV-SSL Subscriber profile)] *(LE-issued only)*
13. A LE-issued subscriber certificate's `subjectAltName` extension MUST be marked critical when the `subject` does not contain a `commonName`. [LE §7.1 (DV-SSL Subscriber profile)] *(LE-issued only)*

### 4.3 `authorityInformationAccess`

1. The `authorityInformationAccess` extension MUST be present. [CABF BR §7.1.2.7.6, §7.1.2.7.7]
2. The `authorityInformationAccess` extension MUST NOT be marked critical. [CABF BR §7.1.2.7.6]
3. The extension MUST contain at least one `AccessDescription`. [CABF BR §7.1.2.7.7]
4. Each `AccessDescription` MUST have `accessMethod` equal to `id-ad-ocsp` (1.3.6.1.5.5.7.48.1) with an HTTP `uniformResourceIdentifier` `accessLocation`, or `id-ad-caIssuers` (1.3.6.1.5.5.7.48.2) with an HTTP `uniformResourceIdentifier` `accessLocation`. [CABF BR §7.1.2.7.7]
5. No `accessMethod` other than `id-ad-ocsp` or `id-ad-caIssuers` MUST appear. [CABF BR §7.1.2.7.7]
6. An `id-ad-caIssuers` `AccessDescription` SHOULD be present. [CABF BR §7.1.2.7.7]
7. When multiple `AccessDescription`s share an `accessMethod`, each `accessLocation` MUST be unique and the `AccessDescription`s MUST be ordered by priority with the most-preferred first. [CABF BR §7.1.2.7.7]
8. If an OCSP URL appears in AIA, it MUST point to an operational OCSP responder. [Mozilla §5.2]
9. A LE-issued subscriber certificate's AIA MUST contain a `caIssuers` URL and MAY contain an OCSP URL. [LE §7.1 (DV-SSL Subscriber profile)] *(LE-issued only)*
10. The certificate MUST contain at least one of: a valid `cRLDistributionPoints` extension, or an AIA `id-ad-ocsp` URL — unless the certificate is a Short-lived Subscriber Certificate (per §1.5 #9), in which case both MAY be omitted. [CABF BR §7.1.2.11.2; CABF BR §7.1.2.7.6] *(Microsoft §3.1.10 separately observes that end-entity certificates "may contain" one or the other, but the operational MUST derives from CABF.)*

### 4.4 `authorityKeyIdentifier`

1. The `authorityKeyIdentifier` extension MUST be present. [CABF BR §7.1.2.7.6]
2. The `authorityKeyIdentifier` MUST NOT be marked critical. [CABF BR §7.1.2.7.6]
3. The `keyIdentifier` field MUST be present and MUST equal the issuing CA's `subjectKeyIdentifier`. [CABF BR §7.1.2.11.1]
4. The `authorityCertIssuer` field MUST NOT be present. [CABF BR §7.1.2.11.1]
5. The `authorityCertSerialNumber` field MUST NOT be present. [CABF BR §7.1.2.11.1]

### 4.5 `certificatePolicies`

1. The `certificatePolicies` extension MUST be present. [CABF BR §7.1.2.7.6]
2. The `certificatePolicies` extension MUST NOT be marked critical. [CABF BR §7.1.2.7.6]
3. The extension MUST contain exactly one CABF Reserved Certificate Policy Identifier corresponding to the certificate's validation type: `2.23.140.1.2.1` for DV, `2.23.140.1.2.3` for IV, `2.23.140.1.2.2` for OV, or `2.23.140.1.1` for EV. [CABF BR §7.1.2.7.9]
4. The `certificatePolicies` extension MUST NOT contain `anyPolicy` (2.5.29.32.0). [CABF BR §7.1.2.7.9]
5. Additional CA-defined `policyIdentifier` OIDs MAY appear and MUST be defined in the issuing CA's CP/CPS. [CABF BR §7.1.2.7.9]
6. The first `PolicyInformation` SHOULD be the Reserved Certificate Policy Identifier. [CABF BR §7.1.2.7.9, footnote `first_policy_note`]
7. `policyQualifiers` are NOT RECOMMENDED; if present, MUST contain only `id-qt-cps` (1.3.6.1.5.5.7.2.1) qualifiers with an HTTP or HTTPS URL pointing to the CA's policy materials. [CABF BR §7.1.2.7.9]
8. `policyQualifiers` MUST NOT include any qualifier other than `id-qt-cps`. [CABF BR §7.1.2.7.9]
9. A LE-issued subscriber certificate's `certificatePolicies` MUST contain exactly the DV OID `2.23.140.1.2.1` and no other `policyIdentifier`. [LE §7.1 (DV-SSL Subscriber profile)] *(LE-issued only)*
10. A LE-issued subscriber certificate MUST NOT contain a `policyQualifiers` of type `id-qt-cps`. [LE §7.1, v5.2 change history] *(LE-issued only, since 2024-02-07)*
11. The CABF policy OID asserted in this certificate MUST be one of the TLS-server-auth Reserved Certificate Policy Identifiers from §7.1.6.1 (`2.23.140.1.2.1` DV, `2.23.140.1.2.3` IV, `2.23.140.1.2.2` OV, or `2.23.140.1.1` EV); the code-signing OID `2.23.140.1.4.1` and the S/MIME OIDs `2.23.140.1.5.x` listed by Microsoft §3.1.15 apply to non-TLS end-entity profiles and MUST NOT appear in a TLS subscriber certificate (already excluded by §4.6's EKU prohibitions on `id-kp-codeSigning` and `id-kp-emailProtection`). [Microsoft §3.1.15; CABF BR §7.1.2.7.9, §7.1.6.1]

### 4.6 `extKeyUsage`

1. The `extKeyUsage` extension MUST be present. [CABF BR §7.1.2.7.6, §7.1.2.7.10; Mozilla §5.2]
2. The `extKeyUsage` extension MUST NOT be marked critical. [CABF BR §7.1.2.7.6]
3. The `extKeyUsage` MUST contain `id-kp-serverAuth` (1.3.6.1.5.5.7.3.1). [CABF BR §7.1.2.7.10]
4. The `extKeyUsage` MAY contain `id-kp-clientAuth` (1.3.6.1.5.5.7.3.2). [CABF BR §7.1.2.7.10]
5. The `extKeyUsage` MUST NOT contain `id-kp-codeSigning` (1.3.6.1.5.5.7.3.3). [CABF BR §7.1.2.7.10]
6. The `extKeyUsage` MUST NOT contain `id-kp-emailProtection` (1.3.6.1.5.5.7.3.4). [CABF BR §7.1.2.7.10]
7. The `extKeyUsage` MUST NOT contain `id-kp-timeStamping` (1.3.6.1.5.5.7.3.8). [CABF BR §7.1.2.7.10]
8. The `extKeyUsage` MUST NOT contain `id-kp-OCSPSigning` (1.3.6.1.5.5.7.3.9). [CABF BR §7.1.2.7.10]
9. The `extKeyUsage` MUST NOT contain `anyExtendedKeyUsage` (2.5.29.37.0). [CABF BR §7.1.2.7.10; Mozilla §5.2]
10. The `extKeyUsage` MUST NOT contain the Precertificate Signing OID `1.3.6.1.4.1.11129.2.4.4`. [CABF BR §7.1.2.7.10]
11. Any OID in `extKeyUsage` other than `id-kp-serverAuth` and `id-kp-clientAuth` is NOT RECOMMENDED. [CABF BR §7.1.2.7.10]
12. Effective 2027-03-15, a subscriber certificate under a Chrome Root Store hierarchy MUST contain only `id-kp-serverAuth`. [Chrome §1.3.2(2)]
13. A subscriber certificate in an Applicant PKI hierarchy MUST contain only `id-kp-serverAuth`. [Chrome §2.3(2)]
14. A LE-issued subscriber certificate's `extKeyUsage` MUST contain `id-kp-serverAuth`, MAY contain `id-kp-clientAuth`, and MUST NOT contain any other OID. [LE §7.1 (DV-SSL Subscriber profile)] *(LE-issued only)*
15. Microsoft will only enable the following EKUs in its store: `id-kp-serverAuth`, `id-kp-clientAuth`, `id-kp-emailProtection`, `id-kp-timeStamping`, and `1.3.6.1.4.1.311.10.3.12` (Document Signing); EKUs outside this set are not recognized by Microsoft but are not themselves cert-content prohibited by §3.4.2. [Microsoft §3.4.2] *(Informational; for TLS subscriber certificates, §4.6 #5–#10 above already prohibit `id-kp-codeSigning`, `id-kp-emailProtection`, `id-kp-timeStamping`, `id-kp-OCSPSigning`, `anyExtendedKeyUsage`, and the Precertificate Signing OID.)*

### 4.7 `keyUsage`

1. The `keyUsage` extension SHOULD be present. [CABF BR §7.1.2.7.6]
2. If present, the `keyUsage` extension MUST be marked critical. [CABF BR §7.1.2.7.6]
3. The `nonRepudiation`, `keyAgreement` (RSA only), `encipherOnly`, `decipherOnly`, `keyCertSign`, and `cRLSign` bits MUST NOT be asserted. [CABF BR §7.1.2.7.11]

**If the SPKI is RSA:**

4. The `digitalSignature` bit MAY be asserted; it SHOULD be asserted for use with modern protocols. [CABF BR §7.1.2.7.11]
5. The `keyEncipherment` bit MAY be asserted. [CABF BR §7.1.2.7.11]
6. The `dataEncipherment` bit MAY be asserted but is NOT RECOMMENDED. [CABF BR §7.1.2.7.11]
7. The `keyAgreement`, `nonRepudiation`, `encipherOnly`, and `decipherOnly` bits MUST NOT be asserted. [CABF BR §7.1.2.7.11]
8. At least one of `digitalSignature`, `keyEncipherment`, or `dataEncipherment` MUST be asserted (i.e., `keyUsage` MUST NOT be all-zeros for an RSA key). [CABF BR §7.1.2.7.11 Note]

**If the SPKI is ECDSA:**

9. The `digitalSignature` bit MUST be asserted. [CABF BR §7.1.2.7.11]
10. The `keyAgreement` bit MAY be asserted but is NOT RECOMMENDED. [CABF BR §7.1.2.7.11]
11. The `nonRepudiation`, `keyEncipherment`, `dataEncipherment`, `encipherOnly`, and `decipherOnly` bits MUST NOT be asserted. [CABF BR §7.1.2.7.11]

**LE-specific:**

12. A LE-issued subscriber certificate's `keyUsage` extension MUST be present, MUST be marked critical, MUST assert `digitalSignature`, MAY assert `keyEncipherment`, and MUST NOT assert any other bit. [LE §7.1 (DV-SSL Subscriber profile)] *(LE-issued only)*

### 4.8 `basicConstraints`

1. The `basicConstraints` extension MAY be present. [CABF BR §7.1.2.7.6]
2. If present, the `basicConstraints` extension MUST be marked critical. [CABF BR §7.1.2.7.6]
3. If present, the `cA` boolean MUST be FALSE. [CABF BR §7.1.2.7.8; Microsoft §3.1.17]
4. If present, the `pathLenConstraint` field MUST NOT be present. [CABF BR §7.1.2.7.8; Microsoft §3.1.17]
5. A LE-issued subscriber certificate's `basicConstraints` MUST be present, MUST be marked critical, and MUST have `cA = FALSE`. [LE §7.1 (DV-SSL Subscriber profile)] *(LE-issued only)*

### 4.9 `subjectKeyIdentifier`

1. The `subjectKeyIdentifier` extension is NOT RECOMMENDED. [CABF BR §7.1.2.7.6]
2. If present, the `subjectKeyIdentifier` extension MUST NOT be marked critical. [CABF BR §7.1.2.7.6]
3. If present, the `subjectKeyIdentifier` value MUST be set per RFC 5280 §4.2.1.2 and MUST be unique within the issuing CA for the given public key. [CABF BR §7.1.2.11.4]

### 4.10 `cRLDistributionPoints`

1. The `cRLDistributionPoints` extension MUST be present in a subscriber certificate that is NOT a Short-lived Subscriber Certificate AND does not include an `id-ad-ocsp` AccessDescription in AIA. [CABF BR §7.1.2.11.2]
2. The `cRLDistributionPoints` extension is OPTIONAL in a Short-lived Subscriber Certificate. [CABF BR §7.1.2.11.2]
3. If present, the extension MUST NOT be marked critical. [CABF BR §7.1.2.7.6]
4. If present, the extension MUST contain at least one `DistributionPoint`; more than one is NOT RECOMMENDED. [CABF BR §7.1.2.11.2]
5. If present, each `DistributionPoint`'s `distributionPoint` field MUST be a `fullName`, MUST NOT include `reasons`, and MUST NOT include `cRLIssuer`. [CABF BR §7.1.2.11.2]
6. If present, every `GeneralName` in `fullName` MUST be `uniformResourceIdentifier`, and every URI scheme MUST be `http`. [CABF BR §7.1.2.11.2]
7. If present, the first `GeneralName` MUST be the HTTP URL of the issuing CA's CRL service. [CABF BR §7.1.2.11.2]
8. The CRL URL in `cRLDistributionPoints` MUST match exactly the URL disclosed in CCADB for the issuing CA. [CCADB §6.2]
9. The `cRLDistributionPoints` extension MUST NOT reference a non-operational CRL service. [Mozilla §5.2]
10. If a LE-issued subscriber certificate includes a `cRLDistributionPoints` extension, it MUST contain a URI to the CRL shard whose scope includes that certificate. [LE §7.1 (DV-SSL Subscriber profile)] *(LE-issued only)*

### 4.11 `nameConstraints`

1. The `nameConstraints` extension MUST NOT be present in a subscriber certificate. [CABF BR §7.1.2.7.6]

### 4.12 Precertificate poison and SCT List (Certificate Transparency)

#### 4.12.1 If the certificate is a precertificate (CABF §7.1.2.9)

1. The Precertificate Poison extension (OID `1.3.6.1.4.1.11129.2.4.3`) MUST be present. [CABF BR §7.1.2.9.1, §7.1.2.9.3]
2. The Precertificate Poison extension MUST be marked critical. [CABF BR §7.1.2.9.3]
3. The Precertificate Poison extension `extnValue` MUST be exactly the hex-encoded bytes `0500` (ASN.1 NULL). [CABF BR §7.1.2.9.3]
4. The SCT List extension MUST NOT be present in a precertificate. [CABF BR §7.1.2.9.1]
5. With the poison extension removed from the precertificate and the SCT List extension removed from the corresponding final certificate, the order, criticality, and encoded values of all remaining extensions MUST be byte-for-byte identical between the two certificates; for a precert-CA-issued precertificate, the `authorityKeyIdentifier` extension is additionally permitted to differ as described in §7.1.2.9.4 (where its `keyIdentifier` may either match the final certificate's AKI or match the Precertificate Signing CA's `subjectKeyIdentifier`). [CABF BR §7.1.2.9.1, §7.1.2.9.2, §7.1.2.9.4]
6. The precertificate's `serialNumber` MUST be byte-for-byte identical to the corresponding final certificate's `serialNumber`. [CABF BR §7.1.2.9]
7. The signature algorithm of a precertificate MUST be the same as that of the corresponding final certificate. [CABF BR §7.1.2.9]
8. As of 2026-03-15, a precertificate MUST NOT be issued by a Precertificate Signing CA; precertificates after that date MUST be issued directly by the Issuing CA. [CABF BR §7.1.2.4]

#### 4.12.2 If the certificate is a final TLS certificate

9. The Precertificate Poison extension MUST NOT be present. [CABF BR §7.1.2.9.1]
10. The SCT List extension (OID `1.3.6.1.4.1.11129.2.4.2`) MAY be present. [CABF BR §7.1.2.7.6]
11. If the SCT List extension is present, it MUST NOT be marked critical. [CABF BR §7.1.2.7.6]
12. If the SCT List extension is present, its `extnValue` MUST be an `OCTET STRING` containing a `SignedCertificateTimestampList` per RFC 6962 §3.3. [CABF BR §7.1.2.11.3]
13. Every `SignedCertificateTimestamp` in the SCT List MUST be for a `PreCert` `LogEntryType` corresponding to the current certificate. [CABF BR §7.1.2.11.3]
14. Effective 2026-06-15, a TLS server authentication final certificate MUST NOT be issued unless its corresponding precertificate has been logged to at least one CT log recognized by Chrome as Usable or Qualified before issuance of the final certificate. [Chrome §1.3.4.1]
15. A TLS server authentication precertificate SHOULD be logged to at least one Chrome-Usable/Qualified CT log within 24 hours of issuance. [Chrome §1.3.4.1]
16. A TLS server authentication final certificate SHOULD be logged to at least one Chrome-Usable/Qualified CT log within 24 hours of issuance. [Chrome §1.3.4.2]

#### 4.12.3 Precert-final consistency

17. If a final certificate exists for a logged precertificate (same serial + matching issuer relationship), the final certificate MUST exactly match the precertificate per RFC 6962 §3.1 (i.e., the only differences are removal of the poison extension and addition of the SCT List extension). [Mozilla §5.4; CABF BR §7.1.2.9.1]
18. A logged precertificate MUST itself comply with this entire profile as if it were the corresponding final certificate; non-compliance in the implied final certificate is misissuance. [Mozilla §5.4]
19. A LE-issued precertificate contains the RFC 6962 precertificate poison extension marked critical; a LE-issued final certificate contains the SCT List extension. [LE §7.1 (DV-SSL Subscriber profile)] *(LE-issued only; LE §7.1 frames this as descriptive practice.)*

### 4.13 Other extensions

1. Any extension not listed above is NOT RECOMMENDED. [CABF BR §7.1.2.7.6]
2. Any extension present MUST be DER-encoded according to the ASN.1 module defining it. [CABF BR §7.1.2.11.5]
3. Any extension present MUST apply in the context of the public Internet (or fall within an OID arc demonstrably owned by the applicant). [CABF BR §7.1.2.11.5]
4. Any extension present MUST NOT include semantics that mislead the relying party (e.g., asserting hardware key storage when the CA cannot verify it). [CABF BR §7.1.2.11.5]

## 5. Validation freshness (issuance-context constraints)

These are not byte-readable directly but constrain issuance and are checkable against CCADB-disclosed validation data or the cert's `notBefore`. The CABF reuse windows step down on the same date schedule as the leaf validity period (§1.5).

1. Each `dNSName` and `iPAddress` in `subjectAltName`, and each domain-form `commonName`, MUST have been completely validated via a method in CABF BR §3.2.2.4 (for domains) or §3.2.2.5 (for IPs) within 398 days before the certificate's signing (for certs issued before 2026-03-15). [CABF BR §4.2.1; Mozilla §2.1]
2. The domain/IP validation reuse window steps down to 200 days for certs issued on or after 2026-03-15 and before 2027-03-15. [CABF BR §4.2.1]
3. The domain/IP validation reuse window steps down to 100 days for certs issued on or after 2027-03-15 and before 2029-03-15. [CABF BR §4.2.1]
4. The domain/IP validation reuse window steps down to 10 days for certs issued on or after 2029-03-15. [CABF BR §4.2.1]
5. All non-DNS/IP subscriber identity information embedded in the certificate (e.g., `organizationName`, address attributes) MUST have been verified within the previous 825 days for certs issued before 2026-03-15. [Mozilla §2.1; CABF BR §4.2.1]
6. The non-DNS/IP subscriber-info reuse window steps down to 398 days for certs issued on or after 2026-03-15. [CABF BR §4.2.1]
7. Wildcard Domain Names MUST have been validated for consistency with CABF BR §3.2.2.6. [CABF BR §7.1.2.7.12]

## 6. Chrome-specific issuance and renewal constraints

These are CA/hierarchy-level requirements, not per-certificate cert-bytes rules; included here because they affect how a TLS subscriber certificate is renewed and managed.

1. The CA hierarchy issuing the subscriber certificate, if it supports the ACME protocol, MUST support ACME Renewal Information (ARI, RFC 9773). [Chrome §1.3.3.1.1] *(CA-level requirement; the cert itself does not carry ARI markers.)*
2. A subscriber certificate disclosed as an Automation Test Certificate MUST be renewed (re-issued) at least once every 30 calendar days. [Chrome §1.3.3.1, §2.4] *(Observable as the cert's `notBefore` relative to the disclosure timestamp.)*

## 7. Notes and intentional non-requirements

- The OCSP Responder Certificate profile (CABF §7.1.2.8) is a separate end-entity profile from subscriber certificates: it carries only `id-kp-OCSPSigning`, MUST include `id-pkix-ocsp-nocheck` (1.3.6.1.5.5.7.48.1.5), MUST NOT include `subjectAltName`, MUST NOT include `cRLDistributionPoints`, and is out of scope here unless your linter chooses to validate them.
- Subscriber certificates do not have an explicit prohibition on `subjectAltName` `iPAddress` entries pointing to public-internet addresses; they MUST simply not be Reserved IPs. [CABF BR §7.1.2.7.12]
- CABF §7.1.2.7.11 currently permits the `dataEncipherment` (RSA) and `keyAgreement` (ECDSA) bits but marks them as Pending Prohibitions ([cabforum/servercert#384](https://github.com/cabforum/servercert/issues/384)); linters MAY warn on them today.
- The Apple S/MIME end-entity profile (Apple §2.3) applies to S/MIME leaves rather than TLS server leaves; it is out of scope here.
- LE-specific items (marked *LE-issued only*) bind LE-issued subscriber certificates; they tighten but never loosen any universal CABF/program rule.
