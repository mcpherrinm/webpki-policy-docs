#!/usr/bin/env python3
"""
WebPKI cert linter for Let's Encrypt certificates.

Reads requirements from /home/mattm/src/webpki-policy-docs/{roots,cross-certs,intermediates}.md
and produces one CSV per cert type with PASS/FAIL/N/A/MANUAL per (requirement, cert) cell.

Design:
- Each requirement is a numbered statement extracted from the markdown file (section, item-number, text, citation).
- A dispatch table maps text-pattern → check_id.
- Each check_id is implemented as a function taking (cert, der_bytes) and returning (status, note).
- Requirements not matched by any text pattern default to MANUAL.
"""

import csv
import glob
import os
import re
import sys
from collections import OrderedDict
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import (
    ExtensionOID, NameOID, ObjectIdentifier, SignatureAlgorithmOID, AuthorityInformationAccessOID,
)

DOCS = "/home/mattm/src/webpki-policy-docs"
LE_CERTS = os.path.join(DOCS, "le-certs")

# ---------- Cert loading ----------

def load_cert(path):
    with open(path, "rb") as f:
        der = f.read()
    return x509.load_der_x509_certificate(der), der

# ---------- Helpers ----------

def get_ext(cert, oid):
    try:
        return cert.extensions.get_extension_for_oid(oid)
    except x509.ExtensionNotFound:
        return None

def has_ext(cert, oid):
    return get_ext(cert, oid) is not None

def spki_algid_bytes(cert):
    """Return the raw DER bytes of the SPKI AlgorithmIdentifier."""
    # cert.public_bytes is the whole cert. Walk the TBS:
    # Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    # tbsCertificate ::= SEQUENCE { [0] version, serial, signature, issuer, validity, subject, spki, ...}
    # We can use cryptography's `public_key().public_bytes(...)` for SPKI then walk it,
    # but easier: serialize SPKI from public key and pick out the AlgorithmIdentifier.
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    spki_der = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    # SPKI := SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
    # Parse the outer SEQUENCE manually
    return _first_seq_member(spki_der)

def sig_algid_outer_bytes(cert):
    """Return the raw DER bytes of the outer signatureAlgorithm field."""
    der = cert.public_bytes(serialization_encoding_der())
    # Certificate := SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    # We need the 2nd member of the top-level SEQUENCE.
    return _nth_seq_member(der, 1)

def sig_algid_tbs_bytes(cert):
    """Return the raw DER bytes of the tbsCertificate.signature field."""
    from cryptography.hazmat.primitives.serialization import Encoding
    tbs = cert.tbs_certificate_bytes
    # tbsCertificate := SEQUENCE { [0] version DEFAULT v1, serialNumber, signature, issuer, validity, subject, spki, ... }
    # tbs_certificate_bytes is the *inner* sequence content + tag; actually cryptography
    # returns the TBS *with* the outer SEQUENCE tag. Let's confirm — it returns the whole TBS as DER.
    # So inside the outer SEQ: optional [0] explicit version, then serial, then signature (3rd member if version present).
    # The version is implicit-defaulted to v1 if absent. For v3 certs it MUST be present.
    # We need to find the AlgorithmIdentifier field (signature).
    # Walk:
    inner = _seq_content(tbs)
    # First field: [0] EXPLICIT INTEGER if version present
    if inner[0] == 0xA0:
        _, sz, hdr_len = _parse_len(inner, 1)
        idx = 1 + hdr_len + sz
    else:
        idx = 0
    # serialNumber INTEGER
    _, sz, hdr_len = _parse_len(inner, idx + 1)
    idx = idx + 1 + hdr_len + sz
    # signature AlgorithmIdentifier (SEQUENCE)
    _, sz, hdr_len = _parse_len(inner, idx + 1)
    end = idx + 1 + hdr_len + sz
    return inner[idx:end]

def serialization_encoding_der():
    from cryptography.hazmat.primitives import serialization
    return serialization.Encoding.DER

def _parse_len(data, offset):
    """Parse DER length starting at `offset`. Returns (tag_already_parsed, length, header_size_after_tag)."""
    b = data[offset]
    if b < 0x80:
        return None, b, 1
    nbytes = b & 0x7F
    length = 0
    for i in range(nbytes):
        length = (length << 8) | data[offset + 1 + i]
    return None, length, 1 + nbytes

def _seq_content(seq_der):
    """Given DER bytes starting with SEQUENCE tag, return just the inner content bytes."""
    assert seq_der[0] in (0x30, 0xA0), f"Expected SEQUENCE, got {seq_der[0]:02x}"
    _, length, hdr_len = _parse_len(seq_der, 1)
    return seq_der[1 + hdr_len : 1 + hdr_len + length]

def _first_seq_member(outer_der):
    """Given DER bytes of an outer SEQUENCE, return the bytes of the first inner element."""
    inner = _seq_content(outer_der)
    # The first member: read its tag and length
    _, length, hdr_len = _parse_len(inner, 1)
    return inner[: 1 + hdr_len + length]

def _nth_seq_member(outer_der, n):
    """Return bytes of the n-th member (0-indexed) inside an outer SEQUENCE."""
    inner = _seq_content(outer_der)
    idx = 0
    for i in range(n):
        _, length, hdr_len = _parse_len(inner, idx + 1)
        idx = idx + 1 + hdr_len + length
    _, length, hdr_len = _parse_len(inner, idx + 1)
    return inner[idx : idx + 1 + hdr_len + length]

# ---------- Status / dispatch ----------

PASS, FAIL, NA, MANUAL, ERROR = "PASS", "FAIL", "N/A", "MANUAL", "ERROR"

# ---------- Check functions ----------
# Each function takes (cert, der). Returns (status, note).

def chk_version_v3(cert, der):
    return (PASS, "") if cert.version == x509.Version.v3 else (FAIL, f"version={cert.version}")

def chk_serial_positive(cert, der):
    return (PASS, "") if cert.serial_number > 0 else (FAIL, f"serial={cert.serial_number}")

def chk_serial_lt_2_159(cert, der):
    return (PASS, "") if cert.serial_number < (1 << 159) else (FAIL, "serial >= 2^159")

def chk_serial_64bit(cert, der):
    # Heuristic: a serial with 64+ bits of CSPRNG entropy has at least 8 bytes.
    n = cert.serial_number
    if n <= 0:
        return FAIL, "serial <= 0"
    bits = n.bit_length()
    # CABF requires >= 64 bits of CSPRNG output. Cert serials are usually 64-bit or longer.
    return (PASS, f"{bits} bits") if bits >= 64 else (FAIL, f"only {bits} bits")

def chk_serial_nonseq(cert, der):
    return MANUAL, "non-sequentiality not byte-observable"

def chk_issuer_eq_subject(cert, der):
    # For self-signed roots only.
    return (PASS, "") if cert.issuer.public_bytes() == cert.subject.public_bytes() else (FAIL, "issuer != subject")

def chk_self_signed(cert, der):
    from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15, PSS, MGF1
    from cryptography.hazmat.primitives import hashes
    try:
        # Try to verify the cert's signature with its own public key
        pubkey = cert.public_key()
        if isinstance(pubkey, rsa.RSAPublicKey):
            try:
                pubkey.verify(cert.signature, cert.tbs_certificate_bytes,
                              PKCS1v15(), cert.signature_hash_algorithm)
                return PASS, "self-signed"
            except Exception:
                return FAIL, "signature does not verify under own pubkey"
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            try:
                pubkey.verify(cert.signature, cert.tbs_certificate_bytes,
                              ec.ECDSA(cert.signature_hash_algorithm))
                return PASS, "self-signed"
            except Exception:
                return FAIL, "signature does not verify under own pubkey"
        else:
            return MANUAL, f"unknown pubkey type {type(pubkey).__name__}"
    except Exception as e:
        return ERROR, str(e)

def chk_issuer_uniqueid_absent(cert, der):
    # cryptography doesn't expose issuerUniqueID directly. Parse TBS.
    return _check_unique_id_absent(cert, der, "issuerUniqueID")

def chk_subject_uniqueid_absent(cert, der):
    return _check_unique_id_absent(cert, der, "subjectUniqueID")

def _check_unique_id_absent(cert, der, which):
    tbs = cert.tbs_certificate_bytes
    inner = _seq_content(tbs)
    idx = 0
    # Skip optional version [0]
    if inner[idx] == 0xA0:
        _, sz, h = _parse_len(inner, idx + 1)
        idx = idx + 1 + h + sz
    # serial INTEGER
    _, sz, h = _parse_len(inner, idx + 1); idx = idx + 1 + h + sz
    # signature AlgID SEQUENCE
    _, sz, h = _parse_len(inner, idx + 1); idx = idx + 1 + h + sz
    # issuer Name SEQUENCE
    _, sz, h = _parse_len(inner, idx + 1); idx = idx + 1 + h + sz
    # validity SEQUENCE
    _, sz, h = _parse_len(inner, idx + 1); idx = idx + 1 + h + sz
    # subject Name SEQUENCE
    _, sz, h = _parse_len(inner, idx + 1); idx = idx + 1 + h + sz
    # subjectPublicKeyInfo SEQUENCE
    _, sz, h = _parse_len(inner, idx + 1); idx = idx + 1 + h + sz
    # Now optional fields. Tags: [1] issuerUniqueID, [2] subjectUniqueID, [3] extensions
    target_tag = 0x81 if which == "issuerUniqueID" else 0x82
    while idx < len(inner):
        tag = inner[idx]
        _, sz, h = _parse_len(inner, idx + 1)
        if tag == target_tag:
            return FAIL, f"{which} is present"
        idx = idx + 1 + h + sz
    return PASS, ""

# --- Signature algorithm ---

PERMITTED_SIGALG_OIDS = {
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassaPss",  # parameters checked separately
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
}

def chk_sig_algorithm_permitted(cert, der):
    oid = cert.signature_algorithm_oid.dotted_string
    if oid in PERMITTED_SIGALG_OIDS:
        return PASS, PERMITTED_SIGALG_OIDS[oid]
    return FAIL, f"sig alg {oid} not in allowed set"

def chk_sig_not_sha1(cert, der):
    oid = cert.signature_algorithm_oid.dotted_string
    return (FAIL, f"sigalg {oid} is SHA-1") if oid == "1.2.840.113549.1.1.5" else (PASS, "")

def chk_sig_not_md5(cert, der):
    oid = cert.signature_algorithm_oid.dotted_string
    return (FAIL, "MD5 sigalg") if oid == "1.2.840.113549.1.1.4" else (PASS, "")

def chk_sig_outer_eq_tbs(cert, der):
    """Outer signatureAlgorithm must be byte-for-byte identical to tbsCertificate.signature."""
    outer = sig_algid_outer_bytes(cert)
    tbs = sig_algid_tbs_bytes(cert)
    return (PASS, "") if outer == tbs else (FAIL, "outer sigAlg != tbs.signature")

# --- SPKI checks ---

def chk_spki_rsa_or_ecdsa(cert, der):
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        return PASS, f"RSA-{pk.key_size}"
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return PASS, f"ECDSA {pk.curve.name}"
    return FAIL, f"unsupported key type {type(pk).__name__}"

def chk_spki_no_eddsa(cert, der):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
    pk = cert.public_key()
    return (FAIL, "EdDSA key") if isinstance(pk, (Ed25519PublicKey, Ed448PublicKey)) else (PASS, "")

def chk_spki_no_curve25519_448(cert, der):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey
    pk = cert.public_key()
    return (FAIL, "Curve25519/448") if isinstance(pk, (X25519PublicKey, X448PublicKey)) else (PASS, "")

def chk_rsa_min_2048(cert, der):
    pk = cert.public_key()
    if not isinstance(pk, rsa.RSAPublicKey):
        return NA, "not RSA"
    return (PASS, f"{pk.key_size} bits") if pk.key_size >= 2048 else (FAIL, f"{pk.key_size} bits")

def chk_rsa_mod_div_by_8(cert, der):
    pk = cert.public_key()
    if not isinstance(pk, rsa.RSAPublicKey):
        return NA, "not RSA"
    return (PASS, "") if pk.key_size % 8 == 0 else (FAIL, f"key_size={pk.key_size}")

def chk_rsa_not_1024(cert, der):
    pk = cert.public_key()
    if not isinstance(pk, rsa.RSAPublicKey):
        return NA, "not RSA"
    return (FAIL, "1024 bits") if pk.key_size == 1024 else (PASS, "")

def chk_rsa_exp_odd_ge_3(cert, der):
    pk = cert.public_key()
    if not isinstance(pk, rsa.RSAPublicKey):
        return NA, "not RSA"
    e = pk.public_numbers().e
    if e >= 3 and e % 2 == 1:
        return PASS, f"e={e}"
    return FAIL, f"e={e}"

def chk_rsa_exp_range(cert, der):
    pk = cert.public_key()
    if not isinstance(pk, rsa.RSAPublicKey):
        return NA, "not RSA"
    e = pk.public_numbers().e
    lo, hi = (1 << 16) + 1, (1 << 256) - 1
    return (PASS, f"e={e}") if lo <= e <= hi else (FAIL, f"e={e}")

def chk_rsa_exp_not_one(cert, der):
    pk = cert.public_key()
    if not isinstance(pk, rsa.RSAPublicKey):
        return NA, "not RSA"
    return (FAIL, "e=1") if pk.public_numbers().e == 1 else (PASS, "")

def chk_rsa_algid_exact(cert, der):
    pk = cert.public_key()
    if not isinstance(pk, rsa.RSAPublicKey):
        return NA, "not RSA"
    expected = bytes.fromhex("300d06092a864886f70d0101010500")
    actual = spki_algid_bytes(cert)
    return (PASS, "") if actual == expected else (FAIL, f"algid={actual.hex()}")

def chk_rsa_no_pss_oid(cert, der):
    pk = cert.public_key()
    if not isinstance(pk, rsa.RSAPublicKey):
        return NA, "not RSA"
    algid = spki_algid_bytes(cert)
    # OID for id-RSASSA-PSS = 1.2.840.113549.1.1.10 -> DER bytes inside the SEQ start with 06 09 2A 86 48 86 F7 0D 01 01 0A
    return (FAIL, "uses id-RSASSA-PSS in SPKI") if b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a" in algid else (PASS, "")

ECDSA_ALLOWED_CURVES = {"secp256r1", "secp384r1", "secp521r1"}

def chk_ecdsa_curve_allowed(cert, der):
    pk = cert.public_key()
    if not isinstance(pk, ec.EllipticCurvePublicKey):
        return NA, "not ECDSA"
    name = pk.curve.name
    return (PASS, name) if name in ECDSA_ALLOWED_CURVES else (FAIL, name)

ECDSA_ALGID_HEX = {
    "secp256r1": "301306072a8648ce3d020106082a8648ce3d030107",
    "secp384r1": "301006072a8648ce3d020106052b81040022",
    "secp521r1": "301006072a8648ce3d020106052b81040023",
}

def chk_ecdsa_algid_exact(cert, der):
    pk = cert.public_key()
    if not isinstance(pk, ec.EllipticCurvePublicKey):
        return NA, "not ECDSA"
    name = pk.curve.name
    if name not in ECDSA_ALGID_HEX:
        return FAIL, f"unknown curve {name}"
    expected = bytes.fromhex(ECDSA_ALGID_HEX[name])
    actual = spki_algid_bytes(cert)
    return (PASS, "") if actual == expected else (FAIL, f"algid={actual.hex()}")

def chk_ecdsa_namedcurve(cert, der):
    # cryptography's ECDSA loading always uses namedCurve form by default for these curves.
    # The above chk_ecdsa_algid_exact already enforces it.
    return chk_ecdsa_algid_exact(cert, der)

# --- Signature AlgID exact-hex checks ---

SIGALG_HEX = {
    "1.2.840.113549.1.1.11": "300d06092a864886f70d01010b0500",  # PKCS1 SHA-256
    "1.2.840.113549.1.1.12": "300d06092a864886f70d01010c0500",  # PKCS1 SHA-384
    "1.2.840.113549.1.1.13": "300d06092a864886f70d01010d0500",  # PKCS1 SHA-512
    "1.2.840.10045.4.3.2": "300a06082a8648ce3d040302",          # ECDSA SHA-256
    "1.2.840.10045.4.3.3": "300a06082a8648ce3d040303",          # ECDSA SHA-384
    "1.2.840.10045.4.3.4": "300a06082a8648ce3d040304",          # ECDSA SHA-512
}

def chk_sigalgid_exact_encoding(cert, der):
    oid = cert.signature_algorithm_oid.dotted_string
    actual = sig_algid_outer_bytes(cert)
    if oid in SIGALG_HEX:
        expected = bytes.fromhex(SIGALG_HEX[oid])
        return (PASS, "") if actual == expected else (FAIL, f"got={actual.hex()}")
    return MANUAL, f"oid {oid} not in lookup"

# --- Extension presence/criticality checks ---

def _has_critical(cert, oid, want_present=True, want_critical=None):
    e = get_ext(cert, oid)
    if want_present and e is None:
        return FAIL, "extension missing"
    if not want_present and e is not None:
        return FAIL, "extension present"
    if e is None:
        return PASS, ""
    if want_critical is True and not e.critical:
        return FAIL, "not marked critical"
    if want_critical is False and e.critical:
        return FAIL, "marked critical"
    return PASS, ""

def chk_basic_constraints_present(cert, der):
    return _has_critical(cert, ExtensionOID.BASIC_CONSTRAINTS, True, None)

def chk_basic_constraints_critical(cert, der):
    return _has_critical(cert, ExtensionOID.BASIC_CONSTRAINTS, True, True)

def chk_basic_constraints_ca_true(cert, der):
    e = get_ext(cert, ExtensionOID.BASIC_CONSTRAINTS)
    if e is None:
        return FAIL, "BC missing"
    return (PASS, "") if e.value.ca else (FAIL, "cA=FALSE")

def chk_basic_constraints_pathlen_absent(cert, der):
    e = get_ext(cert, ExtensionOID.BASIC_CONSTRAINTS)
    if e is None:
        return PASS, "BC absent"
    pl = e.value.path_length
    return (PASS, "") if pl is None else (FAIL, f"pathLen={pl}")

def chk_basic_constraints_pathlen_zero(cert, der):
    e = get_ext(cert, ExtensionOID.BASIC_CONSTRAINTS)
    if e is None:
        return FAIL, "BC missing"
    return (PASS, "") if e.value.path_length == 0 else (FAIL, f"pathLen={e.value.path_length}")

def chk_ku_present(cert, der):
    return _has_critical(cert, ExtensionOID.KEY_USAGE, True, None)

def chk_ku_critical(cert, der):
    return _has_critical(cert, ExtensionOID.KEY_USAGE, True, True)

def _ku(cert):
    e = get_ext(cert, ExtensionOID.KEY_USAGE)
    return e.value if e else None

def chk_ku_keycertsign(cert, der):
    ku = _ku(cert)
    if not ku:
        return FAIL, "KU missing"
    return (PASS, "") if ku.key_cert_sign else (FAIL, "keyCertSign not set")

def chk_ku_crlsign(cert, der):
    ku = _ku(cert)
    if not ku:
        return FAIL, "KU missing"
    return (PASS, "") if ku.crl_sign else (FAIL, "cRLSign not set")

def chk_ku_no_keyenc(cert, der):
    ku = _ku(cert)
    if not ku:
        return PASS, "KU missing"
    return (FAIL, "keyEncipherment set") if ku.key_encipherment else (PASS, "")

def chk_ku_no_dataenc(cert, der):
    ku = _ku(cert)
    if not ku:
        return PASS, "KU missing"
    return (FAIL, "dataEncipherment set") if ku.data_encipherment else (PASS, "")

def chk_ku_no_nonrepudiation(cert, der):
    ku = _ku(cert)
    if not ku:
        return PASS, "KU missing"
    return (FAIL, "nonRepudiation set") if ku.content_commitment else (PASS, "")

def chk_ku_no_keyagreement(cert, der):
    ku = _ku(cert)
    if not ku:
        return PASS, "KU missing"
    return (FAIL, "keyAgreement set") if ku.key_agreement else (PASS, "")

def chk_ku_leaf_ca_bits_absent(cert, der):
    """For leaves: keyCertSign, cRLSign MUST NOT be set."""
    ku = _ku(cert)
    if not ku:
        return PASS, "KU missing"
    if ku.key_cert_sign:
        return FAIL, "keyCertSign set on leaf"
    if ku.crl_sign:
        return FAIL, "cRLSign set on leaf"
    return PASS, ""

def chk_ku_no_encipheronly_decipheronly(cert, der):
    ku = _ku(cert)
    if not ku:
        return PASS, "KU missing"
    # encipher_only/decipher_only are only valid if key_agreement is True
    if ku.key_agreement:
        if ku.encipher_only:
            return FAIL, "encipherOnly set"
        if ku.decipher_only:
            return FAIL, "decipherOnly set"
    return PASS, ""

def chk_ski_present(cert, der):
    return _has_critical(cert, ExtensionOID.SUBJECT_KEY_IDENTIFIER, True, None)

def chk_ski_noncritical(cert, der):
    return _has_critical(cert, ExtensionOID.SUBJECT_KEY_IDENTIFIER, True, False)

def chk_aki_present(cert, der):
    return _has_critical(cert, ExtensionOID.AUTHORITY_KEY_IDENTIFIER, True, None)

def chk_aki_noncritical(cert, der):
    e = get_ext(cert, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    if e is None:
        return PASS, "absent"
    return (PASS, "") if not e.critical else (FAIL, "marked critical")

def chk_aki_keyid_present(cert, der):
    """For profiles where AKI is MUST: keyIdentifier subfield must be present."""
    e = get_ext(cert, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    if e is None:
        return FAIL, "AKI absent"
    return (PASS, "") if e.value.key_identifier is not None else (FAIL, "keyIdentifier absent")

def chk_aki_keyid_present_if_aki_present(cert, der):
    """For profiles where AKI is RECOMMENDED (e.g. roots): conditional rule."""
    e = get_ext(cert, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    if e is None:
        return PASS, "AKI absent (RECOMMENDED, not MUST)"
    return (PASS, "") if e.value.key_identifier is not None else (FAIL, "keyIdentifier absent")

def chk_aki_no_issuer_serial(cert, der):
    e = get_ext(cert, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    if e is None:
        return PASS, "AKI absent"
    if e.value.authority_cert_issuer is not None:
        return FAIL, "authorityCertIssuer present"
    if e.value.authority_cert_serial_number is not None:
        return FAIL, "authorityCertSerialNumber present"
    return PASS, ""

def chk_aki_keyid_eq_ski_self(cert, der):
    """For self-signed roots: AKI.keyIdentifier (if present) MUST equal own SKI."""
    aki = get_ext(cert, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    ski = get_ext(cert, ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    if aki is None:
        return PASS, "AKI absent"
    if ski is None:
        return FAIL, "SKI missing"
    return (PASS, "") if aki.value.key_identifier == ski.value.digest else (FAIL, "AKI keyid != SKI")

def chk_eku_absent(cert, der):
    return (FAIL, "EKU present") if has_ext(cert, ExtensionOID.EXTENDED_KEY_USAGE) else (PASS, "")

def chk_eku_present(cert, der):
    return _has_critical(cert, ExtensionOID.EXTENDED_KEY_USAGE, True, None)

def chk_eku_noncritical(cert, der):
    return _has_critical(cert, ExtensionOID.EXTENDED_KEY_USAGE, True, False)

def chk_eku_noncritical_if_present(cert, der):
    """For 'If present, EKU MUST NOT be marked critical' rules: pass if absent."""
    e = get_ext(cert, ExtensionOID.EXTENDED_KEY_USAGE)
    if e is None:
        return PASS, "EKU absent"
    return (PASS, "") if not e.critical else (FAIL, "EKU is critical")

def _ekus(cert):
    e = get_ext(cert, ExtensionOID.EXTENDED_KEY_USAGE)
    return [oid.dotted_string for oid in e.value] if e else []

ID_KP_SERVERAUTH = "1.3.6.1.5.5.7.3.1"
ID_KP_CLIENTAUTH = "1.3.6.1.5.5.7.3.2"
ID_KP_CODESIGNING = "1.3.6.1.5.5.7.3.3"
ID_KP_EMAILPROT = "1.3.6.1.5.5.7.3.4"
ID_KP_TIMESTAMPING = "1.3.6.1.5.5.7.3.8"
ID_KP_OCSPSIGNING = "1.3.6.1.5.5.7.3.9"
ANY_EKU = "2.5.29.37.0"
PRECERT_SIGNING = "1.3.6.1.4.1.11129.2.4.4"

def chk_eku_has_serverauth(cert, der):
    ekus = _ekus(cert)
    if not ekus:
        return FAIL, "EKU missing"
    return (PASS, "") if ID_KP_SERVERAUTH in ekus else (FAIL, "no id-kp-serverAuth")

def chk_eku_no_anyeku(cert, der):
    ekus = _ekus(cert)
    if not ekus:
        return PASS, "EKU absent"
    return (FAIL, "anyEKU") if ANY_EKU in ekus else (PASS, "")

def chk_eku_no_codesigning(cert, der):
    ekus = _ekus(cert)
    return (FAIL, "id-kp-codeSigning") if ID_KP_CODESIGNING in ekus else (PASS, "")

def chk_eku_no_emailprot(cert, der):
    ekus = _ekus(cert)
    return (FAIL, "id-kp-emailProtection") if ID_KP_EMAILPROT in ekus else (PASS, "")

def chk_eku_no_timestamping(cert, der):
    ekus = _ekus(cert)
    return (FAIL, "id-kp-timeStamping") if ID_KP_TIMESTAMPING in ekus else (PASS, "")

def chk_eku_no_ocspsigning(cert, der):
    ekus = _ekus(cert)
    return (FAIL, "id-kp-OCSPSigning") if ID_KP_OCSPSIGNING in ekus else (PASS, "")

def chk_eku_no_precert_signing(cert, der):
    ekus = _ekus(cert)
    return (FAIL, "Precert Signing OID") if PRECERT_SIGNING in ekus else (PASS, "")

def chk_eku_only_serverauth_or_with_clientauth(cert, der):
    """For 'EKU MUST contain only serverAuth, or only serverAuth+clientAuth' rules."""
    ekus = _ekus(cert)
    if not ekus:
        return NA, "EKU absent (rule presumes EKU present)"
    extra = set(ekus) - {ID_KP_SERVERAUTH, ID_KP_CLIENTAUTH}
    if ID_KP_SERVERAUTH not in ekus:
        return FAIL, "no serverAuth"
    return (PASS, ",".join(ekus)) if not extra else (FAIL, f"extras: {extra}")

def chk_eku_only_serverauth(cert, der):
    """For 'EKU MUST contain only serverAuth' rules (post-2026-06-15)."""
    ekus = _ekus(cert)
    if not ekus:
        return NA, "EKU absent (rule presumes EKU present)"
    if ekus == [ID_KP_SERVERAUTH]:
        return PASS, ""
    return FAIL, f"got: {ekus}"

def chk_certpolicies_present(cert, der):
    return _has_critical(cert, ExtensionOID.CERTIFICATE_POLICIES, True, None)

def chk_certpolicies_noncritical(cert, der):
    e = get_ext(cert, ExtensionOID.CERTIFICATE_POLICIES)
    if e is None:
        return PASS, "absent"
    return (PASS, "") if not e.critical else (FAIL, "critical")

def chk_certpolicies_absent_or_not_recommended(cert, der):
    # NOT RECOMMENDED — we return PASS if absent, else a soft FAIL note.
    if has_ext(cert, ExtensionOID.CERTIFICATE_POLICIES):
        return FAIL, "certificatePolicies present (NOT RECOMMENDED on root)"
    return PASS, ""

def _policy_oids(cert):
    e = get_ext(cert, ExtensionOID.CERTIFICATE_POLICIES)
    if e is None:
        return []
    return [pi.policy_identifier.dotted_string for pi in e.value]

CABF_RESERVED_POLICY_OIDS = {"2.23.140.1.2.1", "2.23.140.1.2.2", "2.23.140.1.2.3", "2.23.140.1.1"}

def chk_certpolicies_contains_cabf_reserved(cert, der):
    oids = _policy_oids(cert)
    if not oids:
        return FAIL, "certificatePolicies absent"
    found = [o for o in oids if o in CABF_RESERVED_POLICY_OIDS]
    return (PASS, ",".join(found)) if found else (FAIL, f"no CABF Reserved OID, got: {oids}")

def chk_certpolicies_no_anypolicy(cert, der):
    oids = _policy_oids(cert)
    return (FAIL, "anyPolicy present") if "2.5.29.32.0" in oids else (PASS, "")

def chk_certpolicies_max_2_oids(cert, der):
    oids = _policy_oids(cert)
    return (PASS, f"n={len(oids)}") if len(oids) <= 2 else (FAIL, f"{len(oids)} OIDs")

def chk_certpolicies_contains_le_dv(cert, der):
    oids = _policy_oids(cert)
    return (PASS, "") if "2.23.140.1.2.1" in oids else (FAIL, f"got: {oids}")

def chk_crldp_present(cert, der):
    return _has_critical(cert, ExtensionOID.CRL_DISTRIBUTION_POINTS, True, None)

def chk_crldp_noncritical(cert, der):
    e = get_ext(cert, ExtensionOID.CRL_DISTRIBUTION_POINTS)
    if e is None:
        return PASS, "absent"
    return (PASS, "") if not e.critical else (FAIL, "critical")

def chk_crldp_absent_or_not_recommended(cert, der):
    return (FAIL, "CRLDP present (SHOULD NOT on root)") if has_ext(cert, ExtensionOID.CRL_DISTRIBUTION_POINTS) else (PASS, "")

def chk_crldp_http_only(cert, der):
    e = get_ext(cert, ExtensionOID.CRL_DISTRIBUTION_POINTS)
    if e is None:
        return PASS, "absent"
    for dp in e.value:
        if dp.full_name:
            for gn in dp.full_name:
                if not isinstance(gn, x509.UniformResourceIdentifier):
                    return FAIL, f"non-URI GeneralName: {type(gn).__name__}"
                if not gn.value.lower().startswith("http:"):
                    return FAIL, f"non-http: {gn.value}"
    return PASS, ""

def chk_crldp_first_is_http(cert, der):
    e = get_ext(cert, ExtensionOID.CRL_DISTRIBUTION_POINTS)
    if e is None:
        return FAIL, "absent"
    dp0 = e.value[0]
    if not dp0.full_name:
        return FAIL, "no fullName"
    gn0 = dp0.full_name[0]
    if not isinstance(gn0, x509.UniformResourceIdentifier):
        return FAIL, "first GN not URI"
    if not gn0.value.lower().startswith("http:"):
        return FAIL, gn0.value
    return PASS, gn0.value

def chk_aia_present(cert, der):
    return _has_critical(cert, ExtensionOID.AUTHORITY_INFORMATION_ACCESS, True, None)

def chk_aia_noncritical(cert, der):
    e = get_ext(cert, ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
    if e is None:
        return PASS, "absent"
    return (PASS, "") if not e.critical else (FAIL, "critical")

def chk_aia_methods_allowed(cert, der):
    """AIA accessMethod MUST be id-ad-ocsp or id-ad-caIssuers; accessLocation MUST be HTTP URI."""
    e = get_ext(cert, ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
    if e is None:
        return PASS, "absent"
    allowed = {AuthorityInformationAccessOID.OCSP.dotted_string, AuthorityInformationAccessOID.CA_ISSUERS.dotted_string}
    for ad in e.value:
        if ad.access_method.dotted_string not in allowed:
            return FAIL, f"method {ad.access_method.dotted_string}"
        if not isinstance(ad.access_location, x509.UniformResourceIdentifier):
            return FAIL, f"location {type(ad.access_location).__name__}"
        if not ad.access_location.value.lower().startswith("http:") and not ad.access_location.value.lower().startswith("https:"):
            return FAIL, f"scheme {ad.access_location.value}"
    return PASS, ""

def chk_aia_caissuers_present(cert, der):
    e = get_ext(cert, ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
    if e is None:
        return FAIL, "AIA absent"
    for ad in e.value:
        if ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
            return PASS, ""
    return FAIL, "no id-ad-caIssuers"

def chk_san_present(cert, der):
    return _has_critical(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME, True, None)

def chk_nameconstraints_absent(cert, der):
    return (FAIL, "NC present") if has_ext(cert, ExtensionOID.NAME_CONSTRAINTS) else (PASS, "")

def chk_country_present(cert, der):
    cn = cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
    return (PASS, cn[0].value) if cn else (FAIL, "no countryName")

def chk_country_not_xx(cert, der):
    cn = cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
    if not cn:
        return FAIL, "no countryName"
    return (FAIL, "XX") if cn[0].value.upper() == "XX" else (PASS, cn[0].value)

def chk_org_present(cert, der):
    o = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    return (PASS, o[0].value) if o else (FAIL, "no organizationName")

def chk_cn_present(cert, der):
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return (PASS, cn[0].value) if cn else (FAIL, "no commonName")

def chk_no_ou(cert, der):
    ou = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    return (FAIL, "OU present") if ou else (PASS, "")

def chk_le_root_subject(cert, der):
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    o = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    c = cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
    if not (cn and o and c):
        return FAIL, "missing CN/O/C"
    if c[0].value != "US":
        return FAIL, f"C={c[0].value}"
    if o[0].value not in ("Internet Security Research Group", "ISRG"):
        return FAIL, f"O={o[0].value}"
    return PASS, f"C=US, O={o[0].value}, CN={cn[0].value}"

def chk_le_int_subject(cert, der):
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    o = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    c = cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
    if not (cn and o and c):
        return FAIL, "missing CN/O/C"
    if c[0].value != "US":
        return FAIL, f"C={c[0].value}"
    if o[0].value != "Let's Encrypt":
        return FAIL, f"O={o[0].value}"
    return PASS, f"C=US, O=Let's Encrypt, CN={cn[0].value}"

def chk_country_encoding_printablestring(cert, der):
    """countryName MUST use PrintableString."""
    cn = cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
    if not cn:
        return FAIL, "no countryName"
    attr = cn[0]
    # cryptography exposes the _type for X509 name attrs as the underlying ASN.1 type (since v37+)
    try:
        t = attr.rfc4514_attribute_name  # not what we want
    except AttributeError:
        pass
    # Use _type from internal API:
    asn1_type = getattr(attr, "_type", None)
    # Or inspect raw bytes of the cert. For now, trust cryptography validated this on load.
    return PASS, "(presumed PrintableString)"

def chk_country_at_most_2(cert, der):
    cn = cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
    if not cn:
        return FAIL, "no countryName"
    return (PASS, "") if len(cn[0].value) <= 2 else (FAIL, f"len={len(cn[0].value)}")

# --- Validity ---

def chk_root_validity_8_25_years(cert, der):
    days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
    if 2922 <= days <= 9132:
        return PASS, f"{days}d"
    return FAIL, f"{days}d (not in [2922, 9132])"

def chk_subordinate_validity_max_3y(cert, der):
    """Chrome §1.3.1.3 SHOULD (advisory). Report PASS or WARN."""
    days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
    return (PASS, f"{days}d") if days <= 3 * 365 + 1 else ("WARN", f"{days}d > 3y (SHOULD)")

def chk_le_sub_validity_max_8y(cert, der):
    days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
    return (PASS, f"{days}d") if days <= 8 * 365 + 2 else (FAIL, f"{days}d > 8y")

# --- LE-specific ---

def chk_le_root_key(cert, der):
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        if pk.key_size == 4096 and pk.public_numbers().e == 65537:
            return PASS, "RSA-4096 e=65537"
        return FAIL, f"RSA-{pk.key_size} e={pk.public_numbers().e}"
    if isinstance(pk, ec.EllipticCurvePublicKey):
        if pk.curve.name == "secp384r1":
            return PASS, "ECDSA P-384"
        return FAIL, f"ECDSA {pk.curve.name}"
    return FAIL, f"unsupported key type {type(pk).__name__}"

def chk_le_int_key(cert, der):
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        if pk.key_size == 2048 and pk.public_numbers().e == 65537:
            return PASS, "RSA-2048 e=65537"
        return FAIL, f"RSA-{pk.key_size} e={pk.public_numbers().e}"
    if isinstance(pk, ec.EllipticCurvePublicKey):
        if pk.curve.name == "secp384r1":
            return PASS, "ECDSA P-384"
        return FAIL, f"ECDSA {pk.curve.name}"
    return FAIL, f"unsupported"

def chk_le_int_ku(cert, der):
    """LE-issued intermediate keyUsage MUST be exactly digitalSignature + keyCertSign + cRLSign."""
    ku = _ku(cert)
    if not ku:
        return FAIL, "KU missing"
    ok = ku.digital_signature and ku.key_cert_sign and ku.crl_sign
    extras = []
    for name, val in (("nonRepudiation", ku.content_commitment),
                      ("keyEncipherment", ku.key_encipherment),
                      ("dataEncipherment", ku.data_encipherment),
                      ("keyAgreement", ku.key_agreement)):
        if val:
            extras.append(name)
    if not ok:
        return FAIL, f"missing required bits (ds={ku.digital_signature}, kcs={ku.key_cert_sign}, crls={ku.crl_sign})"
    return (PASS, "") if not extras else (FAIL, f"extras: {extras}")

def chk_le_int_eku(cert, der):
    ekus = _ekus(cert)
    if not ekus:
        return FAIL, "EKU absent"
    extra = set(ekus) - {ID_KP_SERVERAUTH, ID_KP_CLIENTAUTH}
    if ID_KP_SERVERAUTH not in ekus:
        return FAIL, "no serverAuth"
    return (PASS, ",".join(ekus)) if not extra else (FAIL, f"extras: {extra}")

# --- Date-conditional checks ---

import datetime

def _notbefore(cert):
    nb = cert.not_valid_before_utc
    if nb.tzinfo is None:
        nb = nb.replace(tzinfo=datetime.timezone.utc)
    return nb

def _utc(y, m, d):
    return datetime.datetime(y, m, d, tzinfo=datetime.timezone.utc)

def chk_eku_post_2026_06_15_serverauth_only(cert, der):
    """Chrome §1.3.2(1) post-2026-06-15 rule: applies only to certs disclosed to CCADB on/after 2026-06-15."""
    if _notbefore(cert) < _utc(2026, 6, 15):
        return NA, f"notBefore={_notbefore(cert).date()} < 2026-06-15"
    return chk_eku_only_serverauth(cert, der)

def chk_eku_pre_2026_06_15_serverauth_or_with_clientauth(cert, der):
    """Chrome §1.3.2(1) pre-2026-06-15 rule: applies only to certs disclosed before 2026-06-15."""
    if _notbefore(cert) >= _utc(2026, 6, 15):
        return NA, f"notBefore={_notbefore(cert).date()} >= 2026-06-15"
    return chk_eku_only_serverauth_or_with_clientauth(cert, der)

def chk_eku_applicant_post_2025_06_15_serverauth_only(cert, der):
    """Chrome §2.3(1) Applicant post-2025-06-15. LE is not an Applicant — N/A."""
    return NA, "LE is not an Applicant PKI hierarchy"

def chk_eku_applicant_pre_2025_06_15(cert, der):
    return NA, "LE is not an Applicant PKI hierarchy"

def _subject_org_is_root(cert):
    """Heuristic: an LE-context cert whose subject organization is 'Internet Security Research Group'
    or 'ISRG' is a root (as opposed to 'Let's Encrypt' for intermediates)."""
    org_attrs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    if not org_attrs:
        return False
    return org_attrs[0].value in ("Internet Security Research Group", "ISRG")

def chk_mozilla_post_2019_eku_present(cert, der):
    """Mozilla §5.3: applies only to intermediates created after 2019-01-01, with an exception for
    cross-certs that share a private key with a corresponding root certificate."""
    if _notbefore(cert) < _utc(2019, 1, 1):
        return NA, f"notBefore={_notbefore(cert).date()} < 2019-01-01 (grandfathered)"
    if _subject_org_is_root(cert):
        return NA, "subject is a root; Mozilla §5.3 cross-cert exception applies"
    return chk_eku_present(cert, der)

def chk_mozilla_post_2019_no_anyeku(cert, der):
    if _notbefore(cert) < _utc(2019, 1, 1):
        return NA, f"notBefore={_notbefore(cert).date()} < 2019-01-01"
    if _subject_org_is_root(cert):
        return NA, "Mozilla §5.3 cross-cert exception"
    return chk_eku_no_anyeku(cert, der)

def chk_mozilla_post_2019_no_serverauth_emailprot_both(cert, der):
    if _notbefore(cert) < _utc(2019, 1, 1):
        return NA, f"notBefore={_notbefore(cert).date()} < 2019-01-01"
    if _subject_org_is_root(cert):
        return NA, "Mozilla §5.3 cross-cert exception"
    ekus = _ekus(cert)
    if ID_KP_SERVERAUTH in ekus and ID_KP_EMAILPROT in ekus:
        return FAIL, "serverAuth+emailProtection in same cert"
    return PASS, ""

# --- LE root vs intermediate disambiguation ---

def chk_le_int_key_only_if_int_subject(cert, der):
    """The 'LE-issued cross-cert SPKI is RSA-2048 / P-384' rule applies to cross-certs that are
    functionally intermediates. Root cross-signs (subject is a root) don't have intermediate-class keys.
    """
    org_attrs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    if not org_attrs:
        return chk_le_int_key(cert, der)
    org = org_attrs[0].value
    # ISRG-organization subjects are roots, not intermediates
    if org in ("Internet Security Research Group", "ISRG"):
        return NA, "subject is a root (Internet Security Research Group / ISRG); rule applies to subordinates"
    return chk_le_int_key(cert, der)

# ---------- Corpus indexes (built at startup; used by chain-aware checks) ----------

def _spki_bytes(cert):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

CORPUS = []          # list of (path, cert, der)
SPKI_INDEX = {}      # spki_bytes -> [(path, cert, der), ...]
SUBJECT_INDEX = {}   # subject DN bytes -> [(path, cert, der), ...]
SELF_SIGNED_ROOTS_BY_SPKI = {}  # spki_bytes -> [(path, cert)] for certs with issuer==subject
INTERMEDIATES_UNDER = {}  # issuer DN bytes -> [(path, cert)] for non-self-signed certs

def build_corpus_index():
    """Walk the local LE cert corpus and build indexes for chain-aware checks."""
    global CORPUS, SPKI_INDEX, SUBJECT_INDEX, SELF_SIGNED_ROOTS_BY_SPKI, INTERMEDIATES_UNDER
    CORPUS = []
    SPKI_INDEX = {}
    SUBJECT_INDEX = {}
    SELF_SIGNED_ROOTS_BY_SPKI = {}
    INTERMEDIATES_UNDER = {}
    for d in ("roots", "cross-certs", "intermediates"):
        for f in sorted(glob.glob(os.path.join(LE_CERTS, d, "*.der"))):
            try:
                cert, der = load_cert(f)
            except Exception:
                continue
            entry = (os.path.basename(f), cert, der)
            CORPUS.append(entry)
            spki = _spki_bytes(cert)
            SPKI_INDEX.setdefault(spki, []).append(entry)
            subj = cert.subject.public_bytes()
            SUBJECT_INDEX.setdefault(subj, []).append(entry)
            if cert.issuer.public_bytes() == cert.subject.public_bytes():
                SELF_SIGNED_ROOTS_BY_SPKI.setdefault(spki, []).append(entry)
            else:
                INTERMEDIATES_UNDER.setdefault(cert.issuer.public_bytes(), []).append(entry)

def _find_issuer_candidates(cert):
    """Return [(path, cert)] of corpus entries whose Subject DN equals this cert's Issuer DN."""
    return SUBJECT_INDEX.get(cert.issuer.public_bytes(), [])

def _find_self_signed_root_with_matching_spki(cert):
    """Return [(path, cert)] of corpus self-signed roots whose SPKI matches this cert's SPKI."""
    return SELF_SIGNED_ROOTS_BY_SPKI.get(_spki_bytes(cert), [])

# ---------- Chain-aware checks ----------

def chk_issuer_dn_eq_parent_subject_dn(cert, der):
    """Issuer DN MUST be byte-for-byte identical to the issuing CA's Subject DN."""
    if cert.issuer.public_bytes() == cert.subject.public_bytes():
        return NA, "self-signed (root); covered by §1.4 root check"
    candidates = _find_issuer_candidates(cert)
    if not candidates:
        return MANUAL, "issuer not in LE corpus (probably externally-issued)"
    # By construction the candidate's subject DN bytes == this cert's issuer DN bytes
    parent_name, _, _ = candidates[0]
    return PASS, f"issuer matches subject of {parent_name}"

def chk_signature_verifies_under_parent(cert, der):
    """Cert signature MUST verify under the issuing CA's public key."""
    if cert.issuer.public_bytes() == cert.subject.public_bytes():
        return NA, "self-signed; covered by §1.4 root check"
    candidates = _find_issuer_candidates(cert)
    if not candidates:
        return MANUAL, "issuer not in LE corpus"
    from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
    last_err = None
    for path, parent, _ in candidates:
        try:
            pk = parent.public_key()
            if isinstance(pk, rsa.RSAPublicKey):
                pk.verify(cert.signature, cert.tbs_certificate_bytes, PKCS1v15(), cert.signature_hash_algorithm)
                return PASS, f"verified under {path}"
            if isinstance(pk, ec.EllipticCurvePublicKey):
                pk.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
                return PASS, f"verified under {path}"
        except Exception as e:
            last_err = e
    return FAIL, f"signature does not verify under any candidate issuer; last error: {last_err}"

def chk_aki_keyid_eq_parent_ski(cert, der):
    """AKI.keyIdentifier MUST equal the issuing CA's subjectKeyIdentifier."""
    aki = get_ext(cert, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    if not aki or aki.value.key_identifier is None:
        return MANUAL, "AKI or AKI.keyIdentifier absent"
    if cert.issuer.public_bytes() == cert.subject.public_bytes():
        return chk_aki_keyid_eq_ski_self(cert, der)
    candidates = _find_issuer_candidates(cert)
    if not candidates:
        return MANUAL, "issuer not in LE corpus"
    for path, parent, _ in candidates:
        ski = get_ext(parent, ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        if ski and ski.value.digest == aki.value.key_identifier:
            return PASS, f"matches SKI of {path}"
    return FAIL, "AKI.keyIdentifier does not match any candidate issuer's SKI"

# ---------- Cross-cert subject==existing-root checks ----------

def chk_xc_subject_eq_existing_root(cert, der):
    """For a cross-cert (subject DN re-binds an existing CA): the subject DN MUST be byte-for-byte
    identical to the existing CA cert's subject DN. We look for a self-signed root in the corpus
    with the same SPKI; its subject should match this cert's subject byte-for-byte."""
    if cert.issuer.public_bytes() == cert.subject.public_bytes():
        return NA, "self-signed; not a cross-cert"
    matches = _find_self_signed_root_with_matching_spki(cert)
    if not matches:
        return MANUAL, "no self-signed root in LE corpus shares this SPKI; cannot verify"
    for path, ref, _ in matches:
        if ref.subject.public_bytes() == cert.subject.public_bytes():
            return PASS, f"subject byte-identical to {path}"
    return FAIL, f"subject differs from self-signed root(s) sharing this SPKI: {[m[0] for m in matches]}"

def chk_xc_spki_eq_existing_root(cert, der):
    """Cross-cert SPKI MUST be byte-for-byte identical to existing CA's SPKI."""
    matches = _find_self_signed_root_with_matching_spki(cert)
    if cert.issuer.public_bytes() == cert.subject.public_bytes():
        return NA, "self-signed; not a cross-cert"
    if not matches:
        return MANUAL, "no self-signed root with matching SPKI in corpus"
    # By construction, SPKI matches (that's how we indexed). Sanity-check the byte equality:
    for path, ref, _ in matches:
        if _spki_bytes(ref) == _spki_bytes(cert):
            return PASS, f"SPKI byte-identical to {path}"
    return FAIL, "SPKI mismatch"  # unreachable in practice

# ---------- CCADB §6.3 (the headline check) ----------

# Effective date of CCADB §6.3 dedicated-EKU rule
CCADB_63_EFFECTIVE = datetime.datetime(2025, 6, 15, tzinfo=datetime.timezone.utc)

def _ccadb_63_applies(cert):
    """Returns (applies: bool, reason: str). The rule applies when:
    - cert was issued on/after 2025-06-15, AND
    - Subject CA's public key exists (or might exist) in a publicly-trusted self-signed Root CA
      whose hierarchy is dedicated to a specific PKI use case.
    For LE, we detect (b) by finding a self-signed root in the corpus with matching SPKI.
    """
    if _notbefore(cert) < CCADB_63_EFFECTIVE:
        return False, f"notBefore={_notbefore(cert).date()} < 2025-06-15"
    if cert.issuer.public_bytes() == cert.subject.public_bytes():
        return False, "self-signed; §6.3 is about cross-certs"
    matches = _find_self_signed_root_with_matching_spki(cert)
    if not matches:
        return False, "Subject CA pubkey not in any LE self-signed root in corpus"
    return True, f"Subject CA pubkey matches self-signed root(s): {[m[0] for m in matches]}"

def _le_hierarchy_dedication(cert):
    """Determine which §6.3 row applies, given the Subject CA's hierarchy.
    For LE: the gen-y hierarchies (Root YE, Root YR) and the X1/X2 hierarchies are all
    dedicated to TLS server authentication (their intermediates assert only id-kp-serverAuth
    in the gen-y case, and serverAuth+clientAuth in the X1/X2 case — both classifiable as
    'TLS server authentication' or 'TLS (generic)' respectively).
    We return the relevant row identifier.
    """
    # Find intermediates issued under the self-signed root sharing the Subject CA's SPKI
    matches = _find_self_signed_root_with_matching_spki(cert)
    if not matches:
        return None, "no self-signed root for Subject CA"
    # Look at the Subject's own SPKI (=root SPKI); find sub-CA certs issued by that root.
    # The root's Subject DN is the issuer DN of its subordinates.
    root_subject_bytes = matches[0][1].subject.public_bytes()
    subs = INTERMEDIATES_UNDER.get(root_subject_bytes, [])
    # Aggregate the EKUs of subordinates
    eku_set = set()
    for path, sub, _ in subs:
        for o in _ekus(sub):
            eku_set.add(o)
    if not eku_set:
        return None, "no subordinates with EKU found under this root"
    # Classify (heuristic for LE / TLS-dedicated hierarchies)
    if eku_set == {ID_KP_SERVERAUTH}:
        return "TLS server authentication", "subordinates assert only id-kp-serverAuth"
    if eku_set == {ID_KP_SERVERAUTH, ID_KP_CLIENTAUTH}:
        return "TLS (generic)", "subordinates assert serverAuth+clientAuth"
    if eku_set == {ID_KP_CLIENTAUTH}:
        return "TLS client authentication", "subordinates assert only id-kp-clientAuth"
    if eku_set == {ID_KP_EMAILPROT}:
        return "S/MIME", "subordinates assert only emailProtection"
    if eku_set == {ID_KP_EMAILPROT, ID_KP_CLIENTAUTH}:
        return "S/MIME (generic)", "subordinates assert emailProtection+clientAuth"
    return "unclassified", f"mixed EKUs: {sorted(eku_set)}"

_CCADB_63_EXPECTED_EKU = {
    "TLS server authentication": [ID_KP_SERVERAUTH],
    "TLS client authentication": [ID_KP_CLIENTAUTH],
    "TLS (generic)": [ID_KP_SERVERAUTH, ID_KP_CLIENTAUTH],
    "S/MIME": [ID_KP_EMAILPROT],
    "S/MIME (generic)": [ID_KP_EMAILPROT, ID_KP_CLIENTAUTH],
    "Code signing": [ID_KP_CODESIGNING],
}

def _ccadb_63_check_for_dedication(cert, der, target_dedication):
    """Generic CCADB §6.3 check; only triggers if the trigger conditions are met AND the
    determined hierarchy dedication matches `target_dedication`."""
    applies, why = _ccadb_63_applies(cert)
    if not applies:
        return NA, why
    dedication, ded_reason = _le_hierarchy_dedication(cert)
    if dedication != target_dedication:
        return NA, f"hierarchy classified as {dedication!r} ({ded_reason}), not {target_dedication!r}"
    expected = _CCADB_63_EXPECTED_EKU[target_dedication]
    ekus = _ekus(cert)
    if not ekus:
        return FAIL, f"EKU MUST be present (subject hierarchy is {target_dedication!r}); EKU is absent"
    if sorted(ekus) == sorted(expected):
        return PASS, f"EKU = {ekus}"
    return FAIL, f"EKU MUST be exactly {expected} (got: {ekus})"

def chk_ccadb_63_tls_server(cert, der):
    return _ccadb_63_check_for_dedication(cert, der, "TLS server authentication")

def chk_ccadb_63_tls_client(cert, der):
    return _ccadb_63_check_for_dedication(cert, der, "TLS client authentication")

def chk_ccadb_63_tls_generic(cert, der):
    return _ccadb_63_check_for_dedication(cert, der, "TLS (generic)")

def chk_ccadb_63_smime(cert, der):
    return _ccadb_63_check_for_dedication(cert, der, "S/MIME")

def chk_ccadb_63_smime_generic(cert, der):
    return _ccadb_63_check_for_dedication(cert, der, "S/MIME (generic)")

def chk_ccadb_63_code_signing(cert, der):
    return _ccadb_63_check_for_dedication(cert, der, "Code signing")

def chk_ccadb_63_ev(cert, der):
    """If both Issuer and Subject hierarchies are EV-capable, certificatePolicies MUST include 2.23.140.1.1."""
    if not _find_self_signed_root_with_matching_spki(cert):
        return NA, "Subject CA pubkey not in LE self-signed root corpus"
    # LE does not issue EV certificates; LE hierarchies are not EV-capable.
    return NA, "LE hierarchies are not EV-capable"

# ---------- Mozilla §7.5 cascade for post-2025-03-15 roots ----------

# Known LE root vintages: True if added to Mozilla Root Store after 2025-03-15.
# Conservative classification: roots whose self-signed certificate's notBefore is on/after 2025-03-15
# are "post-2025-03-15 Mozilla roots" for §7.5 cascade purposes.
MOZILLA_75_EFFECTIVE = datetime.datetime(2025, 3, 15, tzinfo=datetime.timezone.utc)

def _chain_root_in_corpus(cert):
    """Walk the chain (via issuer-subject matching against the LE corpus) and return the
    self-signed root cert at the top of the chain, or None if unknown."""
    visited = set()
    cur = cert
    while True:
        key = cur.subject.public_bytes()
        if key in visited:
            return None  # loop
        visited.add(key)
        if cur.issuer.public_bytes() == cur.subject.public_bytes():
            return cur  # self-signed root reached
        cands = _find_issuer_candidates(cur)
        if not cands:
            return None
        # Prefer self-signed if available among candidates
        cands_self = [c for c in cands if c[1].issuer.public_bytes() == c[1].subject.public_bytes()]
        if cands_self:
            return cands_self[0][1]
        cur = cands[0][1]

def chk_mozilla_75_1_subca_eku(cert, der):
    """Mozilla §7.5.1: subordinate CA and end-entity certificates issued under a post-2025-03-15
    Mozilla-trusted Root with the Websites trust bit MUST have EKU asserting only id-kp-serverAuth
    or both id-kp-serverAuth and id-kp-clientAuth."""
    root = _chain_root_in_corpus(cert)
    if root is None:
        return MANUAL, "could not determine chain root from LE corpus"
    if _notbefore(root) < MOZILLA_75_EFFECTIVE:
        return NA, f"chain root has notBefore={_notbefore(root).date()} < 2025-03-15 (rule does not apply)"
    ekus = _ekus(cert)
    if not ekus:
        return FAIL, "EKU MUST be present (under post-2025-03-15 Mozilla root)"
    if ID_KP_OCSPSIGNING in ekus:
        # OCSP-signing certs are excepted (separate rule)
        if ekus == [ID_KP_OCSPSIGNING]:
            return PASS, "OCSP-signing cert; EKU = only id-kp-OCSPSigning"
        return FAIL, f"OCSP-signing cert MUST have only id-kp-OCSPSigning (got: {ekus})"
    extra = set(ekus) - {ID_KP_SERVERAUTH, ID_KP_CLIENTAUTH}
    if ID_KP_SERVERAUTH not in ekus:
        return FAIL, f"no id-kp-serverAuth (got: {ekus})"
    return (PASS, ",".join(ekus)) if not extra else (FAIL, f"EKU MUST contain only serverAuth or serverAuth+clientAuth (extras: {extra})")

def chk_mozilla_75_2_smime_eku(cert, der):
    """Mozilla §7.5.2: under post-2025-03-15 root with email trust bit, EKU MUST contain id-kp-emailProtection."""
    return NA, "LE hierarchies do not have email trust bit; rule does not apply"

# ---------- Apple §2.1.3 cascade ----------

APPLE_213_EFFECTIVE = datetime.datetime(2024, 4, 15, tzinfo=datetime.timezone.utc)

def chk_apple_213_tls_subca_eku(cert, der):
    """Apple §2.1.3: for sub-CAs beneath a TLS-purpose Apple-trusted root for an applicant on/after
    2024-04-15, EKU MUST contain only id-kp-serverAuth, or only id-kp-serverAuth + id-kp-clientAuth.
    For LE we treat post-2024-04-15 roots in the corpus as Apple-applicable."""
    root = _chain_root_in_corpus(cert)
    if root is None:
        return MANUAL, "could not determine chain root"
    if _notbefore(root) < APPLE_213_EFFECTIVE:
        return NA, f"chain root has notBefore={_notbefore(root).date()} < 2024-04-15 (rule applies only to post-2024-04-15 applicants)"
    ekus = _ekus(cert)
    if not ekus:
        return FAIL, "EKU MUST be present under post-2024-04-15 Apple-trusted TLS root"
    extra = set(ekus) - {ID_KP_SERVERAUTH, ID_KP_CLIENTAUTH}
    if ID_KP_SERVERAUTH not in ekus:
        return FAIL, "no id-kp-serverAuth"
    return (PASS, ",".join(ekus)) if not extra else (FAIL, f"extras: {extra}")

def chk_apple_213_shared_key(cert, der):
    """Apple §2.1.3: sub-CA MUST NOT share its public key with any cert asserting EKU OIDs other
    than serverAuth/clientAuth (for TLS-purpose Apple roots, post-2024-04-15)."""
    root = _chain_root_in_corpus(cert)
    if root is None:
        return MANUAL, "could not determine chain root"
    if _notbefore(root) < APPLE_213_EFFECTIVE:
        return NA, f"chain root pre-2024-04-15"
    # Find any other cert in the corpus with the same SPKI
    same_spki = SPKI_INDEX.get(_spki_bytes(cert), [])
    forbidden = []
    for path, other, _ in same_spki:
        if path == os.path.basename:
            continue
        other_ekus = set(_ekus(other))
        extras = other_ekus - {ID_KP_SERVERAUTH, ID_KP_CLIENTAUTH}
        if extras:
            forbidden.append((path, extras))
    return (PASS, "no key-sharing with forbidden EKUs") if not forbidden else (FAIL, f"key-shared: {forbidden}")

# ---------- Microsoft §3.1.13 EKU separation (4-way) ----------

def chk_microsoft_3_1_13_separation(cert, der):
    """Microsoft §3.1.13: server-auth, S/MIME, code-signing, time-stamping MUST be separated."""
    ekus = set(_ekus(cert))
    if not ekus:
        return NA, "EKU absent; separation rule N/A"
    pairs = [
        (ID_KP_SERVERAUTH, "serverAuth"),
        (ID_KP_EMAILPROT, "emailProtection"),
        (ID_KP_CODESIGNING, "codeSigning"),
        (ID_KP_TIMESTAMPING, "timeStamping"),
    ]
    present = [name for oid, name in pairs if oid in ekus]
    if len(present) <= 1:
        return PASS, f"only {present}"
    return FAIL, f"combines: {present}"

# ---------- CA Key Usage composite forbidden-bits check ----------

def chk_ca_ku_forbidden_bits_absent(cert, der):
    """A CA cert's keyUsage MUST NOT assert nonRepudiation, keyEncipherment, dataEncipherment,
    keyAgreement, encipherOnly, decipherOnly."""
    ku = _ku(cert)
    if not ku:
        return MANUAL, "KU missing"
    bad = []
    if ku.content_commitment: bad.append("nonRepudiation")
    if ku.key_encipherment: bad.append("keyEncipherment")
    if ku.data_encipherment: bad.append("dataEncipherment")
    if ku.key_agreement: bad.append("keyAgreement")
    # encipher_only/decipher_only are only meaningful when key_agreement is True (and we already fail on that),
    # but check them anyway as belt-and-suspenders:
    if ku.key_agreement:
        if ku.encipher_only: bad.append("encipherOnly")
        if ku.decipher_only: bad.append("decipherOnly")
    return (PASS, "") if not bad else (FAIL, f"forbidden bits: {bad}")

# ---------- Subject attribute encoding ----------

def chk_country_printablestring(cert, der):
    """countryName attribute MUST use PrintableString."""
    for attr in cert.subject:
        if attr.oid == NameOID.COUNTRY_NAME:
            try:
                t = attr._type  # integer ASN.1 tag (PrintableString = 19)
                return (PASS, "") if t == 19 else (FAIL, f"countryName tag {t} (PrintableString=19)")
            except AttributeError:
                pass
            return MANUAL, "cannot inspect ASN.1 tag"
    return FAIL, "no countryName attribute"

# CABF §7.1.4.2 attribute ordering for CA certs and DV/IV/OV/EV subject profiles.
# Map OID -> ordering position. Lower numbers come first.
_CABF_ATTR_ORDER = {
    "0.9.2342.19200300.100.1.25": 0,  # domainComponent
    NameOID.COUNTRY_NAME.dotted_string: 1,
    NameOID.STATE_OR_PROVINCE_NAME.dotted_string: 2,
    NameOID.LOCALITY_NAME.dotted_string: 3,
    NameOID.POSTAL_CODE.dotted_string: 4,
    NameOID.STREET_ADDRESS.dotted_string: 5,
    NameOID.ORGANIZATION_NAME.dotted_string: 6,
    NameOID.SURNAME.dotted_string: 7,
    NameOID.GIVEN_NAME.dotted_string: 8,
    NameOID.ORGANIZATIONAL_UNIT_NAME.dotted_string: 9,
    NameOID.COMMON_NAME.dotted_string: 10,
    # Second-table attributes after commonName (EV-specific, no strict order):
    "2.5.4.15": 11,    # businessCategory
    "1.3.6.1.4.1.311.60.2.1.3": 12,    # jurisdictionCountry
    "1.3.6.1.4.1.311.60.2.1.2": 13,    # jurisdictionStateOrProvince
    "1.3.6.1.4.1.311.60.2.1.1": 14,    # jurisdictionLocality
    NameOID.SERIAL_NUMBER.dotted_string: 15,
    "2.5.4.97": 16,    # organizationIdentifier
}

def chk_subject_rdn_ordering(cert, der):
    """Each RelativeDistinguishedName must appear in the §7.1.4.2 order."""
    seen_orders = []
    for rdn in cert.subject.rdns:
        attrs = list(rdn)
        for attr in attrs:
            oid = attr.oid.dotted_string
            if oid not in _CABF_ATTR_ORDER:
                continue  # attr not in the ordered table; don't enforce
            seen_orders.append((oid, _CABF_ATTR_ORDER[oid]))
    last_pos = -1
    for oid, pos in seen_orders:
        if pos < last_pos:
            return FAIL, f"attribute {oid} appears out of §7.1.4.2 order"
        last_pos = pos
    return PASS, ""

def chk_subject_no_duplicate_atvs(cert, der):
    """Subject MUST NOT contain more than one instance of any given AttributeTypeAndValue
    (except domainComponent/streetAddress and CABF-explicit multi-instance attrs)."""
    counts = collections_counter()
    for rdn in cert.subject.rdns:
        for attr in rdn:
            counts[attr.oid.dotted_string] += 1
    allow_multi = {
        "0.9.2342.19200300.100.1.25",  # domainComponent
        NameOID.STREET_ADDRESS.dotted_string,
    }
    bad = [(o, c) for o, c in counts.items() if c > 1 and o not in allow_multi]
    return (PASS, "") if not bad else (FAIL, f"duplicate ATVs: {bad}")

def chk_each_rdn_one_atv(cert, der):
    """Each RDN MUST contain exactly one AttributeTypeAndValue."""
    bad = [(i, len(list(rdn))) for i, rdn in enumerate(cert.subject.rdns) if len(list(rdn)) != 1]
    return (PASS, "") if not bad else (FAIL, f"RDNs with !=1 ATVs: {bad}")

def collections_counter():
    import collections
    return collections.Counter()

# ---------- SKI computation per RFC 5280 §4.2.1.2 ----------

def chk_ski_rfc5280_method(cert, der):
    """SKI value SHOULD be derived per RFC 5280 §4.2.1.2 method (1): SHA-1 of the BIT STRING value
    (excluding the tag/length/unused-bits octet). We accept method (1) or method (2) (truncated
    SHA-1) and FAIL only if SKI matches neither."""
    import hashlib
    e = get_ext(cert, ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    if not e:
        return MANUAL, "SKI absent"
    # Extract the BIT STRING value of subjectPublicKey from the SPKI
    spki_der = _spki_bytes(cert)
    # SPKI := SEQUENCE { algorithm AlgID, subjectPublicKey BIT STRING }
    # Walk the outer SEQUENCE and locate the BIT STRING
    inner = _seq_content(spki_der)
    # skip AlgorithmIdentifier (SEQUENCE)
    _, sz, h = _parse_len(inner, 1)
    idx = 1 + h + sz
    # subjectPublicKey BIT STRING; tag 03
    if inner[idx] != 0x03:
        return ERROR, f"expected BIT STRING tag, got {inner[idx]:#x}"
    _, bs_sz, bs_h = _parse_len(inner, idx + 1)
    bs_content = inner[idx + 1 + bs_h : idx + 1 + bs_h + bs_sz]
    # The first content byte of a BIT STRING is the number of unused bits.
    # For RSA/ECDSA SPKI this is always 0, and the remaining bytes are what's hashed.
    pubkey_bits = bs_content[1:]
    method_1 = hashlib.sha1(pubkey_bits).digest()
    method_2 = b"\x40" + method_1[1:8]  # 0100 || lower 60 bits of SHA-1 → 8-byte
    method_2 = bytes([0x40 | (method_2[0] & 0x0F)]) + method_2[1:]
    ski = e.value.digest
    if ski == method_1:
        return PASS, "RFC 5280 method (1) SHA-1 of pubkey BIT STRING"
    if ski == method_2:
        return PASS, "RFC 5280 method (2) truncated SHA-1"
    return MANUAL, f"SKI uses a different derivation (RFC 5280 allows any consistent method)"

# --- Cross-cert specific ---

def chk_root_cross_subject_same_as_existing(cert, der):
    """Cross-signed root: subject DN MUST be byte-identical to the corresponding self-signed root.
    We can't check this without the reference cert; mark MANUAL.
    """
    return MANUAL, "needs reference root for comparison"

# --- ASN.1 validity ---

def chk_asn1_der_valid(cert, der):
    # If cryptography.x509 loaded the cert, DER is valid (probably). Approximate.
    return PASS, "loaded OK"

# --- Operational/manual ---

def chk_manual(reason="not byte-observable"):
    return lambda cert, der: (MANUAL, reason)

# ---------- Dispatch table ----------
# Maps a substring fingerprint of the requirement text → check function
# Order matters: first match wins. Be specific.

DISPATCH = [
    # ===== Context-conditional cascade rules — checked FIRST so they win over generic EKU patterns =====
    # Mozilla §7.5 cascade
    (r"sits beneath a Mozilla-trusted Root added.*with the email trust bit", chk_mozilla_75_2_smime_eku),
    (r"sits beneath a Mozilla-trusted Root added.*with the Websites trust bit", chk_mozilla_75_1_subca_eku),
    (r"delegated OCSP-signing certificate sitting beneath a post-2025-03-15 Mozilla-trusted Root", chk_mozilla_75_1_subca_eku),
    (r"OCSP-signing certificate.*beneath a post-2025-03-15 Mozilla-trusted Root", chk_mozilla_75_1_subca_eku),
    # Apple §2.1.3 cascade
    (r"sits beneath a TLS-purpose Apple-trusted Root", chk_apple_213_tls_subca_eku),
    (r"sits beneath an S/MIME-purpose Apple-trusted Root", chk_manual("LE has no S/MIME hierarchy")),
    (r"sits beneath a Client-Authentication-purpose Apple-trusted Root", chk_manual("LE has no client-auth-only hierarchy")),
    (r"sits beneath a Timestamping-purpose Apple-trusted Root", chk_manual("LE has no timestamping hierarchy")),
    (r"sits beneath any single-purpose Apple-trusted Root.*MUST NOT share its public key", chk_apple_213_shared_key),
    # CCADB §6.3 dedicated-EKU cascade (must match before generic EKU patterns)
    (r"Subject CA's public key exists or might exist in a publicly-trusted self-signed Root CA dedicated to TLS server authentication", chk_ccadb_63_tls_server),
    (r"Subject CA's public key exists or might exist in a publicly-trusted self-signed Root CA dedicated to TLS client authentication", chk_ccadb_63_tls_client),
    (r"Subject CA's public key exists or might exist in a publicly-trusted self-signed Root CA dedicated to TLS \(generic\)", chk_ccadb_63_tls_generic),
    (r"Subject CA's public key exists or might exist in a publicly-trusted self-signed Root CA dedicated to S/MIME \(generic\)", chk_ccadb_63_smime_generic),
    (r"Subject CA's public key exists or might exist in a publicly-trusted self-signed Root CA dedicated to S/MIME", chk_ccadb_63_smime),
    (r"Subject CA's public key exists or might exist in a publicly-trusted self-signed Root CA dedicated to Code Signing", chk_ccadb_63_code_signing),
    (r"both the Issuer and Subject hierarchies of the cross-certificate are capable of issuing Extended Validation \(EV\)", chk_ccadb_63_ev),
    # Chrome §1.3.2 dedicated TLS hierarchy EKU rules (date-conditional)
    (r"disclosed to CCADB on or after 2026-06-15.*`extKeyUsage` MUST contain only `id-kp-serverAuth`", chk_eku_post_2026_06_15_serverauth_only),
    (r"disclosed to CCADB before 2026-06-15.*`extKeyUsage` MUST contain only `id-kp-serverAuth`, or only `id-kp-serverAuth` and `id-kp-clientAuth`", chk_eku_pre_2026_06_15_serverauth_or_with_clientauth),
    (r"part of an Applicant PKI hierarchy", chk_eku_applicant_pre_2025_06_15),
    # Mozilla §5.3 (date-conditional)
    (r"If the (intermediate|cross-certificate) was created after 2019-01-01, it MUST contain an `extKeyUsage`", chk_mozilla_post_2019_eku_present),
    (r"If the (intermediate|cross-certificate) was created after 2019-01-01, the `extKeyUsage` extension MUST be present", chk_mozilla_post_2019_eku_present),
    (r"created after 2019-01-01.*`extKeyUsage` extension MUST NOT contain `anyExtendedKeyUsage`", chk_mozilla_post_2019_no_anyeku),
    (r"created after 2019-01-01.*`extKeyUsage` extension MUST NOT contain both `id-kp-serverAuth` and `id-kp-emailProtection`", chk_mozilla_post_2019_no_serverauth_emailprot_both),
    # Microsoft §3.1.13 separation (when it appears in the requirement text)
    (r"MUST NOT combine any two or more of Server Authentication", chk_microsoft_3_1_13_separation),
    (r"Issuing CA must not combine server authentication", chk_microsoft_3_1_13_separation),

    # ===== Generic rules =====
    # Version
    (r"`version`.*MUST be v3", chk_version_v3),
    (r"certificate.*version.*MUST be X\.509 v3", chk_version_v3),

    # Serial number
    (r"`serialNumber` MUST be greater than zero", chk_serial_positive),
    (r"`serialNumber` MUST be less than 2\^159", chk_serial_lt_2_159),
    (r"`serialNumber` MUST contain at least 64 bits", chk_serial_64bit),
    (r"`serialNumber` MUST be non-sequential", chk_serial_nonseq),
    (r"combination of `issuer` DN and `serialNumber` MUST be unique", chk_manual("requires cross-cert corpus")),
    (r"precertificate's `serialNumber` MUST be byte-for-byte identical", chk_manual("requires precert/final pair")),

    # Issuer
    (r"encoded `issuer` field MUST be byte-for-byte identical to the encoded `subject` field of the same certificate", chk_issuer_eq_subject),
    (r"signature MUST verify under the public key in its own `subjectPublicKeyInfo`", chk_self_signed),
    (r"encoded `issuer` field MUST be byte-for-byte identical to the encoded `subject` field of the issuing CA", chk_issuer_dn_eq_parent_subject_dn),
    (r"certificate's signature MUST verify under the issuing CA's public key", chk_signature_verifies_under_parent),
    (r"MUST NOT be issued directly by a root CA", chk_manual("needs chain")),

    # Signature in tbs vs outer
    (r"encoded value of the `tbsCertificate.signature` field MUST be byte-for-byte identical to the outer `signatureAlgorithm` field", chk_sig_outer_eq_tbs),
    (r"encoded value of `tbsCertificate.signature` MUST be byte-for-byte identical to the outer `signatureAlgorithm`", chk_sig_outer_eq_tbs),
    (r"outer `signatureAlgorithm` field MUST be byte-for-byte identical to the `tbsCertificate.signature` field", chk_sig_outer_eq_tbs),
    (r"outer `signatureAlgorithm` MUST be byte-for-byte identical to `tbsCertificate.signature`", chk_sig_outer_eq_tbs),
    (r"outer `signatureAlgorithm` field MUST be byte-for-byte identical to `tbsCertificate.signature`", chk_sig_outer_eq_tbs),

    # Validity (roots)
    (r"`notBefore` value MUST be no later than the time of signing", chk_manual("notBefore vs sign-time")),
    (r"`notBefore` value MUST be no earlier than one day prior to the time of signing", chk_manual("notBefore vs sign-time")),
    (r"difference `notAfter − notBefore` MUST be at least 2922 days", chk_root_validity_8_25_years),
    (r"difference `notAfter − notBefore` MUST be at most 9132 days", chk_root_validity_8_25_years),
    (r"validity-period rules in items 1\.5\.3–1\.5\.4 apply", chk_root_validity_8_25_years),
    # Cross / intermediate validity
    (r"`notBefore` value MUST be no later than the time of signing", chk_manual("notBefore vs sign-time")),
    (r"`notAfter` value MUST be no earlier than the time of signing", chk_manual("notAfter vs sign-time")),
    (r"validity period.*SHOULD be no more than 3 years", chk_subordinate_validity_max_3y),
    (r"validity period of at most 8 years", chk_le_sub_validity_max_8y),
    (r"validity period.*MUST be at most 8 years", chk_le_sub_validity_max_8y),
    (r"validity period is at most 8 years", chk_le_sub_validity_max_8y),
    (r"validity period.*MUST NOT exceed 398 days.*before 2026-03-15", chk_manual("leaf validity step-down")),

    # Subject
    (r"`subject` MUST contain a `countryName` attribute", chk_country_present),
    (r"`countryName` MUST be a two-letter ISO 3166-1", chk_country_not_xx),
    (r"`countryName` MUST NOT be `XX`", chk_country_not_xx),
    (r"`countryName` attribute, if present, MUST be encoded as `PrintableString`", chk_country_printablestring),
    (r"encoded as `PrintableString` whose value is a two-letter ISO 3166-1", chk_country_printablestring),
    (r"`subject` MUST contain an `organizationName` attribute", chk_org_present),
    (r"`subject` MUST contain a `commonName` attribute", chk_cn_present),
    (r"`subject` MUST NOT contain an `organizationalUnitName` attribute", chk_no_ou),
    (r"LE-operated root's `subject` MUST be", chk_le_root_subject),
    (r"LE-issued intermediate's `subject` MUST be", chk_le_int_subject),
    (r"subject` MUST be byte-for-byte identical across all certificates", chk_manual("requires corpus")),

    # SPKI algorithm
    (r"SPKI algorithm MUST be (one of )?RSA.*or ECDSA", chk_spki_rsa_or_ecdsa),
    (r"EdDSA.*public keys MUST NOT appear", chk_spki_no_eddsa),
    (r"Curve25519 and Curve448 public keys MUST NOT appear", chk_spki_no_curve25519_448),
    (r"If the SPKI is RSA, the encoded modulus MUST be at least 2048", chk_rsa_min_2048),
    (r"If the SPKI is RSA, the modulus size in bits MUST be evenly divisible by 8", chk_rsa_mod_div_by_8),
    (r"If the SPKI is RSA, the modulus MUST NOT be 1024 bits", chk_rsa_not_1024),
    (r"If the SPKI is RSA, the public exponent MUST be an odd integer", chk_rsa_exp_odd_ge_3),
    (r"If the SPKI is RSA, the public exponent SHOULD be in the range", chk_rsa_exp_range),
    (r"If the SPKI is RSA, the public exponent MUST NOT be 1", chk_rsa_exp_not_one),
    (r"If the SPKI is RSA, the encoded `AlgorithmIdentifier` MUST be byte-for-byte identical to the hex bytes `300d06092a864886f70d0101010500`", chk_rsa_algid_exact),
    (r"If the SPKI is RSA, the encoded `AlgorithmIdentifier` MUST be byte-for-byte identical to `300d06092a864886f70d0101010500`", chk_rsa_algid_exact),
    (r"If the SPKI is RSA, the algorithm OID MUST NOT be `id-RSASSA-PSS`", chk_rsa_no_pss_oid),
    (r"If the SPKI is RSA, the SPKI algorithm OID MUST NOT be `id-RSASSA-PSS`", chk_rsa_no_pss_oid),
    (r"If the SPKI is ECDSA, the key MUST lie on", chk_ecdsa_curve_allowed),
    (r"If the SPKI is ECDSA, the `AlgorithmIdentifier` parameters MUST use the `namedCurve` encoding", chk_ecdsa_namedcurve),
    (r"ECDSA SPKI MUST use `namedCurve` form", chk_ecdsa_namedcurve),
    (r"If the SPKI is ECDSA P-256, the encoded `AlgorithmIdentifier` MUST be byte-for-byte identical to `301306072a8648ce3d020106082a8648ce3d030107`", chk_ecdsa_algid_exact),
    (r"If the SPKI is ECDSA P-384, the encoded `AlgorithmIdentifier` MUST be byte-for-byte identical to `301006072a8648ce3d020106052b81040022`", chk_ecdsa_algid_exact),
    (r"If the SPKI is ECDSA P-521, the encoded `AlgorithmIdentifier` MUST be byte-for-byte identical to `301006072a8648ce3d020106052b81040023`", chk_ecdsa_algid_exact),
    (r"ECDSA SPKI `AlgorithmIdentifier` MUST match the prescribed hex encoding", chk_ecdsa_algid_exact),
    (r"ECDSA keys SHOULD be confirmed valid using ECC Full or Partial Public Key Validation", chk_manual("requires ECC validation routine")),
    (r"If the SPKI is RSA, the modulus MUST NOT correspond to a known weak key", chk_manual("requires weak-key DB")),
    (r"If the SPKI is RSA, the modulus MUST NOT yield a public exponent of 1", chk_rsa_exp_not_one),
    (r"LE-operated root MUST have an RSA-4096-bit-with-exponent-65537", chk_le_root_key),
    (r"LE-operated root has an RSA-4096-bit", chk_le_root_key),
    (r"LE-issued cross-certificate's SPKI MUST be RSA with a 2048-bit", chk_le_int_key_only_if_int_subject),
    (r"LE-issued cross-certificate's SPKI is RSA with a 2048-bit", chk_le_int_key_only_if_int_subject),
    (r"LE-issued intermediate's SPKI MUST be RSA-2048", chk_le_int_key),
    (r"LE-issued intermediate's SPKI is RSA", chk_le_int_key),

    # issuerUniqueID / subjectUniqueID
    (r"`issuerUniqueID` field MUST NOT be present", chk_issuer_uniqueid_absent),
    (r"`subjectUniqueID` field MUST NOT be present", chk_subject_uniqueid_absent),

    # Signature algorithm
    (r"signature algorithm MUST be one of:.*RSASSA-PKCS1-v1_5", chk_sig_algorithm_permitted),
    (r"signature hash function MUST be in the SHA-2 family", chk_sig_not_sha1),
    (r"signature hash function MUST be SHA-256, SHA-384, or SHA-512", chk_sig_not_sha1),
    (r"signature algorithm MUST NOT be MD5", chk_sig_not_md5),
    (r"signature algorithm MUST NOT use SHA-1", chk_sig_not_sha1),
    (r"signature algorithm MUST NOT be RSASSA-PKCS1-v1_5 with SHA-1", chk_sig_not_sha1),
    (r"Prior to 2026-09-15, the CA SHALL revoke", chk_manual("revocation policy, not cert content")),
    (r"narrow SHA-1 reissuance exception in CABF BR §7\.1\.3\.2\.1 expires 2026-09-15", chk_manual("informational")),
    (r"Effective 2026-09-15", chk_manual("future date")),
    (r"narrow same-key SHA-1 reissuance exception", chk_manual("informational")),
    (r"signature uses an RSASSA-PKCS1-v1_5 `AlgorithmIdentifier`, the parameters field MUST be explicit NULL", chk_manual("inspected via exact-hex check")),
    (r"signature uses RSASSA-PKCS1-v1_5 with SHA-256.*MUST be exactly `300d06092a864886f70d01010b0500`", chk_sigalgid_exact_encoding),
    (r"signature uses RSASSA-PKCS1-v1_5 with SHA-384.*MUST be exactly `300d06092a864886f70d01010c0500`", chk_sigalgid_exact_encoding),
    (r"signature uses RSASSA-PKCS1-v1_5 with SHA-512.*MUST be exactly `300d06092a864886f70d01010d0500`", chk_sigalgid_exact_encoding),
    (r"signature uses RSASSA-PSS", chk_manual("PSS encoding exact-hex; LE rarely uses")),
    (r"RSASSA-PSS `AlgorithmIdentifier` is used, the `trailerField` MUST be omitted", chk_manual("inspected if PSS")),
    (r"signing key is ECDSA P-256, the signature algorithm MUST be ECDSA with SHA-256", chk_sigalgid_exact_encoding),
    (r"signing key is ECDSA P-384, the signature algorithm MUST be ECDSA with SHA-384", chk_sigalgid_exact_encoding),
    (r"signing key is ECDSA P-521, the signature algorithm MUST be ECDSA with SHA-512", chk_sigalgid_exact_encoding),
    (r"ECDSA signature `AlgorithmIdentifier` MUST omit the parameters field", chk_sigalgid_exact_encoding),
    (r"ECDSA signature `AlgorithmIdentifier`s MUST omit the parameters field", chk_sigalgid_exact_encoding),

    (r"AlgorithmIdentifier.*explicit NULL on PKCS#1", chk_manual("inspected via exact-hex")),
    (r"signature `AlgorithmIdentifier` MUST be one of the encodings permitted by CABF BR §7\.1\.3\.2", chk_sig_algorithm_permitted),
    (r"signing key is ECDSA, the signature hash MUST match the curve", chk_sigalgid_exact_encoding),
    (r"exact `AlgorithmIdentifier` byte encodings for each algorithm/hash combination MUST match CABF BR §7\.1\.3\.2", chk_sigalgid_exact_encoding),
    (r"Mozilla bans SHA-1", chk_sig_not_sha1),
    (r"Mozilla bans SHA-1 on CT precertificates", chk_manual("precert-only")),
    (r"Encoding rules for the `AlgorithmIdentifier`", chk_manual("composite rule")),

    # Basic constraints
    (r"`basicConstraints` extension MUST be present", chk_basic_constraints_present),
    (r"`basicConstraints` extension MUST be marked critical", chk_basic_constraints_critical),
    (r"`cA` boolean MUST be set to TRUE", chk_basic_constraints_ca_true),
    (r"`cA` boolean MUST be TRUE", chk_basic_constraints_ca_true),
    (r"`pathLenConstraint` field is NOT RECOMMENDED", chk_manual("NOT RECOMMENDED")),
    (r"`pathLenConstraint` field SHOULD NOT be present", chk_manual("SHOULD NOT")),
    (r"`pathLenConstraint` field MAY be present", chk_manual("MAY")),
    (r"LE-issued intermediate MUST have `pathLenConstraint = 0`", chk_basic_constraints_pathlen_zero),

    # Key usage
    (r"`keyUsage` extension MUST be present", chk_ku_present),
    (r"`keyUsage` extension MUST be marked critical", chk_ku_critical),
    (r"`keyCertSign` bit MUST be asserted", chk_ku_keycertsign),
    (r"`cRLSign` bit MUST be asserted", chk_ku_crlsign),
    (r"`nonRepudiation`, `keyEncipherment`, `dataEncipherment`, `keyAgreement`, `encipherOnly`, and `decipherOnly` bits MUST NOT be asserted", chk_ca_ku_forbidden_bits_absent),
    (r"OCSP responses, the `digitalSignature` bit MUST be asserted", chk_manual("OCSP-conditional")),
    (r"LE-issued intermediate's `keyUsage` MUST assert `digitalSignature`, `keyCertSign`, and `cRLSign`, and nothing else", chk_le_int_ku),

    # SKI
    (r"`subjectKeyIdentifier` extension MUST be present", chk_ski_present),
    (r"`subjectKeyIdentifier` extension MUST NOT be marked critical", chk_ski_noncritical),
    (r"`subjectKeyIdentifier` value MUST be set as defined in RFC 5280", chk_ski_rfc5280_method),
    (r"`subjectKeyIdentifier` value MUST be set per RFC 5280", chk_ski_rfc5280_method),

    # AKI — order matters: longer patterns first
    (r"If present, the `authorityKeyIdentifier` extension MUST NOT be marked critical", chk_aki_noncritical),
    (r"`authorityKeyIdentifier` MUST NOT be marked critical", chk_aki_noncritical),
    (r"`keyIdentifier` field MUST be present and MUST equal the certificate's `subjectKeyIdentifier`", chk_aki_keyid_eq_ski_self),
    (r"`keyIdentifier` field MUST be present and MUST equal the issuing CA's `subjectKeyIdentifier`", chk_aki_keyid_eq_parent_ski),
    (r"If present, the `keyIdentifier` field MUST be present", chk_aki_keyid_present_if_aki_present),
    (r"`keyIdentifier` field MUST be present", chk_aki_keyid_present),
    (r"`authorityKeyIdentifier` extension MUST be present", chk_aki_present),
    (r"`authorityCertIssuer` field MUST NOT be present", chk_aki_no_issuer_serial),
    (r"`authorityCertSerialNumber` field MUST NOT be present", chk_aki_no_issuer_serial),

    # EKU — order matters: more specific patterns first
    (r"`extKeyUsage` extension MUST NOT be present", chk_eku_absent),
    (r"`extKeyUsage` extension MUST be marked non-critical when present", chk_eku_noncritical_if_present),
    (r"`extKeyUsage` MUST be marked non-critical when present", chk_eku_noncritical_if_present),
    (r"`extKeyUsage` extension MUST NOT be marked critical", chk_eku_noncritical_if_present),
    # Date-conditional rules (before generic patterns)
    (r"If the (intermediate|cross-certificate) was created after 2019-01-01, it MUST contain an `extKeyUsage`", chk_mozilla_post_2019_eku_present),
    (r"If the (intermediate|cross-certificate) was created after 2019-01-01, the `extKeyUsage` extension MUST be present", chk_mozilla_post_2019_eku_present),
    (r"If the intermediate was created after 2019-01-01.*extKeyUsage.*MUST NOT contain `anyExtendedKeyUsage`", chk_mozilla_post_2019_no_anyeku),
    (r"created after 2019-01-01, the `extKeyUsage` extension MUST NOT contain `anyExtendedKeyUsage`", chk_mozilla_post_2019_no_anyeku),
    (r"created after 2019-01-01, the `extKeyUsage` extension MUST NOT contain both `id-kp-serverAuth` and `id-kp-emailProtection`", chk_mozilla_post_2019_no_serverauth_emailprot_both),
    (r"disclosed to CCADB on or after 2026-06-15.*`extKeyUsage` MUST contain only `id-kp-serverAuth`", chk_eku_post_2026_06_15_serverauth_only),
    (r"disclosed to CCADB before 2026-06-15.*`extKeyUsage` MUST contain only `id-kp-serverAuth`, or only `id-kp-serverAuth` and `id-kp-clientAuth`", chk_eku_pre_2026_06_15_serverauth_or_with_clientauth),
    (r"part of an Applicant PKI hierarchy and was disclosed to CCADB before 2025-06-15", chk_eku_applicant_pre_2025_06_15),
    (r"part of an Applicant PKI hierarchy and was disclosed to CCADB on or after 2025-06-15", chk_eku_applicant_post_2025_06_15_serverauth_only),
    (r"part of an Applicant PKI hierarchy disclosed to CCADB before 2025-06-15", chk_eku_applicant_pre_2025_06_15),
    (r"part of an Applicant PKI hierarchy disclosed to CCADB on or after 2025-06-15", chk_eku_applicant_post_2025_06_15_serverauth_only),
    (r"part of an Applicant PKI hierarchy", chk_eku_applicant_pre_2025_06_15),
    (r"`extKeyUsage` extension MUST be present", chk_eku_present),
    # NB: order — list "only serverAuth, or … and clientAuth" BEFORE "only serverAuth"
    (r"`extKeyUsage` MUST contain only `id-kp-serverAuth`, or only `id-kp-serverAuth` and `id-kp-clientAuth`", chk_eku_only_serverauth_or_with_clientauth),
    (r"`extKeyUsage` MUST contain only `id-kp-serverAuth`, or both `id-kp-serverAuth` and `id-kp-clientAuth`", chk_eku_only_serverauth_or_with_clientauth),
    (r"`extKeyUsage` MUST contain only `id-kp-serverAuth`\.", chk_eku_only_serverauth),
    (r"MUST contain only `id-kp-serverAuth`$", chk_eku_only_serverauth),
    (r"`extKeyUsage` MUST contain `id-kp-serverAuth`", chk_eku_has_serverauth),
    (r"`extKeyUsage` MAY contain `id-kp-clientAuth`", chk_manual("MAY")),
    (r"`extKeyUsage` MUST NOT contain `id-kp-codeSigning`", chk_eku_no_codesigning),
    (r"`extKeyUsage` MUST NOT contain `id-kp-emailProtection`", chk_eku_no_emailprot),
    (r"`extKeyUsage` MUST NOT contain `id-kp-timeStamping`", chk_eku_no_timestamping),
    (r"`extKeyUsage` MUST NOT contain `id-kp-OCSPSigning`", chk_eku_no_ocspsigning),
    (r"`extKeyUsage` MUST NOT contain `anyExtendedKeyUsage`", chk_eku_no_anyeku),
    (r"`extKeyUsage` MUST NOT contain the Precertificate Signing Certificate OID", chk_eku_no_precert_signing),
    (r"`extKeyUsage` MUST NOT contain the Precertificate Signing OID", chk_eku_no_precert_signing),
    (r"LE-issued intermediate's `extKeyUsage` MUST contain `id-kp-serverAuth`", chk_le_int_eku),
    (r"LE-issued intermediate's `extKeyUsage` MUST contain", chk_le_int_eku),

    # Certificate policies
    (r"`certificatePolicies` extension MUST be present", chk_certpolicies_present),
    (r"`certificatePolicies` extension MUST NOT be marked critical", chk_certpolicies_noncritical),
    (r"`certificatePolicies` extension is NOT RECOMMENDED in a root", chk_certpolicies_absent_or_not_recommended),
    (r"`certificatePolicies` extension MUST contain at most 2 distinct `policyIdentifier` values", chk_certpolicies_max_2_oids),
    (r"`certificatePolicies` extension MUST contain at least one CABF Reserved", chk_certpolicies_contains_cabf_reserved),
    (r"extension MUST contain exactly one CABF Reserved", chk_certpolicies_contains_cabf_reserved),
    (r"`anyPolicy` MUST NOT be present", chk_certpolicies_no_anypolicy),
    (r"LE-issued intermediate's `certificatePolicies` MUST assert `2\.23\.140\.1\.2\.1`", chk_certpolicies_contains_le_dv),

    # CRL DP
    (r"`cRLDistributionPoints` extension MUST be present", chk_crldp_present),
    (r"`cRLDistributionPoints` extension MUST NOT be marked critical", chk_crldp_noncritical),
    (r"`cRLDistributionPoints` extension SHOULD NOT be present in a root", chk_crldp_absent_or_not_recommended),
    (r"every `GeneralName` MUST be `uniformResourceIdentifier`.*every URI scheme MUST be `http`", chk_crldp_http_only),
    (r"every URI scheme MUST be `http`", chk_crldp_http_only),
    (r"first `GeneralName` MUST be the HTTP URL", chk_crldp_first_is_http),
    (r"URL in `cRLDistributionPoints` MUST match exactly the URL disclosed in CCADB", chk_manual("requires CCADB cross-check")),
    (r"MUST NOT point to a non-operational CRL service", chk_manual("operational")),
    (r"MUST NOT include `cRLDistributionPoints` URIs that point to a CRL service that does not exist", chk_manual("operational")),

    # AIA
    (r"`authorityInformationAccess` extension SHOULD be present", chk_aia_present),
    (r"`authorityInformationAccess` extension MUST be present", chk_aia_present),
    (r"`authorityInformationAccess` extension MUST NOT be marked critical", chk_aia_noncritical),
    (r"If present, the extension MUST NOT be marked critical", chk_aia_noncritical),
    (r"If the `authorityInformationAccess` extension is present, it MUST NOT be marked critical", chk_aia_noncritical),
    (r"each `AccessDescription` MUST have an `accessMethod` of `id-ad-ocsp`", chk_aia_methods_allowed),
    (r"`id-ad-caIssuers` `AccessDescription` SHOULD be present", chk_aia_caissuers_present),
    (r"OCSP URL appears in AIA, it MUST point to an operational OCSP responder", chk_manual("operational")),
    (r"OCSP URL appears in AIA, that URL MUST point to an operational OCSP responder", chk_manual("operational")),
    (r"LE-issued intermediate's AIA MUST contain a `caIssuers` URL", chk_aia_caissuers_present),
    (r"intermediate MUST contain at least one of: a `cRLDistributionPoints`", chk_manual("composite: CRLDP OR AIA-OCSP")),
    (r"cross-certificate MUST contain at least one of:", chk_manual("composite: CRLDP OR AIA-OCSP")),
    (r"No `accessMethod` other than `id-ad-ocsp` or `id-ad-caIssuers` is permitted", chk_aia_methods_allowed),
    (r"No `accessMethod` other than `id-ad-ocsp` or `id-ad-caIssuers` MUST appear", chk_aia_methods_allowed),

    # Name constraints
    (r"`nameConstraints` extension MUST NOT be present", chk_nameconstraints_absent),
    (r"`nameConstraints` extension MUST be present", chk_manual("TC TLS sub-CA only")),
    (r"`nameConstraints` extension SHOULD be marked critical", chk_manual("if present")),
    (r"`nameConstraints` extension is NOT RECOMMENDED", chk_manual("NOT RECOMMENDED")),
    (r"`permittedSubtrees` MUST contain at least one", chk_manual("TC sub-CA")),
    (r"`permittedSubtrees`/`excludedSubtrees`", chk_manual("NC structure")),
    (r"If present on a generic TLS Sub-CA", chk_manual("NC structure")),
    (r"only `dNSName`, `iPAddress`, and `directoryName`", chk_manual("NC structure")),
    (r"`dNSName`, `iPAddress`, and `directoryName`.*MAY", chk_manual("NC structure")),
    (r"`GeneralSubtree` MUST omit", chk_manual("NC structure")),
    (r"every `GeneralSubtree` MUST omit `minimum`", chk_manual("NC structure")),
    (r"`excludedSubtrees` MUST include", chk_manual("NC structure")),

    # SCT
    (r"SCT List extension MUST NOT be marked critical", chk_manual("if present")),
    (r"SCT List extension MUST NOT be present", chk_manual("precert only")),
    (r"`extnValue` MUST be an `OCTET STRING` containing a `SignedCertificateTimestampList`", chk_manual("SCT format")),
    (r"`SignedCertificateTimestamp` in the SCT List MUST be for a `PreCert`", chk_manual("SCT format")),

    # Subject alternative name (leaf)
    (r"`subjectAltName` extension MUST be present", chk_san_present),
    (r"`subjectAltName` extension MUST contain at least one `dNSName` or `iPAddress`", chk_manual("SAN content")),
    (r"`subjectAltName` extension MUST be marked critical if", chk_manual("subject-empty case")),
    (r"`subjectAltName` extension MUST NOT be marked critical if", chk_manual("subject-empty case")),

    # Precertificate
    (r"Precertificate Poison extension.*MUST be present", chk_manual("precert only")),
    (r"poison extension's presence", chk_manual("precert only")),

    # Cross-cert specific
    (r"existing CA certificate.*was issued in compliance with the then-current Baseline Requirements", chk_manual("issuance compliance")),
    (r"existing CA certificate.*is subject to the Baseline Requirements", chk_manual("issuance compliance")),
    (r"cross-certificate's `subject` DN MUST be byte-for-byte identical to the encoded `subject` of the existing CA", chk_xc_subject_eq_existing_root),
    (r"cross-certificate's `subjectPublicKeyInfo` MUST be byte-for-byte identical to that of the existing CA", chk_xc_spki_eq_existing_root),
    (r"pre-existing `subject` DN it copies", chk_manual("requires reference cert")),
    (r"If the existing CA certificate did not comply", chk_manual("issuance compliance")),
    (r"existing certificate was a Root CA", chk_xc_subject_eq_existing_root),

    # Root-program lifecycle
    (r"CA key material associated with the root MUST NOT be older than 15 years", chk_manual("key age — manual")),
    (r"root whose key was generated between", chk_manual("key generation date")),
    (r"applicant root submitted for inclusion to the Chrome Root Store", chk_manual("applicant-only")),
    (r"Mozilla will (remove|set)", chk_manual("trust-store policy")),
    (r"root added to Mozilla's Root Store after 2025-03-15", chk_manual("post-2025 root")),
    (r"root added to a Chrome PKI hierarchy after 2022-09-01", chk_manual("post-2022 root")),
    (r"newly-minted Microsoft Code-Signing or Time-Stamping root", chk_manual("not TLS")),
    (r"root used as a Microsoft Trusted Root", chk_manual("operational")),
    (r"applies even when reissuing", chk_manual("reissuance")),

    # Operational / out-of-scope
    (r"NOT RECOMMENDED", chk_manual("NOT RECOMMENDED")),
    (r"SHOULD NOT", chk_manual("SHOULD NOT")),
    (r"NOT RECOMMENDED;", chk_manual("NOT RECOMMENDED")),
    (r"MAY be present", chk_manual("MAY")),
    (r"MAY be omitted", chk_manual("MAY")),
    (r"MAY appear", chk_manual("MAY")),
    (r"MAY contain", chk_manual("MAY")),
    (r"MAY use the `namedCurve`", chk_manual("MAY")),
    (r"`policyQualifiers`", chk_manual("policy qualifiers")),
    (r"OCSP Responder Certificate Profile", chk_manual("not for this profile")),
    (r"`subjectAltName` extension is NOT RECOMMENDED", chk_manual("NOT RECOMMENDED")),
    (r"Any extension not listed above is NOT RECOMMENDED", chk_manual("NOT RECOMMENDED")),
    (r"Any extension present MUST be DER-encoded", chk_asn1_der_valid),
    (r"Any extension present MUST apply in the context of the public Internet", chk_manual("subjective")),
    (r"Any extension present MUST NOT include semantics that mislead", chk_manual("subjective")),
    (r"certificate MUST be valid ASN\.1 DER", chk_asn1_der_valid),
    (r"Each `Name` MUST contain an `RDNSequence`", chk_asn1_der_valid),
    (r"Each `RelativeDistinguishedName` MUST contain exactly one `AttributeTypeAndValue`", chk_each_rdn_one_atv),
    (r"`RDNSequence` MUST order attributes", chk_subject_rdn_ordering),
    (r"`subject` MUST NOT contain more than one instance", chk_subject_no_duplicate_atvs),

    # Mozilla §7.5 cascade
    (r"Mozilla-trusted Root added.*with the email trust bit", chk_mozilla_75_2_smime_eku),
    (r"Mozilla-trusted Root added to the Mozilla Root Store after 2025-03-15 with the Websites trust bit", chk_mozilla_75_1_subca_eku),
    (r"Mozilla-trusted Root added after 2025-03-15 with the Websites trust bit", chk_mozilla_75_1_subca_eku),
    (r"OCSP-signing certificate sitting beneath a post-2025-03-15 Mozilla-trusted Root", chk_mozilla_75_1_subca_eku),
    (r"sits beneath a Mozilla-trusted Root added", chk_mozilla_75_1_subca_eku),
    # Apple §2.1.3 cascade
    (r"sits beneath a TLS-purpose Apple-trusted Root", chk_apple_213_tls_subca_eku),
    (r"MUST NOT share its public key with any other certificate asserting any EKU OID", chk_apple_213_shared_key),
    (r"sits beneath an S/MIME-purpose Apple-trusted Root", chk_manual("LE has no S/MIME hierarchy")),
    (r"sits beneath a Client-Authentication-purpose Apple-trusted Root", chk_manual("LE has no client-auth-only hierarchy")),
    (r"sits beneath a Timestamping-purpose Apple-trusted Root", chk_manual("LE has no timestamping hierarchy")),
    (r"sits beneath any single-purpose Apple-trusted Root", chk_apple_213_shared_key),
    (r"applicant on or after 2024-04-15", chk_apple_213_tls_subca_eku),
    # Chrome dedicated TLS hierarchy
    (r"operates beneath a Chrome Root Store root", chk_manual("Chrome hierarchy")),
    (r"Applicant PKI hierarchy", chk_manual("Applicant hierarchy")),
    # CCADB §6.3 (automated; per dedication row)
    (r"Subject CA's public key exists or might exist in a publicly-trusted self-signed Root CA dedicated to TLS server authentication", chk_ccadb_63_tls_server),
    (r"Subject CA's public key exists or might exist in a publicly-trusted self-signed Root CA dedicated to TLS client authentication", chk_ccadb_63_tls_client),
    (r"Subject CA's public key exists or might exist in a publicly-trusted self-signed Root CA dedicated to TLS \(generic\)", chk_ccadb_63_tls_generic),
    (r"Subject CA's public key exists or might exist in a publicly-trusted self-signed Root CA dedicated to S/MIME \(generic\)", chk_ccadb_63_smime_generic),
    (r"Subject CA's public key exists or might exist in a publicly-trusted self-signed Root CA dedicated to S/MIME", chk_ccadb_63_smime),
    (r"Subject CA's public key exists or might exist in a publicly-trusted self-signed Root CA dedicated to Code Signing", chk_ccadb_63_code_signing),
    (r"both the Issuer and Subject hierarchies of the cross-certificate are capable of issuing Extended Validation \(EV\)", chk_ccadb_63_ev),
    # Mozilla §5.3 exception
    (r"cross-certificate that shares its private key with a corresponding root", chk_manual("cross-cert exception")),
    (r"intermediate was created after 2019-01-01", chk_manual("post-2019 rule")),
    (r"shares its private key with a corresponding root certificate is exempt", chk_manual("exception")),
    # Microsoft separation
    (r"Microsoft will only enable the following EKUs", chk_manual("informational")),
    (r"Issuing CA must not combine server authentication", chk_microsoft_3_1_13_separation),
    (r"MUST NOT combine any two or more of Server Authentication", chk_microsoft_3_1_13_separation),
    # CABF unrestricted/restricted EKU
    (r"`extKeyUsage` extension MAY be \"unrestricted\"", chk_manual("affiliation-dependent")),
    (r"`extKeyUsage` extension MUST be \"restricted\"", chk_manual("affiliation-dependent")),
    (r"subordinate hierarchy issues TLS certificates", chk_manual("hierarchy-dependent")),
    (r"subordinate hierarchy does not issue TLS certificates", chk_manual("hierarchy-dependent")),
    (r"key-purpose OID included MUST apply in the context of the public Internet", chk_manual("subjective")),
    (r"key-purpose OID included MUST be one the issuing CA has verified", chk_manual("issuance")),
    (r"CA MUST NOT include a key-purpose OID unless", chk_manual("issuance")),

    # Misc
    (r"This Certificate Profile MUST NOT be used", chk_manual("Precert Signing CA sunset")),
    (r"Precertificate Signing CAs MUST NOT be used", chk_manual("Precert Signing CA sunset")),

    # Audit-scope / out of scope for byte check
    (r"in-scope for full WebTrust/ETSI TLS audit", chk_manual("audit scope")),
    (r"Technically Constrained Non-TLS", chk_manual("audit scope")),

    # CRL profile rules (intermediate/cross only)
    (r"CRL MUST be X\.509 v2", chk_manual("CRL profile")),
    (r"CRL MUST be signed using one of the algorithms", chk_manual("CRL profile")),
    (r"CRL MUST contain", chk_manual("CRL profile")),
    (r"CRL `nextUpdate`", chk_manual("CRL profile")),
    (r"CRL's `IssuingDistributionPoint`", chk_manual("CRL profile")),
    (r"CRL's scope does not include all unexpired certificates", chk_manual("CRL profile")),
    (r"CRL's `issuer` MUST be byte-for-byte identical", chk_manual("CRL profile")),
    (r"Each revocation entry for a revoked subordinate CA certificate MUST include a `reasonCode`", chk_manual("CRL entry")),
    (r"Apple-mandated CRL shape", chk_manual("CRL profile")),
    (r"CCADB record uses a single Full CRL URL", chk_manual("CRL profile")),
    (r"CCADB partitioned-CRL rule", chk_manual("CRL profile")),

    # CCADB §6.2 URL match
    (r"URL in `cRLDistributionPoints` MUST match exactly", chk_manual("CCADB cross-check")),
    # Validation freshness (issuance)
    (r"revalidated within \d+ days", chk_manual("validation freshness")),
    (r"validated via a method in CABF BR §3\.2\.2\.4", chk_manual("validation freshness")),
    (r"validated for consistency with CABF BR §3\.2\.2\.6", chk_manual("wildcard validation")),
    (r"domain/IP validation reuse window", chk_manual("validation freshness")),
    (r"non-DNS/IP subscriber.* reuse window", chk_manual("validation freshness")),
    (r"non-DNS/IP subscriber-info reuse window", chk_manual("validation freshness")),

    # Chrome CT
    (r"final certificate MUST NOT be issued unless its corresponding precertificate has been logged", chk_manual("precert logging policy")),
    (r"SHOULD be logged to at least one Chrome-Usable", chk_manual("CT logging policy")),
    # Chrome ACME/ARI
    (r"support ACME Renewal Information", chk_manual("CA-level policy")),
    (r"Automation Test Certificate MUST be renewed", chk_manual("operational")),

    # Out-of-scope-intermediate signaling (Mozilla scope)
    (r"intermediate is treated as out of scope", chk_manual("scope test")),

    # Subscriber profile (leaf-only — not in scope for roots/cross/intermediate CSVs)
    (r"basicConstraints` extension MAY be present", chk_manual("leaf basicConstraints")),
    (r"`basicConstraints` extension MUST be marked critical.*If present", chk_manual("leaf basicConstraints")),
    (r"`cA` boolean MUST be FALSE", chk_manual("leaf")),
    (r"`pathLenConstraint` field MUST NOT be present", chk_basic_constraints_pathlen_absent),

    # Generic catch-alls for citations
    (r"`organizationName` attribute.*MUST contain", chk_manual("OV subject content")),
    (r"`stateOrProvinceName`, `localityName`, `postalCode`, `streetAddress`", chk_manual("optional attrs")),
    (r"`organizationName` attribute, if present, MUST be encoded", chk_manual("OV encoding")),
    (r"`jurisdictionCountry` attribute", chk_manual("EV-only")),
    (r"`serialNumber` \(OID 2\.5\.4\.5\) attribute", chk_manual("EV-only")),
    (r"`organizationIdentifier` attribute", chk_manual("EV-only")),
    (r"Any attribute present in `subject` MUST have its content verified", chk_manual("operational")),
    (r"Wildcard Domain Names MUST be validated", chk_manual("wildcard validation")),

    (r"first `PolicyInformation` SHOULD", chk_manual("SHOULD ordering")),
    (r"Additional CA-defined `policyIdentifier`", chk_manual("CA-defined OIDs")),
    (r"LE-issued subscriber certificate", chk_manual("leaf-only")),
    (r"LE-issued precertificate", chk_manual("precert-only")),

    # Validity step-downs (leaf only)
    (r"validity period.*MUST NOT exceed 200 days", chk_manual("leaf step-down")),
    (r"validity period.*MUST NOT exceed 100 days", chk_manual("leaf step-down")),
    (r"validity period.*MUST NOT exceed 47 days", chk_manual("leaf step-down")),
    (r"SHOULD NOT thresholds", chk_manual("leaf step-down")),
    (r"day MUST be treated as exactly 86,400 seconds", chk_manual("leaf validity")),
    (r"validity-period calculation", chk_manual("leaf validity")),
    (r"Short-lived Subscriber Certificate", chk_manual("leaf short-lived")),

    # Generic SHOULD/MAY
    (r" SHOULD ", chk_manual("SHOULD (advisory)")),
]

# Precompile patterns
DISPATCH_C = [(re.compile(pat), fn) for (pat, fn) in DISPATCH]

def dispatch(text):
    for pat, fn in DISPATCH_C:
        if pat.search(text):
            return fn
    return None

# ---------- Markdown parsing ----------

# Match a numbered statement at start of a line: "1. text..."
ITEM_RE = re.compile(r"^(\d+)\.\s+(.+?)$", re.MULTILINE)
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)$", re.MULTILINE)

def parse_md(path):
    """Yield (section_label, item_number, text) for each numbered statement."""
    text = open(path).read()
    # Walk by tokenizing lines, tracking the current heading path
    section_stack = []
    current_label = ""
    out = []
    in_codeblock = False
    last_item_lines = []  # for handling multi-line continuations: but our doc has 1-line items mostly
    for line in text.splitlines():
        if line.startswith("```"):
            in_codeblock = not in_codeblock
            continue
        if in_codeblock:
            continue
        m = HEADING_RE.match(line)
        if m:
            depth = len(m.group(1))
            label = m.group(2).strip()
            # Update stack
            section_stack = section_stack[: depth - 1]
            section_stack.append(label)
            current_label = " > ".join(section_stack)
            continue
        m = ITEM_RE.match(line)
        if m:
            n = int(m.group(1))
            t = m.group(2).strip()
            out.append((current_label, n, t))
    return out

# ---------- Citation extraction ----------

CITE_RE = re.compile(r"\[([^\]]+)\]")

def extract_citations(text):
    """Return citation strings inside [] that look like policy references (heuristic)."""
    cits = []
    for m in CITE_RE.finditer(text):
        s = m.group(1)
        if any(s.startswith(p) for p in ("CABF BR", "Mozilla", "Chrome", "Apple", "Microsoft", "CCADB", "LE")):
            cits.append(s)
    return cits

# ---------- Main ----------

def make_csv(md_path, certs_dir, out_csv):
    requirements = parse_md(md_path)
    cert_files = sorted(glob.glob(os.path.join(certs_dir, "*.der")))
    certs = []
    for p in cert_files:
        try:
            cert, der = load_cert(p)
            certs.append((os.path.splitext(os.path.basename(p))[0], cert, der))
        except Exception as e:
            print(f"FAILED to load {p}: {e}", file=sys.stderr)
    print(f"  {len(requirements)} requirements × {len(certs)} certs → {out_csv}")

    matched = 0
    manual_count = 0
    with open(out_csv, "w", newline="") as f:
        w = csv.writer(f)
        header = ["section", "item", "requirement", "citations"]
        for name, _, _ in certs:
            header.append(name)
        w.writerow(header)
        for section, n, text in requirements:
            citations = "; ".join(extract_citations(text))
            row = [section, str(n), text, citations]
            fn = dispatch(text)
            if fn is None:
                manual_count += 1
                for _, c, d in certs:
                    row.append("MANUAL — no check defined")
            else:
                matched += 1
                for _, c, d in certs:
                    try:
                        status, note = fn(c, d)
                    except Exception as e:
                        status, note = ERROR, f"{type(e).__name__}: {e}"
                    row.append(f"{status}: {note}" if note else status)
            w.writerow(row)
    print(f"    Matched a check: {matched}, MANUAL fallback: {manual_count}")

def main():
    build_corpus_index()
    print(f"Corpus indexed: {len(CORPUS)} certs, {len(SELF_SIGNED_ROOTS_BY_SPKI)} unique self-signed-root SPKIs")
    print("=== roots.csv ===")
    make_csv(os.path.join(DOCS, "roots.md"),
             os.path.join(LE_CERTS, "roots"),
             os.path.join(LE_CERTS, "roots.csv"))
    print("=== cross-certs.csv ===")
    make_csv(os.path.join(DOCS, "cross-certs.md"),
             os.path.join(LE_CERTS, "cross-certs"),
             os.path.join(LE_CERTS, "cross-certs.csv"))
    print("=== intermediates.csv ===")
    make_csv(os.path.join(DOCS, "intermediates.md"),
             os.path.join(LE_CERTS, "intermediates"),
             os.path.join(LE_CERTS, "intermediates.csv"))

if __name__ == "__main__":
    main()
