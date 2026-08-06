"""SoftHSM / PKCS#11 key backend (A1).

The CA private key lives inside a PKCS#11 token and never enters Python memory.
pyca/cryptography cannot sign with a PKCS#11 key (its builders type-check the
key object), so we reproduce pyca's exact DER a different way:

  1. pyca builds and signs the object with a *throwaway* key of the same
     algorithm. The TBS (to-be-signed) bytes are independent of *which* key
     signs — they depend only on the signature AlgorithmIdentifier
     (sha256WithRSAEncryption / ecdsa-with-SHA256), which the same-algorithm
     throwaway reproduces exactly.
  2. the token signs those TBS bytes with the CA's real key.
  3. asn1crypto reassembles the object with the token's signature swapped in.

Because RSA PKCS#1 v1.5 is deterministic, the DER produced here is
byte-identical to what the software backend produced from the same key — the
differential test in tests/test_softhsm.py asserts exactly that.

Phase 2 implements leaf-certificate signing (RSA + EC), key generation, and key
import. CRL and OCSP signing for HSM-backed CAs arrive in a later phase.
"""
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from asn1crypto import x509 as asn1_x509

from .base import KeyBackend, OcspResponseSpec
from . import pkcs11_session


# NIST curve name (asn1crypto NamedCurve) by pyca key size.
_EC_CURVE_NAME = {256: "secp256r1", 384: "secp384r1", 521: "secp521r1"}


class Pkcs11Backend(KeyBackend):
    name = "softhsm"

    # -- helpers -------------------------------------------------------------
    def _ca_key_info(self, ca):
        """('RSA', None) or ('EC', curve) from the CA certificate's public key."""
        pub = self.load_public_key(ca)
        if isinstance(pub, rsa.RSAPublicKey):
            return "RSA", None
        if isinstance(pub, ec.EllipticCurvePublicKey):
            return "EC", pub.curve
        raise ValueError("Unsupported CA key type for the HSM backend.")

    def _throwaway_key(self, ca):
        key_type, curve = self._ca_key_info(ca)
        if key_type == "RSA":
            return rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return ec.generate_private_key(curve)

    def _hsm_sign(self, tbs_bytes, ca):
        """Sign TBS bytes inside the token; return the X.509 signatureValue.

        We sign with the single-part RSA mechanism but the *raw* EC mechanism
        over a SHA-256 digest: SoftHSM (and many hardware tokens) implement only
        CKM_ECDSA, not CKM_ECDSA_SHA256. The certificate's algorithm is
        ecdsa-with-SHA256 either way (the software backend also hashes with
        SHA-256), so signing the SHA-256 digest keeps output equivalent.
        """
        import hashlib
        from pkcs11 import ObjectClass, Mechanism
        from pkcs11.util.ec import encode_ecdsa_signature

        key_type, _curve = self._ca_key_info(ca)
        with pkcs11_session.session_scope() as session:
            priv = session.get_key(
                object_class=ObjectClass.PRIVATE_KEY, label=ca.key_label
            )
            if key_type == "RSA":
                # SHA256_RSA_PKCS hashes and signs; the result is the PKCS#1 v1.5
                # signatureValue directly.
                return priv.sign(tbs_bytes, mechanism=Mechanism.SHA256_RSA_PKCS)
            # Raw ECDSA over the SHA-256 digest returns r||s; wrap it in the DER
            # Ecdsa-Sig-Value X.509 wants.
            digest = hashlib.sha256(tbs_bytes).digest()
            raw = priv.sign(digest, mechanism=Mechanism.ECDSA)
            return encode_ecdsa_signature(raw)

    def _swap_signature(self, throwaway_der, ca):
        """Rebuild a Certificate from a throwaway-signed DER, replacing its
        signature with the token's over the (unchanged) TBS bytes."""
        asn1cert = asn1_x509.Certificate.load(throwaway_der)
        tbs = asn1cert["tbs_certificate"]
        signature = self._hsm_sign(tbs.dump(), ca)
        signed = asn1_x509.Certificate({
            "tbs_certificate": tbs,
            "signature_algorithm": asn1cert["signature_algorithm"],
            "signature_value": signature,
        })
        return signed.dump()

    # -- key lifecycle -------------------------------------------------------
    def generate_ca_key(self, key_type, key_size, *, label):
        from pkcs11 import KeyType, Attribute
        from pkcs11.util.ec import encode_named_curve_parameters

        with pkcs11_session.session_scope() as session:
            if key_type == "RSA":
                pub, _priv = session.generate_keypair(
                    KeyType.RSA, key_size, store=True, label=label,
                    id=label.encode()[:32],
                    private_template={
                        Attribute.TOKEN: True, Attribute.PRIVATE: True,
                        Attribute.SENSITIVE: True, Attribute.EXTRACTABLE: False,
                        Attribute.SIGN: True,
                    },
                    public_template={Attribute.TOKEN: True, Attribute.VERIFY: True},
                )
                n = int.from_bytes(pub[Attribute.MODULUS], "big")
                e = int.from_bytes(pub[Attribute.PUBLIC_EXPONENT], "big")
                public_key = rsa.RSAPublicNumbers(e, n).public_key()
            elif key_type == "EC":
                params = encode_named_curve_parameters(_EC_CURVE_NAME[key_size])
                pub, _priv = session.generate_keypair(
                    KeyType.EC, key_size, store=True, label=label,
                    id=label.encode()[:32],
                    private_template={
                        Attribute.TOKEN: True, Attribute.PRIVATE: True,
                        Attribute.SENSITIVE: True, Attribute.EXTRACTABLE: False,
                        Attribute.SIGN: True,
                    },
                    public_template={
                        Attribute.TOKEN: True, Attribute.VERIFY: True,
                        Attribute.EC_PARAMS: params,
                    },
                )
                from pkcs11.util.ec import encode_ec_public_key
                spki = encode_ec_public_key(pub)
                public_key = serialization.load_der_public_key(spki)
            else:
                raise ValueError(f"Unsupported key type: {key_type}")

            # Tag both objects with the real SKI (CKA_ID) for interop/lookup.
            try:
                ski = x509.SubjectKeyIdentifier.from_public_key(public_key).digest
                pub[Attribute.ID] = ski
            except Exception:
                pass
        return public_key, label

    def import_ca_key(self, private_key, *, label):
        from pkcs11 import Attribute
        from pkcs11.util.rsa import decode_rsa_private_key
        from pkcs11.util.ec import decode_ec_private_key

        der = private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        if isinstance(private_key, rsa.RSAPrivateKey):
            template = decode_rsa_private_key(der)
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            template = decode_ec_private_key(der)
        else:
            raise ValueError("Unsupported key type for HSM import.")

        template[Attribute.TOKEN] = True
        template[Attribute.LABEL] = label
        template[Attribute.ID] = label.encode()[:32]
        template[Attribute.PRIVATE] = True
        template[Attribute.SENSITIVE] = True
        template[Attribute.EXTRACTABLE] = False  # one-way: cannot be pulled back out
        template[Attribute.SIGN] = True
        with pkcs11_session.session_scope() as session:
            session.create_object(template)
        return label

    def load_public_key(self, ca):
        return x509.load_pem_x509_certificate(ca.certificate_pem.encode()).public_key()

    # -- signing -------------------------------------------------------------
    def sign_certificate(self, builder, ca, *, secret=None) -> bytes:
        throwaway_der = builder.sign(
            self._throwaway_key(ca), hashes.SHA256()
        ).public_bytes(serialization.Encoding.DER)
        return self._swap_signature(throwaway_der, ca)

    def sign_crl(self, builder, ca, *, secret=None) -> bytes:
        raise NotImplementedError(
            "CRL signing for HSM-backed CAs is not yet supported (arrives in a later phase)."
        )

    def sign_ocsp(self, spec: OcspResponseSpec, ca, *, secret=None) -> bytes:
        raise NotImplementedError(
            "OCSP signing for HSM-backed CAs is not yet supported (arrives in a later phase)."
        )

    # -- capabilities --------------------------------------------------------
    def can_export(self) -> bool:
        return False
