from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

from app.services.crypto_utils import encrypt_private_key, decrypt_private_key


def test_encrypt_decrypt_rsa_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    passphrase = "test-passphrase"

    encrypted = encrypt_private_key(key, passphrase)
    assert isinstance(encrypted, bytes)
    assert len(encrypted) > 16  # salt + token

    decrypted = decrypt_private_key(encrypted, passphrase)
    original_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    decrypted_pem = decrypted.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    assert original_pem == decrypted_pem


def test_encrypt_decrypt_ec_key():
    key = ec.generate_private_key(ec.SECP256R1())
    passphrase = "another-passphrase"

    encrypted = encrypt_private_key(key, passphrase)
    decrypted = decrypt_private_key(encrypted, passphrase)

    original_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    decrypted_pem = decrypted.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    assert original_pem == decrypted_pem


def test_wrong_passphrase_fails():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    encrypted = encrypt_private_key(key, "correct-passphrase")

    try:
        decrypt_private_key(encrypted, "wrong-passphrase")
        assert False, "Should have raised an exception"
    except Exception:
        pass


def test_encrypt_pem_bytes():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    encrypted = encrypt_private_key(key_pem, "test")
    decrypted = decrypt_private_key(encrypted, "test")

    decrypted_pem = decrypted.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    assert key_pem == decrypted_pem
