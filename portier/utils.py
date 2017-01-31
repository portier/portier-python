from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.utils import b64_decode as b64decode


# Public API
__all__ = (
    'b64decode',
    'jwk_to_rsa'
)


def jwk_to_rsa(key):
    """Convert a deserialized JWK into an RSA Public Key instance."""
    e = int(b64decode(key['e']).encode('hex'), 16)
    n = int(b64decode(key['n']).encode('hex'), 16)
    return rsa.RSAPublicNumbers(e, n).public_key(default_backend())
