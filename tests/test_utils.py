import os
from jwt.utils import b64_encode, base64_to_int

from portier.utils import jwk_to_rsa


def test_jwk_to_rsa():
    key = {
        'e': 'KHTPnNouCvwROWeIWQkJiw',
        'n': 'ZgKgqvEo_GZMamwy293IvA',
    }
    rsa_key = jwk_to_rsa(key)
    assert rsa_key
