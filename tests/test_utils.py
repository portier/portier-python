import os
from jwt.utils import b64_encode, base64_to_int

from portier.utils import jwk_to_rsa


def test_jwk_to_rsa():
    e = b64_encode(os.urandom(16))
    n = b64_encode(os.urandom(16))

    int_e = base64_to_int(e)
    int_n = base64_to_int(n)
    while int_e % 2 != 1 or int_e > int_n:
        e = b64_encode(os.urandom(16))
        int_e = base64_to_int(e)

    key = {
        'e': e,
        'n': b64_encode(os.urandom(16)),
    }
    rsa_key = jwk_to_rsa(key)
    assert rsa_key
