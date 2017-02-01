import mock
import pytest

from portier.client import discover_keys, get_verified_email

BROKER_URL = "http://broker-url.tld/"
TOKEN = "eyJraWQiOiAiYWJjIn0.foo.bar"
JWKS_URI = "http://broker-url.tld/jwks_uri"

KEY = {"kid": "abc",
       "e": "KHTPnNouCvwROWeIWQkJiw",
       "n": "ZgKgqvEo_GZMamwy293IvA",
       "alg": "RS256"}

DECODED_JWT = {
    "sub": "foobar@restmail.com",
    "nonce": "a nonce"
}
REDIRECT_URI = "http://redirect_uri"

empty_cache = mock.MagicMock()
empty_cache.get.return_value = None


# Test discover_keys helper

def test_discover_key_call_the_well_known_url_and_the_jwks_uri():
    empty_cache.reset_mock()
    with mock.patch("portier.client.requests") as mocked_requests:
        mocked_requests.get.return_value.json.side_effect = (
            {"jwks_uri": JWKS_URI},
            {"keys": []}
        )
        keys = discover_keys(BROKER_URL, empty_cache)

    assert isinstance(keys, dict)

    assert mocked_requests.get.call_count == 2
    mocked_requests.get.assert_any_call("http://broker-url.tld/.well-known/openid-configuration")
    mocked_requests.get.assert_any_call(JWKS_URI)

    assert empty_cache.get.call_count == 1
    assert empty_cache.set.call_count == 1


def test_discover_key_raises_a_value_error_if_jwks_uri_is_not_found():
    with mock.patch("portier.client.requests") as mocked_requests:
        mocked_requests.get.return_value.json.return_value = {}
        with pytest.raises(ValueError) as e:
            discover_keys(BROKER_URL, empty_cache)
        assert "No jwks_uri in discovery document" in str(e)


def test_discover_key_raises_a_value_error_if_keys_not_found():
    with mock.patch("portier.client.requests") as mocked_requests:
        mocked_requests.get.return_value.json.side_effect = (
            {"jwks_uri": JWKS_URI},
            {}
        )
        with pytest.raises(ValueError) as e:
            discover_keys(BROKER_URL, empty_cache)
        assert "No keys found in JWK Set" in str(e)


# Test get_verified_email helper
def test_get_verified_email_validate_the_subject_resembles_an_email_address():
    cache = mock.MagicMock()
    cache.get.side_effect = (
        {"keys": [KEY]},
        REDIRECT_URI
    )
    with mock.patch("portier.client.jwt") as mocked_jwt:
        mocked_jwt.decode.return_value = {
            "sub": "invalid subject"
        }
        with pytest.raises(ValueError) as e:
            get_verified_email(broker_url=BROKER_URL,
                               token=TOKEN,
                               audience="audience",
                               issuer="issuer",
                               cache=cache)
        assert "Invalid email address: invalid subject" in str(e)


def test_get_verified_email_validate_it_can_find_a_public_key():
    cache = mock.MagicMock()
    cache.get.side_effect = (
        {"keys": []},
        None
    )
    with mock.patch("portier.client.jwt") as mocked_jwt:
        mocked_jwt.decode.return_value = {
            "sub": "invalid subject"
        }
        with pytest.raises(ValueError) as e:
            get_verified_email(broker_url=BROKER_URL,
                               token=TOKEN,
                               audience="audience",
                               issuer="issuer",
                               cache=cache)
        assert "Cannot find public key with ID abc" in str(e)


def test_get_verified_email_validate_it_can_decode_the_jwt_payload():
    cache = mock.MagicMock()
    cache.get.side_effect = (
        {"keys": [KEY]},
        REDIRECT_URI
    )
    with mock.patch("portier.client.jwt") as mocked_jwt:
        mocked_jwt.decode.side_effect = Exception("Foobar")
        with pytest.raises(ValueError) as e:
            get_verified_email(broker_url=BROKER_URL,
                               token=TOKEN,
                               audience="audience",
                               issuer="issuer",
                               cache=cache)
        assert "Invalid JWT: Foobar" in str(e)


def test_get_verified_email_validate_the_nonce():
    cache = mock.MagicMock()
    cache.get.side_effect = (
        {"keys": [KEY]},
        None
    )
    with mock.patch("portier.client.jwt") as mocked_jwt:
        mocked_jwt.decode.return_value = DECODED_JWT
        with pytest.raises(ValueError) as e:
            get_verified_email(broker_url=BROKER_URL,
                               token=TOKEN,
                               audience="audience",
                               issuer="issuer",
                               cache=cache)
        assert "Invalid, expired, or re-used nonce" in str(e)


def test_get_verified_return_the_subject_and_redirect_uri():
    cache = mock.MagicMock()
    cache.get.side_effect = (
        {"keys": [KEY]},
        REDIRECT_URI
    )
    with mock.patch("portier.client.jwt") as mocked_jwt:
        mocked_jwt.decode.return_value = DECODED_JWT
        result = get_verified_email(broker_url=BROKER_URL,
                                    token=TOKEN,
                                    audience="audience",
                                    issuer="issuer",
                                    cache=cache)
        assert result == (DECODED_JWT['sub'], REDIRECT_URI)
