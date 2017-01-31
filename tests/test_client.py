import mock
import pytest
from portier.client import discover_keys, get_verified_email


# Test discover_keys helper

def test_discover_key_call_the_well_known_url_and_the_jwks_uri():
    cache = mock.MagicMock()
    cache.get.return_value = None
    with mock.patch("portier.client.requests") as mocked_requests:
        mocked_requests.get.return_value.json.side_effect = (
            {"jwks_uri": "http://broker-url.tld/jwks_uri"},
            {"keys": []}
        )
        keys = discover_keys("http://broker-url.tld/", cache)

        assert isinstance(keys, dict)

        assert mocked_requests.get.call_count == 2
        mocked_requests.get.assert_any_call(
            "http://broker-url.tld//.well-known/openid-configuration")
        mocked_requests.get.assert_any_call(
            "http://broker-url.tld/jwks_uri")

        assert cache.get.call_count == 1
        assert cache.set.call_count == 1


def test_discover_key_raises_a_value_error_if_jwks_uri_is_not_found():
    cache = mock.MagicMock()
    cache.get.return_value = None
    with mock.patch("portier.client.requests") as mocked_requests:
        mocked_requests.get.return_value.json.return_value = {}
        with pytest.raises(ValueError) as e:
            discover_keys("http://broker-url.tld/", cache)
        assert "No jwks_uri in discovery document" in str(e)


def test_discover_key_raises_a_value_error_if_keys_not_found():
    cache = mock.MagicMock()
    cache.get.return_value = None
    with mock.patch("portier.client.requests") as mocked_requests:
        mocked_requests.get.return_value.json.side_effect = (
            {"jwks_uri": "http://broker-url.tld/jwks_uri"},
            {}
        )
        with pytest.raises(ValueError) as e:
            discover_keys("http://broker-url.tld/", cache)
        assert "No keys found in JWK Set" in str(e)


# Test get_verified_email helper
def test_get_verified_email_validate_the_subject_resembles_an_email_address():
    cache = mock.MagicMock()
    cache.get.side_effect = (
        {"keys": [
            {"kid": "abc",
             "e": "KHTPnNouCvwROWeIWQkJiw",
             "n": "ZgKgqvEo_GZMamwy293IvA",
             "alg": "RS256"}]},
        None
    )
    with mock.patch("portier.client.jwt") as mocked_jwt:
        mocked_jwt.decode.return_value = {
            "sub": "invalid subject"
        }
        with pytest.raises(ValueError) as e:
            get_verified_email("http://broker-url.tld/",
                               "eyJraWQiOiAiYWJjIn0.foo.bar",
                               "audience", "issuer", cache)
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
            get_verified_email("http://broker-url.tld/",
                               "eyJraWQiOiAiYWJjIn0.foo.bar",
                               "audience", "issuer", cache)
        assert "Cannot find public key with ID abc" in str(e)


def test_get_verified_email_validate_it_can_decode_the_jwt_payload():
    cache = mock.MagicMock()
    cache.get.side_effect = (
        {"keys": [
            {"kid": "abc",
             "e": "KHTPnNouCvwROWeIWQkJiw",
             "n": "ZgKgqvEo_GZMamwy293IvA",
             "alg": "RS256"}]},
        None
    )
    with mock.patch("portier.client.jwt") as mocked_jwt:
        mocked_jwt.decode.side_effect = Exception("Foobar")
        with pytest.raises(ValueError) as e:
            get_verified_email("http://broker-url.tld/",
                               "eyJraWQiOiAiYWJjIn0.foo.bar",
                               "audience", "issuer", cache)
        assert "Invalid JWT: Foobar" in str(e)


def test_get_verified_email_validate_the_nonce():
    cache = mock.MagicMock()
    cache.get.side_effect = (
        {"keys": [
            {"kid": "abc",
             "e": "KHTPnNouCvwROWeIWQkJiw",
             "n": "ZgKgqvEo_GZMamwy293IvA",
             "alg": "RS256"}]},
        None
    )
    with mock.patch("portier.client.jwt") as mocked_jwt:
        mocked_jwt.decode.return_value = {
            "sub": "foobar@restmail.com",
            "nonce": "a nonce"
        }
        with pytest.raises(ValueError) as e:
            get_verified_email("http://broker-url.tld/",
                               "eyJraWQiOiAiYWJjIn0.foo.bar",
                               "audience", "issuer", cache)
        assert "Invalid, expired, or re-used nonce" in str(e)


def test_get_verified_return_the_subject_and_redirect_uri():
    cache = mock.MagicMock()
    cache.get.side_effect = (
        {"keys": [
            {"kid": "abc",
             "e": "KHTPnNouCvwROWeIWQkJiw",
             "n": "ZgKgqvEo_GZMamwy293IvA",
             "alg": "RS256"}]},
        "http://redirect_uri"
    )
    with mock.patch("portier.client.jwt") as mocked_jwt:
        mocked_jwt.decode.return_value = {
            "sub": "foobar@restmail.com",
            "nonce": "a nonce"
        }
        result = get_verified_email("http://broker-url.tld/",
                                    "eyJraWQiOiAiYWJjIn0.foo.bar",
                                    "audience", "issuer", cache)
        assert result == ("foobar@restmail.com", "http://redirect_uri")
