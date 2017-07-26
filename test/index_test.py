import unittest

from index import lambda_handler


SAMPLE_PASSWORD = 'password'
SAMPLE_SHA1_HASH = '$pbkdf2$131000$rVUq5VxLKcWYkxKiVOq99w$5zoSk15EHe9N1nmRfyFoPIIRy/Y'
SAMPLE_SHA512_HASH = '$pbkdf2-sha512$25000$ltLae69VihFirDVGSOmdUw$pcLVv3Vnm3XRx9aHNUgI1FQaF8.UmKHBYt.Hs2EI7at/V80kbsb2P1A2t9akjNom8ZUgVJ4AcbA5vk/7QTgEJQ'
SAMPLE_SHA256_HASH = '$pbkdf2-sha256$29000$.L93bg0BwFiLEaL0fm8NIQ$yYmxiSuP9pXXbrO4cT6CkE1QaNKpt8PjugrgvOBfcRY'
SAMPLE_BCRYPT_HASH = '$2b$12$44roRI0Ftbbvoy6V1YQebOKeO7a7WhzRvv.X194BMxykDT0nQGcS2'


class TestLambdaHandler(unittest.TestCase):
    def test_valid_sha256_hash_with_matching_password_returns_true(self):
        event = _build_event('sha256', SAMPLE_SHA256_HASH, SAMPLE_PASSWORD)
        expected = True

        result = lambda_handler(event, None)

        self.assertEqual(expected, result)

    def test_valid_sha256_hash_with_wrong_password_returns_false(self):
        event = _build_event('sha256', SAMPLE_SHA256_HASH, 'this is not the password')
        expected = False

        result = lambda_handler(event, None)

        self.assertEqual(expected, result)

    def test_valid_sha512_hash_with_matching_password_returns_true(self):
        event = _build_event('sha512', SAMPLE_SHA512_HASH, SAMPLE_PASSWORD)
        expected = True

        result = lambda_handler(event, None)

        self.assertEqual(expected, result)

    def test_valid_sha512_hash_with_wrong_password_returns_false(self):
        event = _build_event('sha512', SAMPLE_SHA512_HASH, 'this is not the password')
        expected = False

        result = lambda_handler(event, None)

        self.assertEqual(expected, result)

    def test_valid_sha1_hash_with_matching_password_returns_true(self):
        event = _build_event('sha1', SAMPLE_SHA1_HASH, SAMPLE_PASSWORD)
        expected = True

        result = lambda_handler(event, None)

        self.assertEqual(expected, result)

    def test_valid_sha1_hash_with_wrong_password_returns_false(self):
        event = _build_event('sha1', SAMPLE_SHA1_HASH, 'this is not the password')
        expected = False

        result = lambda_handler(event, None)

        self.assertEqual(expected, result)

    def test_default_hash_is_sha1(self):
        event = _build_event(None, SAMPLE_SHA1_HASH, SAMPLE_PASSWORD)
        expected = True

        result = lambda_handler(event, None)

        self.assertEqual(expected, result)

    def test_valid_bcrypt_hash_with_matching_password_returns_true(self):
        event = _build_event('bcrypt', SAMPLE_BCRYPT_HASH, SAMPLE_PASSWORD)
        expected = True

        result = lambda_handler(event, None)

        self.assertEqual(expected, result)

    def test_valid_sha1_hash_with_wrong_password_returns_false(self):
        event = _build_event('bcrypt', SAMPLE_BCRYPT_HASH, 'this is not the password')
        expected = False

        result = lambda_handler(event, None)

        self.assertEqual(expected, result)

    def test_unspecified_hash_pass_returns_false(self):
        event = _build_event('bcrypt', SAMPLE_BCRYPT_HASH, SAMPLE_PASSWORD)
        del event['hash_pass']
        expected = False

        result = lambda_handler(event, None)

        self.assertEqual(expected, result)

    def test_unspecified_digest_uses_sha1(self):
        event = _build_event('does not matter', SAMPLE_SHA1_HASH, SAMPLE_PASSWORD)
        del event['digest']
        expected = True

        result = lambda_handler(event, None)

        self.assertEqual(expected, result)


def _build_event(digest, hash_pass, password):
    return {
        "digest": digest,
        "hash_pass": hash_pass,
        "password": password,
    }
