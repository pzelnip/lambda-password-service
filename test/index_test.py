import unittest

from index import lambda_handler


SAMPLE_SHA256_HASH = '$pbkdf2-sha256$29000$.L93bg0BwFiLEaL0fm8NIQ$yYmxiSuP9pXXbrO4cT6CkE1QaNKpt8PjugrgvOBfcRY'
SAMPLE_PASSWORD = 'password'


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


def _build_event(digest, hash_pass, password):
    return {
        "digest": digest,
        "hash_pass": hash_pass,
        "password": password,
    }
