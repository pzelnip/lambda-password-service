import unittest

from index import lambda_handler


class TestLambdaHandler(unittest.TestCase):
    def test_valid_sha256_hash_with_matching_password_returns_true(self):
        event = {
            "digest": "sha256",
            "hash_pass": "$pbkdf2-sha256$29000$.L93bg0BwFiLEaL0fm8NIQ$yYmxiSuP9pXXbrO4cT6CkE1QaNKpt8PjugrgvOBfcRY",
            "password": "password"
        }
        expected = True

        result = lambda_handler(event, None)

        self.assertEqual(expected, result)

    def test_valid_sha256_hash_with_wrong_password_returns_false(self):
        event = {
            "digest": "sha256",
            "hash_pass": "$pbkdf2-sha256$29000$.L93bg0BwFiLEaL0fm8NIQ$yYmxiSuP9pXXbrO4cT6CkE1QaNKpt8PjugrgvOBfcRY",
            "password": "this is not the password"
        }
        expected = False

        result = lambda_handler(event, None)

        self.assertEqual(expected, result)
