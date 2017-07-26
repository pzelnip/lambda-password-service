from __future__ import print_function

from passlib.hash import pbkdf2_sha256, pbkdf2_sha512, pbkdf2_sha1, bcrypt

HASH_MAPPINGS = {
    "sha256": pbkdf2_sha256,
    "sha512": pbkdf2_sha512,
    "bcrypt": bcrypt,
    "sha1": pbkdf2_sha1,
}

DEFAULT_HASH = pbkdf2_sha1


def lambda_handler(event, context):
    digest = event['digest']
    hash_pass = event['hash_pass']
    password = event['password']
    hash_fn = HASH_MAPPINGS.get(digest, DEFAULT_HASH)
    return hash_fn.verify(password, hash_pass)
