from __future__ import print_function

from passlib.hash import pbkdf2_sha256, pbkdf2_sha512, pbkdf2_sha1, bcrypt


HASH_MAPPINGS = {
    "sha256": pbkdf2_sha256,
    "sha512": pbkdf2_sha512,
    "bcrypt": bcrypt,
    "sha1": pbkdf2_sha1,
}

DEFAULT_HASH = 'sha1'


def lambda_handler(event, context):
    digest = event.get('digest', DEFAULT_HASH)
    hash_pass = event.get('hash_pass')
    password = event['password']
    if not hash_pass:
        return False
    hash_fn = HASH_MAPPINGS.get(digest)
    return hash_fn.verify(password, hash_pass)
