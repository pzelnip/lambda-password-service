from __future__ import print_function

from passlib.hash import pbkdf2_sha256, pbkdf2_sha512, pbkdf2_sha1, bcrypt


def lambda_handler(event, context):
    digest = event['digest']
    hash_pass = event['hash_pass']
    password = event['password']

    if digest == "sha256":
        verification = pbkdf2_sha256.verify(password, hash_pass)
    elif digest == "sha512":
        verification = pbkdf2_sha512.verify(password, hash_pass)
    elif digest == "bcrypt":
        verification = bcrypt.verify(password, hash_pass)
    else:
        verification = pbkdf2_sha1.verify(password, hash_pass)
    return verification
