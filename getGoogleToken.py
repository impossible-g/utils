# _*_coding:utf-8_*_
# __author: g
"""
PyJWT==1.7.1
requests==2.24.0
cryptography==3.2.1
"""
import json
import time

import jwt
import requests


def try_while(func):
    num = 3

    def inner(*args, **kwargs):
        for i in range(num):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                print(f"{func}", e)
                return inner(*args, **kwargs)

    return inner


cache_map = {}  # {func: {"value": "", "expires": int(time.time()) + expires_in}}


def cache(func):
    def inner(cls, *args, **kwargs):
        key = f"{func}"
        if key in cache_map and cache_map[key]["expires"] > int(time.time()):
            return cache_map[key]["value"]

        result = func(cls, *args, **kwargs)
        cache_map.setdefault(key, {})
        cache_map[key].update({"value": result, "expires": int(time.time()) + cls.expires_in - 30})
        return result

    return inner


class GenGoogleToken:
    auth_url = "https://www.googleapis.com/oauth2/v4/token"
    scope = "https://www.googleapis.com/auth/cloud-platform"
    expires_in = 3600
    algorithm = "RS256"
    account_file = "account.json"

    with open(account_file, "r") as fr:
        account_json = json.load(fr)

    @classmethod
    def gen_jwt(cls):
        issued = int(time.time())
        expires = issued + cls.expires_in

        headers = {
            "kid": cls.account_json["private_key_id"],
            "alg": cls.algorithm,
            "typ": "JWT",
        }

        payload = {
            "iss": cls.account_json["client_email"],  # Issuer claim
            "sub": cls.account_json["client_email"],  # Issuer claim
            "aud": cls.auth_url,  # Audience claim
            "iat": issued,  # Issued At claim
            "exp": expires,  # Expire time
            "scope": cls.scope  # Permissions
        }

        sig = jwt.encode(payload, cls.account_json["private_key"], algorithm="RS256", headers=headers)
        return sig

    @classmethod
    @try_while
    def gen_token(cls, sig):
        params = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": sig
        }
        resp = requests.post(cls.auth_url, data=params)
        return resp.json()["access_token"]

    @classmethod
    @cache
    def get_token(cls):
        sig = cls.gen_jwt()
        token = cls.gen_token(sig)
        return token


gen_google_token = GenGoogleToken

if __name__ == '__main__':
    for i in range(10):
        # time.sleep(1)
        print(gen_google_token.get_token())
