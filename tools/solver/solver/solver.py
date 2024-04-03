#!/usr/bin/python
# -*- coding: utf-8 -*-
import base64
import hashlib

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

KEY = b"flag{ReADiNg_AsM_aiNt_thAT_HarD}"
IV = b"shELlnEverDaNCEwiThUsagAIN"[:16]
SERVER_BASE_URL = "http://127.0.0.1:8080"


def pad(data: bytes) -> bytes:
    """
    Pad the data with PKCS7 padding.

    :param data: the data to pad
    :return: the padded data
    """
    padder = PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data


def main() -> int:
    names = requests.get(f"{SERVER_BASE_URL}/challenges").json()["names"]

    tokens = []
    for name in names:

        # use AES-256 in CBC mode
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
        encryptor = cipher.encryptor()

        # hash the name with SHA-256
        name_hash = hashlib.sha256(name.encode("utf-8")).digest()

        # pad the name with PKCS#7
        padded_name_hash = pad(name_hash)

        # encrypt the padded name hash
        encrypted_hash = encryptor.update(padded_name_hash) + encryptor.finalize()

        # encode the encrypted hash with base64
        encoded_encrypted_hash = base64.b64encode(encrypted_hash).decode()

        # concatenate the base64-encoded name and the base64-encoded encrypted hash
        token = "{}.{}".format(
            base64.b64encode(name.encode("utf-8")).decode(), encoded_encrypted_hash
        )

        # save the token to the dictionary
        tokens.append({"name": name, "token": token})

    # send the tokens to the server to answer the challenge
    response = requests.post(
        f"{SERVER_BASE_URL}/challenges", json={"submissions": tokens}
    )
    response_json = response.json()

    # print the response from the server
    flag = response_json.get("flag")
    if flag is None:
        print("Incorrect answer.")
        print(f"Response code: {response.status_code}")
        print(f"Error message: {response_json.get('error')}")
    else:
        print(f"Correct answer.\nFlag: {flag}")

    return 0
