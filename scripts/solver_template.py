#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
This is a template for the solver script.
You will need to implement the logic to generate the token for each name.
"""
import requests

SERVER_BASE_URL = "http://127.0.0.1:8080"


def generate_token(name: str) -> str:
    """
    Generate the token for the given name.
    """

    # TODO: implement the logic to generate the token for the name
    return "?"


names = requests.get(f"{SERVER_BASE_URL}/challenge", timeout=3).json()["names"]

tokens = []
for name in names:

    # generate the token for the name
    token = generate_token(name)

    # save the token to the dictionary
    tokens.append({"name": name, "token": token})

# send the tokens to the server to answer the challenge
response = requests.post(
    f"{SERVER_BASE_URL}/challenge", json={"submissions": tokens}, timeout=3
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
