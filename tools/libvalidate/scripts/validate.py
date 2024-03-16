#!/usr/bin/python
import os
from ctypes import CDLL, c_char_p, c_int

lib_path = os.path.abspath("libvalidate.so")
validate_lib = CDLL(lib_path)

validate_lib.validate_token.argtypes = [c_char_p]
validate_lib.validate_token.restype = c_int

TOKEN = (
    "SzRZVDNY.4V43VnMchGsi2mF7Opq1zadt3JYvxox+T2M6NJuofuIDwTeX7vvAQqlaXrw67NPv".encode(
        "utf-8"
    )
)

result = validate_lib.validate_token(TOKEN)

if result == 1:
    print("Token is valid.")

elif result == -1:
    print("Program internal error")

else:
    print("Token is invalid.")
