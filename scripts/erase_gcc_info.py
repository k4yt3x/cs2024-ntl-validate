#!/usr/bin/python
import re

BINARY_PATH = "bin/validate"

with open(BINARY_PATH, "rb") as file:
    binary_data = file.read()

pattern = re.compile(rb"GCC: \(GNU\) \d+(\.\d+)* \d{8}")

replaced_data = pattern.sub(lambda m: b"\x00" * len(m.group()), binary_data)

with open(BINARY_PATH, "wb") as file:
    file.write(replaced_data)

print("Erased compiler information.")
