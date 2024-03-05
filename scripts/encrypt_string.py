#!/usr/bin/python
import base64


def xor_encrypt(data, key):
    if not isinstance(data, bytes):
        data = data.encode("utf-8")
    if not isinstance(key, bytes):
        key = key.encode("utf-8")

    encrypted = bytearray()
    for i in range(len(data)):
        encrypted.append(data[i] ^ key[i % len(key)])
    return bytes(encrypted)


def main():
    string = input("String to encrypt: ")
    string = string.replace("\\n", "\n")
    key = "shELlnEverDaNCEwiThUsagAIN"
    xor_encrypted = xor_encrypt(string, key)
    encoded = base64.b64encode(xor_encrypted)
    print("Encrypted and encoded string:", encoded.decode("utf-8"))
    print(f"String length: {len(encoded) + 1}\n")

    # print C source code
    print("int index = 0;")
    for c in encoded:
        print("message[index] = '{}';\nindex++;".format(chr(c)))
    print("message[index] = '\\0';")
    print("decrypt_print(message);")


if __name__ == "__main__":
    main()
