# Walkthrough

This file contains the walkthrough for the challenge `Infinite Free Conference Tickets`.

## Part I

This challenge focuses heavily on obfuscation. It employs a wide variety of classic forms of junk code. For instance, this is one of the junk code patterns used in the challenge:

```asm
db 0xEB, 0xFF, 0xC0
```

When the CPU executes these instructions, it first reaches `0xEB` which is a two-byte jump short command. It jumps by `0xFF` which is -1 byte from the end of the instruction, so the RIP register lands before `0xFF`. It then interprets `0xFF, 0xC0` as another two-byte instruction and performs `inc eax`. Linear disassemblers might correctly interpret `0xEB, 0xFF` as `jmp -1`, then incorrectly start with `0xC1` instead of `0xFF` as the next opcode. This results in the following bytes being interpreted incorrectly and either produces incorrect disassembly or get displayed as raw data because the disassembler cannot understand the following bytes.

In practice, such junk code will result in linear disassemblers producing incorrect results (e.g., IDA Pro). Non-linear disassemblers like Radare2 and Binary Ninja do not suffer the same issues as much. Disassembly after junk code may be incorrect, or represented as raw data because the disassembler cannot interpret the bytes.

![[junk_code_example.png]]

Junk codes like these are spread out throughout the entire file. They make the disassembly unreadable. Participants need to successfully identify these obfuscation patterns and make use of IDAPython or other similar automated tools to NOP-patch these junk codes in bulk to make the file readable. For instance, the following IDAPython script can be used to patch the `0xEB, 0xFF, 0xC0` pattern:

```python
#!/usr/bin/python
# -*- utf-8 -*-
from idaapi import *
from idautils import *
from idc import *

def nops_out_junk_bytes():
    # Iterate through all segments
    for seg in Segments():
        seg_start = get_segm_start(seg)
        seg_end = get_segm_end(seg)
        
        ea = seg_start
        while ea < seg_end:
            # Read 3 bytes from the current address
            bytes = get_bytes(ea, 3)
            
            if bytes is None or len(bytes) < 3:
                ea += 1
                continue

            # If the bytes match 0xEB 0xFF 0xC0
            # Replace 0xEB with 0x90 (NOP)
            if bytes[0] == 0xEB and bytes[1] == 0xFF and bytes[2] == 0xC0:
                patch_byte(ea, 0x90)
            
            ea += 1

nops_out_junk_bytes()
```

With automated and manual junk code patching, the program's bytes can be gradually converted into normal readable disassembly:

![](corrected_disassembly.png)

From this point onward, the participants can read the assembly or, optionally, patch the program to a state where IDA can correctly identify the subroutine boundaries and run decompilers on the functions. The latter could be difficult. The participants will find that this program contains strings hinting that OpenSSL is statically linked, indicating that one of the algorithms in OpenSSL may be used to sign the token.

![](openssl_strings.png)

From here, it may be helpful for the participants to use a debugger to step through the program to figure out the contents of the concatenated strings and decrypted keys in the memory. This program uses AES-256-CBC to encrypt the SHA-256 hash of the user's name. Participants can catch the IV and AES key used when the function `EVP_DecryptInit_ex` is called. The IV and the AES encryption key are stored in the same chunk of memory without null byte separation. They are passed to the `EVP_DecryptInit_ex` with offsets pointing to different portions of the memory chunk:

```c
EVP_DecryptInit_ex(ctx, (const EVP_CIPHER *)cipher, NULL, MESSAGE_XOR_KEY + 26, MESSAGE_XOR_KEY);
```

The first half of the memory will get decrypted before the AES key and will be null-terminated. It will be used as a XOR decryption key to decrypt the Base64-encoded text strings. Once the program gets to the AES encryption part, the AES key will be appended after the message decryption key, with its first byte overwriting the message decryption key's last byte, the null byte. OpenSSL will take the first 16 bytes starting from the address of `MESSAGE_XOR_KEY` as the IV, and 32 bytes starting from the address of `MESSAGE_XOR_KEY + 26` as the AES encryption key. The string at the address of `MESSAGE_XOR_KEY + 26` is the flag for the first part of the challenge, which would be `flag{ReADiNg_AsM_aiNt_thAT_HarD}`.

It is also worth mentioning that this program also has countermeasures against dynamic analysis (debuggers). It achieves this through sabotaging the program's stack if `ptrace(PTRACE_TRACEME);` returns `-1`, indicating that a debugger is already attached. Attempting to debug the program without patching this check will result in a confusing segfault happening later in the program:

![](anti_debug_segfault.png)

The `ptrace` call is obfuscated and called via a x86 syscall instead of a direct `ptrace` call. The syscall ID is calculated dynamically during the program's execution. The participants will need to patch these checks in order to be able to debug the program.

```c
// manually do a ptrace syscall and write result to ptrace_result
// using x86 `int 0x80` to perform the syscall to make it slightly less obvious
__asm__ volatile(
	"movl %3, %%edx\n"
	"movl %1, %%ebx\n"
	"movl %0, %%eax\n"
	"movl %2, %%ecx\n"
	"int $0x80\n"
	"cmp %%ecx, %%eax\n"
	"jge 0f\n"
	// compiles to a single byte 0x58
	// will crash the program in a later function calls, likely within OpenSSH
	"pop %%rax\n"
	"0:\n"
	:
	: "r"(syscall_id), "r"(ptrace_request), "r"(ptrace_request), "r"((int)message[index])
	: "eax", "ebx", "ecx", "edx"
);
```

## Part II

In this part of the challenge, the participant will need to analyze the file to uncover the algorithm used to check valid tokens. The algorithm is as follows:

- Let `AESDecrypt(T, K, IV)` represent the AES-256-CBC decryption of the token `T` using the key `K` and initialization vector `IV`.
- Let `SHA256(U)` represent the SHA-256 hash of the username `U`.

The algorithm checks if the decryption of the token is equal to the hash of the username:

```scss
AESDecrypt(T, K, IV) = SHA256(U)
```

Thus, the mathematical formula for the validation is:

```scss
Valid ⟺ AESDecrypt(T, K, IV) = SHA256(U)
```

If this equation holds true, the token is valid; otherwise, it is invalid. The participants can fill in the reversed algorithm in the provided `solver_template.py` file to solve the challenge. The algorithm will be:

- Let `AESEncrypt(P, K, IV)` represent the AES-256-CBC encryption of the plaintext `P` using the key `K` and initialization vector `IV`.
- Let `SHA256(U)` represent the SHA-256 hash of the username `U`.

```scss
token = AESEncrypt(SHA256(U), K, IV)
```

The completed `solver.py` will look like:

```python
#!/usr/bin/python
# -*- coding: utf-8 -*-
import base64
import hashlib
import os

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

KEY = b"flag{ReADiNg_AsM_aiNt_thAT_HarD}"
IV = b"shELlnEverDaNCEwiThUsagAIN"[:16]
SERVER_BASE_URL = os.environ.get("SERVER_BASE_URL", "http://127.0.0.1:8080")


def generate_token(name: str) -> str:
    """
    Generate the token for the given name.

    :param name: the name of the participant
    :return: the token for the name
    """

    # use AES-256 in CBC mode
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()

    # hash the name with SHA-256
    name_hash = hashlib.sha256(name.encode("utf-8")).digest()

    # pad the name with PKCS#7
    padder = PKCS7(128).padder()
    padded_name_hash = padder.update(name_hash) + padder.finalize()

    # encrypt the padded name hash
    encrypted_hash = encryptor.update(padded_name_hash) + encryptor.finalize()

    # encode the encrypted hash with base64
    encoded_encrypted_hash = base64.b64encode(encrypted_hash).decode()

    # concatenate the base64-encoded name and the base64-encoded encrypted hash
    token = "{}.{}".format(
        base64.b64encode(name.encode("utf-8")).decode(), encoded_encrypted_hash
    )

    return token

# The rest of the file is omitted
```

The participant can then run the solver script against the challenge server to obtain the flag for part II of this challenge.