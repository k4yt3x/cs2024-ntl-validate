#!/usr/bin/python
KEY = "shELlnEverDaNCEwiThUsagAIN"

CODE = """
    MESSAGE_XOR_KEY[index] = {} ^ 0xFE;

    __asm__ volatile(
        ".byte 0xEB, 0xFF, 0xC1\\n"
        "movq %%rcx, %0\\n"
        : "=r"(index)
        :
        : "rcx"
    );
"""


for i in KEY:
    h = ord(i) ^ 0xFE
    print(CODE.format(hex(h)))
