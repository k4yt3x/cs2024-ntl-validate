#include <openssl/bio.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char *
base64_encode(const unsigned char *input, int length, int *out_len)
{
    BIO *bmem, *b64;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);

    BIO_write(b64, input, length);
    BIO_flush(b64);

    char *buff;
    long data_length = BIO_get_mem_data(bmem, &buff);

    char *encoded_data = (char *)malloc(data_length + 1);
    memcpy(encoded_data, buff, data_length);
    encoded_data[data_length] = '\0';

    *out_len = (int)data_length;

    BIO_free_all(b64);

    return (unsigned char *)encoded_data;
}

void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4])
{
    unsigned int i;
    uint32_t v0 = v[0], v1 = v[1], sum = 0, delta = 0x9E3779B9;
    for (i = 0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }
    v[0] = v0;
    v[1] = v1;
}

int main(int argc, char *argv[])
{
    char flag[32] = "flag{ReADiNg_AsM_aiNt_thAT_HarD}";
    char *key_str = "shELlnEverDaNCEwiThUsagAIN";

    uint32_t key[4];
    memcpy(key, key_str, 16);

    int num_rounds = 32;
    size_t i;
    uint32_t v[2] = {0, 0};

    for (i = 0; i < 32; i += 8) {
        memcpy(&v[0], flag + i, 4);
        memcpy(&v[1], flag + i + 4, 4);
        encipher(num_rounds, v, key);
        memcpy(flag + i, &v[0], 4);
        memcpy(flag + i + 4, &v[1], 4);
    }

    int out_len;
    unsigned char *encoded =
        base64_encode((const unsigned char *)flag, 32, &out_len);
    printf("Encrypted flag: %s\n", encoded);

    free(encoded);

    return 0;
}
