#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
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

void aes_256_cbc_encrypt(
    unsigned char *plaintext,
    size_t plaintext_len,
    unsigned char *key,
    unsigned char *iv,
    unsigned char **ciphertext,
    int *ciphertext_len
)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        unsigned long err_code = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        fprintf(stderr, "Error initializing encryption: %s\n", err_buf);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    *ciphertext = (unsigned char *)malloc(plaintext_len + EVP_MAX_BLOCK_LENGTH);
    if (!*ciphertext) {
        fprintf(stderr, "Malloc failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (!EVP_EncryptUpdate(
            ctx, *ciphertext, ciphertext_len, plaintext, plaintext_len
        )) {
        unsigned long err_code = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        fprintf(stderr, "Error encrypting data: %s\n", err_buf);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int temp_len;
    if (!EVP_EncryptFinal_ex(ctx, *ciphertext + *ciphertext_len, &temp_len)) {
        unsigned long err_code = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        fprintf(stderr, "Error finalizing encryption: %s\n", err_buf);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    *ciphertext_len += temp_len;
    EVP_CIPHER_CTX_free(ctx);
}

void sha256_hash(
    const unsigned char *data,
    size_t data_len,
    unsigned char output[SHA256_DIGEST_LENGTH]
)
{
    EVP_MD_CTX *mdctx;
    unsigned int output_len;

    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
        perror("EVP_MD_CTX_new failed");
        return;
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        perror("EVP_DigestInit_ex failed");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    if (1 != EVP_DigestUpdate(mdctx, data, data_len)) {
        perror("EVP_DigestUpdate failed");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    if (1 != EVP_DigestFinal_ex(mdctx, output, &output_len)) {
        perror("EVP_DigestFinal_ex failed");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_MD_CTX_free(mdctx);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <token>\n", argv[0]);
        return 1;
    }
    unsigned char *token = (unsigned char *)argv[1];

    unsigned char hash[SHA256_DIGEST_LENGTH];
    sha256_hash(token, strlen((char *)token), hash);

    unsigned char *encrypted_signature = NULL;
    int encrypted_len = 0;
    aes_256_cbc_encrypt(
        hash,
        SHA256_DIGEST_LENGTH,
        (unsigned char *)"flag{ReADiNg_AsM_aiNt_thAT_HarD}",
        (unsigned char *)"shELlnEverDaNCEwiThUsagAIN",
        &encrypted_signature,
        &encrypted_len
    );

    int token_encoded_len, signature_encoded_len;
    unsigned char *encoded_token =
        base64_encode(token, strlen((char *)token), &token_encoded_len);
    unsigned char *encoded_signature = base64_encode(
        encrypted_signature, encrypted_len, &signature_encoded_len
    );

    printf("Generated Token: %s.%s\n", encoded_token, encoded_signature);

    free(encrypted_signature);
    free(encoded_token);
    free(encoded_signature);

    return 0;
}
