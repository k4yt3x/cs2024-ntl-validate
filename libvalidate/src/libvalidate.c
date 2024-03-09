#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief decode a base64 encoded string
 *
 * @param[in] input the base64 string to decode
 * @param[in] length length of the input string
 * @param[out] out_len length of the decoded content
 */
unsigned char *base64_decode(const char *input, int length, int *out_len) {
    BIO *b64, *bmem;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf((void *)input, length);
    bmem = BIO_push(b64, bmem);

    // calculate the decoded content length
    size_t decodeLen = length * 3 / 4;
    unsigned char *buffer = (unsigned char *)malloc(decodeLen + 1);
    if (!buffer) {
        BIO_free_all(bmem);
        return NULL;
    }

    // decode the content
    int decodedSize = BIO_read(bmem, buffer, length);
    if (decodedSize < 0) {
        free(buffer);
        BIO_free_all(bmem);
        return NULL;
    }

    // null-terminate the buffer
    buffer[decodedSize] = '\0';
    *out_len = decodedSize;

    BIO_free_all(bmem);
    return buffer;
}

/**
 * @brief handle encryption errors
 *
 * @param[in] message error message
 * @param[in] ctx encryption context
 * @param[in] plaintext decrypted content
 * @return 1
 */
static int handle_encryption_errors(
    const char *message,
    EVP_CIPHER_CTX *ctx,
    unsigned char **plaintext
) {
    if (plaintext && *plaintext) {
        free(*plaintext);
        *plaintext = NULL;
    }
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }

#ifdef DEBUG
    unsigned long err_code = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
    fprintf(stderr, "%s: %s\n", message, err_buf);
#endif

    return 1;
}

/**
 * @brief decrypt content using AES-256-CBC
 *
 * @param[in] ciphertext encrypted content
 * @param[in] ciphertext_len length of the encrypted content
 * @param[in] key encryption key
 * @param[in] iv initialization vector
 * @param[out] plaintext decrypted content
 * @param[out] plaintext_len length of the decrypted content
 * @return 0 on success, 1 on failure
 */
int aes_256_cbc_decrypt(
    unsigned char *ciphertext,
    int ciphertext_len,
    unsigned char *key,
    unsigned char *iv,
    unsigned char **plaintext,
    int *plaintext_len
) {
    if (ciphertext_len <= 0) {
        fprintf(stderr, "Invalid ciphertext length.\n");
        return 1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int temp_len = 0;

    if (!ctx)
        return handle_encryption_errors(
            "Failed to allocate memory for decryption context", NULL, NULL
        );

    *plaintext = (unsigned char *)malloc(ciphertext_len);
    if (!*plaintext) {
        return handle_encryption_errors("Malloc failed", ctx, NULL);
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        return handle_encryption_errors(
            "Error initializing decryption", ctx, plaintext
        );
    }

    if (1 != EVP_DecryptUpdate(
                 ctx, *plaintext, plaintext_len, ciphertext, ciphertext_len
             )) {
        return handle_encryption_errors(
            "Error decrypting data", ctx, plaintext
        );
    }

    if (1 != EVP_DecryptFinal_ex(ctx, *plaintext + *plaintext_len, &temp_len)) {
        return handle_encryption_errors(
            "Error finalizing decryption", ctx, plaintext
        );
    }
    *plaintext_len += temp_len;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/**
 * @brief compute the SHA256 hash of a given input
 *
 * @param[in] data input data
 * @param[in] data_len length of the input data
 * @param[out] output SHA256 hash
 * @return 0 on success, 1 on failure
 */
int sha256_hash(
    const unsigned char *data,
    size_t data_len,
    unsigned char output[SHA256_DIGEST_LENGTH]
) {
    EVP_MD_CTX *mdctx;
    unsigned int output_len;

    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
        return 1;
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(mdctx);
        return 1;
    }

    if (1 != EVP_DigestUpdate(mdctx, data, data_len)) {
        EVP_MD_CTX_free(mdctx);
        return 1;
    }

    if (1 != EVP_DigestFinal_ex(mdctx, output, &output_len)) {
        EVP_MD_CTX_free(mdctx);
        return 1;
    }

    EVP_MD_CTX_free(mdctx);
    return 0;
}

int validate_token(char *input) {
    // split the input into token and signature
    char *token = strtok(input, ".");
    char *signature = strtok(NULL, ".");

    if (!token || !signature) {
        return 0;
    }

    // base64 decode the token
    int token_len = 0;
    unsigned char *decoded_token =
        base64_decode(token, strlen(token), &token_len);

    // base64 decode the signature
    int signature_len = 0;
    unsigned char *decoded_signature =
        base64_decode(signature, strlen(signature), &signature_len);

    // decrypt the signature
    unsigned char *decrypted_signature =
        (unsigned char *)malloc(SHA256_DIGEST_LENGTH);
    if (!decrypted_signature) {
        fprintf(stderr, "Memory allocation failed for decrypted signature.\n");
        return -1;
    }
    int decrypted_signature_len;
    int decryption_result = aes_256_cbc_decrypt(
        (unsigned char *)decoded_signature,
        signature_len,
        (unsigned char *)"flag{ReADiNg_AsM_aiNt_thAT_HarD}",
        (unsigned char *)"shELlnEverDaNCEwiThUsagAIN",
        &decrypted_signature,
        &decrypted_signature_len
    );

    // compute SHA256 hash of the decoded token
    unsigned char hash[SHA256_DIGEST_LENGTH];
    int hash_result = sha256_hash(decoded_token, token_len, hash);

    // compare the decrypted signature with the hash
    int result;
    if (!decryption_result && !(hash_result) &&
        memcmp(decrypted_signature, hash, SHA256_DIGEST_LENGTH) == 0) {
#ifdef DEBUG
        printf("Signature is valid.\n");
#endif
        result = 1;
    } else {
#ifdef DEBUG
        printf("Signature is invalid.\n");
#endif
        result = 0;
    }

    free(decrypted_signature);
    free(decoded_token);

    return result;
}
