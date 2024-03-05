#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>

#define FAKE_INVALID_JUMP_A \
    __asm__ volatile(       \
        "jz 0f\n"           \
        "jnz 0f\n"          \
        ".byte 0xE8\n"      \
        "0:\n"              \
    );

#define FAKE_INVALID_JUMP_B \
    __asm__ volatile(       \
        "cmp $0x2, %rbp\n"  \
        "jne 0f\n"          \
        ".byte 0xE9\n"      \
        "0:\n"              \
    );

#define FAKE_CALL            \
    __asm__ volatile(        \
        "call 0f\n"          \
        "0:\n"               \
        "movq $1f, (%rsp)\n" \
        "ret\n"              \
        "1:\n"               \
    );

#define RETURN(x)            \
    {                        \
        FAKE_INVALID_JUMP_B; \
        return x;            \
    }

// allocate space for the xor key
// data in this memory will be used as
//   - the message xor key
//   - the AES 256 IV, and
//   - the XTEA key for decrypting the AES 256 key
unsigned char MESSAGE_XOR_KEY[59];

void decrypt_message_xor_key()
{
    // decrypt the xor key
    // this is used both as the message decryption key and the AES 256 IV
    // shELlnEverDaNCEwiThUsagAIN
    if (MESSAGE_XOR_KEY[0] == 0) {
        long long index = 0;
        MESSAGE_XOR_KEY[index] = 0x8d;

        __asm__ volatile(
            "xorq %%rcx, %%rcx\n"
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0x96;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0xbb;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0xb2;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0x92;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0x90;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0xbb;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0x88;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0x9b;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0x8c;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0xba;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0x9f;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0xb0;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0xbd;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0xbb;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0x89;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0x97;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0xaa;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0x96;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0xab;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0x8d;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0x9f;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0x99;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0xbf;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0xb7;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        MESSAGE_XOR_KEY[index] = 0xb0;

        __asm__ volatile(
            ".byte 0xEB, 0xFF, 0xC1\n"
            "movq %%rcx, %0\n"
            : "=r"(index)
            :
            : "rcx"
        );

        // xor each byte with 0xFE
        for (int i = 0; i < 27; i++) {
            MESSAGE_XOR_KEY[i] ^= 0xFE;
        }
        MESSAGE_XOR_KEY[index] = '\0';
    }
}

/**
 * @brief decode a base64 encoded string
 *
 * @param[in] input the base64 string to decode
 * @param[in] length length of the input string
 * @param[out] out_len length of the decoded content
 */
unsigned char *base64_decode_type_a(const char *input, int length, int *out_len)
{
    FAKE_CALL;

    BIO *b64, *bmem;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf((void *)input, length);
    bmem = BIO_push(b64, bmem);

    // calculate the decoded content length
    size_t decoded_length = length * 3 / 4;
    unsigned char *buffer = (unsigned char *)malloc(decoded_length + 1);
    if (!buffer) {
        BIO_free_all(bmem);
        RETURN(NULL);
    }

    // decode the content
    int decoded_size = BIO_read(bmem, buffer, length);
    if (decoded_size < 0) {
        free(buffer);
        BIO_free_all(bmem);
        RETURN(NULL);
    }

    // null-terminate the buffer
    buffer[decoded_size] = '\0';
    *out_len = decoded_size;

    BIO_free_all(bmem);

    RETURN(buffer);
}

/**
 * @brief decrypt and print a message
 *
 * @param[in] message the message to decrypt and print
 */
void decrypt_print(const char *message)
{
    FAKE_CALL;
    decrypt_message_xor_key();

    int xor_key_len = strlen((const char *)MESSAGE_XOR_KEY);

    int message_length = 0;
    unsigned char *decrypted_message =
        base64_decode_type_a(message, strlen(message), &message_length);

    for (int i = 0; i < message_length; i++) {
        decrypted_message[i] ^= MESSAGE_XOR_KEY[i % xor_key_len];
    }

    write(STDOUT_FILENO, decrypted_message, message_length);

    free(decrypted_message);
}

/**
 * @brief handle encryption errors
 *
 * @param[in] message error message
 * @param[in] ctx encryption context
 * @param[in] plaintext decrypted content
 * @return 1
 */
static int
handle_encryption_errors(EVP_CIPHER_CTX *ctx, unsigned char **plaintext)
{
    FAKE_CALL;
    FAKE_INVALID_JUMP_B;

    if (plaintext && *plaintext) {
        free(*plaintext);
        *plaintext = NULL;
    }
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }

    RETURN(1);
}

/**
 * @brief decrypt a message using XTEA
 *
 * @param[in] num_rounds the number of encryption rounds
 */
void xtea_decipher(
    unsigned int num_rounds,
    uint32_t v[2],
    uint32_t const key[4]
)
{
    FAKE_CALL;
    FAKE_INVALID_JUMP_A;

    unsigned int i;
    uint32_t v0 = v[0], v1 = v[1], delta = 0x9E3779B9, sum = delta * num_rounds;
    for (i = 0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0] = v0;
    v[1] = v1;
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
    unsigned char **plaintext,
    int *plaintext_len
)
{
    FAKE_CALL;

    // decrypt the AES 256 key using XTEA and append it to the xor key
    // key: "flag{ReADiNg_AsM_aiNt_thAT_HarD}"
    int index = 0;
    char encoded_encrypted_data[45];
    encoded_encrypted_data[index] = 'i';
    index++;
    encoded_encrypted_data[index] = 'e';
    index++;
    encoded_encrypted_data[index] = 'n';
    index++;
    encoded_encrypted_data[index] = 'l';
    index++;
    encoded_encrypted_data[index] = 'Z';
    index++;
    encoded_encrypted_data[index] = 'I';
    index++;
    encoded_encrypted_data[index] = '2';
    index++;
    encoded_encrypted_data[index] = 'O';
    index++;
    encoded_encrypted_data[index] = 'P';
    index++;
    encoded_encrypted_data[index] = 'W';
    index++;
    encoded_encrypted_data[index] = 'T';
    index++;
    encoded_encrypted_data[index] = '4';
    index++;
    encoded_encrypted_data[index] = 's';
    index++;
    encoded_encrypted_data[index] = 'n';
    index++;
    encoded_encrypted_data[index] = 'c';
    index++;
    encoded_encrypted_data[index] = 'V';
    index++;
    encoded_encrypted_data[index] = 'n';
    index++;
    encoded_encrypted_data[index] = '1';
    index++;
    encoded_encrypted_data[index] = '/';
    index++;
    encoded_encrypted_data[index] = 'z';
    index++;
    encoded_encrypted_data[index] = '1';
    index++;
    encoded_encrypted_data[index] = 'B';
    index++;
    encoded_encrypted_data[index] = '7';
    index++;
    encoded_encrypted_data[index] = 'H';
    index++;
    encoded_encrypted_data[index] = 'd';
    index++;
    encoded_encrypted_data[index] = 'p';
    index++;
    encoded_encrypted_data[index] = 'M';
    index++;
    encoded_encrypted_data[index] = 'E';
    index++;
    encoded_encrypted_data[index] = 'N';
    index++;
    encoded_encrypted_data[index] = 'E';
    index++;
    encoded_encrypted_data[index] = 'E';
    index++;
    encoded_encrypted_data[index] = 'n';
    index++;
    encoded_encrypted_data[index] = 'F';
    index++;
    encoded_encrypted_data[index] = 'U';
    index++;
    encoded_encrypted_data[index] = 't';
    index++;
    encoded_encrypted_data[index] = 'x';
    index++;
    encoded_encrypted_data[index] = 'M';
    index++;
    encoded_encrypted_data[index] = 'x';
    index++;
    encoded_encrypted_data[index] = '4';
    index++;
    encoded_encrypted_data[index] = '3';
    index++;
    encoded_encrypted_data[index] = 'k';
    index++;
    encoded_encrypted_data[index] = 'B';
    index++;
    encoded_encrypted_data[index] = 's';
    index++;
    encoded_encrypted_data[index] = '=';
    index++;
    encoded_encrypted_data[index] = '\0';

    // copy 16 bytes of the xor key as the XTEA key
    uint32_t key[4];
    memcpy(key, MESSAGE_XOR_KEY, 16);

    // decode the encrypted flag data
    int out_len = 0;
    unsigned char *decoded_data = base64_decode_type_a(
        encoded_encrypted_data, strlen(encoded_encrypted_data), &out_len
    );

    // decrypt the flag data using XTEA
    for (int i = 0; i < out_len; i += 8) {
        uint32_t *v = (uint32_t *)(decoded_data + i);
        xtea_decipher(32, v, key);
    }

    // append the decoded flag data to the xor key
    memcpy(MESSAGE_XOR_KEY + 26, decoded_data, 32);
    free(decoded_data);

    FAKE_INVALID_JUMP_A;

    if (ciphertext_len <= 0) {
        RETURN(1);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int temp_len = 0;

    if (!ctx)
        RETURN(handle_encryption_errors(NULL, NULL));

    *plaintext = (unsigned char *)malloc(ciphertext_len);
    if (!*plaintext) {
        RETURN(handle_encryption_errors(ctx, NULL));
    }

    volatile EVP_CIPHER *cipher = (EVP_CIPHER *)EVP_aes_128_cfb1();
    cipher = (EVP_CIPHER *)EVP_aes_128_cfb8();
    cipher = (EVP_CIPHER *)EVP_aes_128_cfb128();
    cipher = (EVP_CIPHER *)EVP_aes_128_cfb();
    cipher = (EVP_CIPHER *)EVP_aes_128_ofb();
    cipher = (EVP_CIPHER *)EVP_aes_128_ctr();
    cipher = (EVP_CIPHER *)EVP_aes_128_gcm();
    cipher = (EVP_CIPHER *)EVP_aes_128_ccm();
    cipher = (EVP_CIPHER *)EVP_aes_128_xts();
    cipher = (EVP_CIPHER *)EVP_aes_128_wrap();
    cipher = (EVP_CIPHER *)EVP_aes_128_ecb();
    cipher = (EVP_CIPHER *)EVP_aes_128_cbc();
    cipher = (EVP_CIPHER *)EVP_aes_128_cbc_hmac_sha1();
    cipher = (EVP_CIPHER *)EVP_aes_128_cbc_hmac_sha256();
    cipher = (EVP_CIPHER *)EVP_aes_256_cbc();

    if (1 != EVP_DecryptInit_ex(
                 ctx,
                 (const EVP_CIPHER *)cipher,
                 NULL,
                 MESSAGE_XOR_KEY + 26,
                 MESSAGE_XOR_KEY
             )) {
        RETURN(handle_encryption_errors(ctx, plaintext));
    }

    __asm__ volatile(
        "cmp $0, %0\n"
        "jz 0f\n"
        "call base64_decode_type_a\n"
        "0:\n"
        :
        : "r"(temp_len)
    );

    if (1 != EVP_DecryptUpdate(
                 ctx, *plaintext, plaintext_len, ciphertext, ciphertext_len
             )) {
        RETURN(handle_encryption_errors(ctx, plaintext));
    }

    if (1 != EVP_DecryptFinal_ex(ctx, *plaintext + *plaintext_len, &temp_len)) {
        RETURN(handle_encryption_errors(ctx, plaintext));
    }
    *plaintext_len += temp_len;

    EVP_CIPHER_CTX_free(ctx);
    RETURN(0);
}

/**
 * @brief decode a base64 encoded string
 *
 * @param[in] input the base64 string to decode
 * @param[in] length length of the input string
 * @param[out] out_len length of the decoded content
 */
unsigned char *base64_decode_type_b(const char *input, int length, int *out_len)
{
    FAKE_CALL;
    FAKE_INVALID_JUMP_B;

    BIO *b64, *bmem;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf((void *)input, length);
    bmem = BIO_push(b64, bmem);

    // calculate the decoded content length
    size_t decoded_length = length * 3 / 4;
    unsigned char *buffer = (unsigned char *)malloc(decoded_length + 1);
    if (!buffer) {
        BIO_free_all(bmem);
        RETURN(NULL);
    }

    // decode the content
    int decoded_size = BIO_read(bmem, buffer, length);
    if (decoded_size < 0) {
        free(buffer);
        BIO_free_all(bmem);
        RETURN(NULL);
    }

    // null-terminate the buffer
    buffer[decoded_size] = '\0';
    *out_len = decoded_size;

    BIO_free_all(bmem);

    decrypt_message_xor_key();
    RETURN(buffer);
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
)
{
    FAKE_CALL;
    FAKE_INVALID_JUMP_A;

    EVP_MD_CTX *mdctx;
    unsigned int output_len;

    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
        RETURN(1);
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(mdctx);
        RETURN(1);
    }

    if (1 != EVP_DigestUpdate(mdctx, data, data_len)) {
        EVP_MD_CTX_free(mdctx);
        RETURN(1);
    }

    if (1 != EVP_DigestFinal_ex(mdctx, output, &output_len)) {
        EVP_MD_CTX_free(mdctx);
        RETURN(1);
    }

    EVP_MD_CTX_free(mdctx);
    RETURN(0);
}

/**
 * @brief decode a base64 encoded string
 *
 * @param[in] input the base64 string to decode
 * @param[in] length length of the input string
 * @param[out] out_len length of the decoded content
 */
unsigned char *base64_decode_type_c(const char *input, int length, int *out_len)
{
    FAKE_CALL;
    FAKE_INVALID_JUMP_B;

    BIO *b64, *bmem;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf((void *)input, length);
    bmem = BIO_push(b64, bmem);

    // calculate the decoded content length
    size_t decoded_length = length * 3 / 4;
    unsigned char *buffer = (unsigned char *)malloc(decoded_length + 1);
    if (!buffer) {
        BIO_free_all(bmem);
        RETURN(NULL);
    }

    // decode the content
    int decoded_size = BIO_read(bmem, buffer, length);
    if (decoded_size < 0) {
        free(buffer);
        BIO_free_all(bmem);
        RETURN(NULL);
    }

    // null-terminate the buffer
    buffer[decoded_size] = '\0';
    *out_len = decoded_size;

    BIO_free_all(bmem);

    RETURN(buffer);
}

/**
 * @brief validate a token
 *
 * @param[in] name the base64-encoded name
 * @param[in] signature the base64-encoded encrypted signature
 * @return 0 if the token is valid, 1 otherwise
 */
int validate(const char *name, const char *signature)
{
    FAKE_CALL;
    FAKE_INVALID_JUMP_B;

    // base64 decode the token
    int token_len = 0;
    unsigned char *decoded_token =
        base64_decode_type_b(name, strlen(name), &token_len);

    // base64 decode the signature
    int signature_len = 0;
    unsigned char *decoded_signature =
        base64_decode_type_c(signature, strlen(signature), &signature_len);

    // decrypt the signature
    unsigned char *decrypted_signature =
        (unsigned char *)malloc(SHA256_DIGEST_LENGTH);
    if (!decrypted_signature) {
        // memory allocation failed for decrypted signature
        RETURN(2);
    }
    int decrypted_signature_len;
    int decryption_result = aes_256_cbc_decrypt(
        (unsigned char *)decoded_signature,
        signature_len,
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
        result = 0;
    } else {
        result = 1;
    }

    free(decoded_token);
    free(decoded_signature);
    free(decrypted_signature);

    RETURN(result);
}

int main(int argc, char **argv)
{
    // special fake call for entry point
    __asm__ volatile(
        "movq $0f, %rax\n"
        ".byte 0xEB, 0xFF, 0xC0\n"
        "call *%rax\n"
        "ret\n"
        "cmp $0x2, %rax\n"
        "je base64_decode_type_b\n"
        "jmp validate\n"
        ".byte 0xE8\n"
        "0:\n"
        ".byte 0xE9\n"
        "movq $1f, (%rsp)\n"
        "ret\n"
        "1:\n"
        "cmp $0x2, %rax\n"
        "jne 2f\n"
        ".byte 0xE8\n"
        "2:\n"
    );

    int ptrace_request = 16;

    // break linear disassembly
    FAKE_INVALID_JUMP_A;
    FAKE_CALL;
    FAKE_INVALID_JUMP_B;

    __asm__(
        "xor %%eax, %%eax\n"
        "mov %%eax, %0\n"
        : "=r"(ptrace_request)
        :
        : "rax"
    );

    // the index is declared once for all messages
    // since only one message will be printed
    int index = 0;

    if (argc != 2) {
        // encrypted string: "Usage: ./validate [token]\n"
        char message[37];
        message[index] = 'J';
        index++;
        message[index] = 'h';
        index++;
        message[index] = 's';
        index++;
        message[index] = 'k';
        index++;
        message[index] = 'K';
        index++;
        message[index] = 'w';
        index++;
        message[index] = 'l';
        index++;
        message[index] = 'U';
        index++;
        message[index] = 'Z';
        index++;
        message[index] = 'V';
        index++;
        message[index] = 'h';
        index++;
        message[index] = 'K';
        index++;
        message[index] = 'B';
        index++;
        message[index] = 'C';
        index++;
        message[index] = 'U';
        index++;
        message[index] = 'N';
        index++;
        message[index] = 'J';
        index++;
        message[index] = 'y';
        index++;
        message[index] = 'c';
        index++;
        message[index] = 'k';
        index++;
        message[index] = 'A';
        index++;
        message[index] = 'w';
        index++;
        message[index] = 'x';
        index++;
        message[index] = '0';
        index++;
        message[index] = 'M';
        index++;
        message[index] = 'y';
        index++;
        message[index] = 'E';
        index++;
        message[index] = 'c';
        index++;
        message[index] = 'C';
        index++;
        message[index] = 'g';
        index++;
        message[index] = 'I';
        index++;
        message[index] = 'v';
        index++;
        message[index] = 'F';
        index++;
        message[index] = 'E';
        index++;
        message[index] = 'Q';
        index++;
        message[index] = '=';
        index++;
        message[index] = '\0';
        decrypt_print(message);
        RETURN(1);
    }

    // detect debugger and sabotage the stack
    long ptrace_result = ptrace(ptrace_request, ptrace_request, NULL, NULL);
    if (ptrace_result == -1) {
        __asm__ volatile("dec %rsp\n");
    }
    ptrace(ptrace_request + 17, ptrace_request, 1, ptrace_request);

    // split the input into token and signature
    char *token = argv[1];
    char *name = strtok(token, ".");
    char *signature = strtok(NULL, ".");

    if (!name || !signature) {
        // encrypted string: "Invalid token format.\n"
        char message[33];
        message[index] = 'O';
        index++;
        message[index] = 'g';
        index++;
        message[index] = 'Y';
        index++;
        message[index] = 'z';
        index++;
        message[index] = 'L';
        index++;
        message[index] = 'Q';
        index++;
        message[index] = 'A';
        index++;
        message[index] = 'H';
        index++;
        message[index] = 'I';
        index++;
        message[index] = 'V';
        index++;
        message[index] = 'Y';
        index++;
        message[index] = 'R';
        index++;
        message[index] = 'H';
        index++;
        message[index] = 'S';
        index++;
        message[index] = '8';
        index++;
        message[index] = 'E';
        index++;
        message[index] = 'I';
        index++;
        message[index] = 'G';
        index++;
        message[index] = 'M';
        index++;
        message[index] = 'j';
        index++;
        message[index] = 'G';
        index++;
        message[index] = 'B';
        index++;
        message[index] = 's';
        index++;
        message[index] = '5';
        index++;
        message[index] = 'C';
        index++;
        message[index] = 'S';
        index++;
        message[index] = 'F';
        index++;
        message[index] = 'd';
        index++;
        message[index] = 'a';
        index++;
        message[index] = 'w';
        index++;
        message[index] = '=';
        index++;
        message[index] = '=';
        index++;
        message[index] = '\0';
        decrypt_print(message);
        RETURN(1);
    }

    int result = validate(name, signature);

    char message[60];
    // encrypted string: "The token is valid.\n"
    message[index] = 'J';
    index++;
    message[index] = 'w';
    index++;
    message[index] = 'A';
    index++;
    message[index] = 'g';
    index++;
    message[index] = 'b';
    index++;
    message[index] = 'B';
    index++;
    message[index] = 'g';
    index++;
    message[index] = 'B';
    index++;
    message[index] = 'L';
    index++;
    message[index] = 'h';
    index++;
    message[index] = 'M';
    index++;
    message[index] = 'L';
    index++;
    message[index] = 'U';
    index++;
    message[index] = 'i';
    index++;
    message[index] = '0';
    index++;
    message[index] = 'S';
    index++;
    message[index] = 'b';
    index++;
    message[index] = 'j';
    index++;
    message[index] = 'U';
    index++;
    message[index] = 'k';
    index++;
    message[index] = 'G';
    index++;
    message[index] = 'w';
    index++;
    message[index] = 'A';
    index++;
    message[index] = 'w';
    index++;
    message[index] = 'R';
    index++;
    message[index] = 'l';
    index++;
    message[index] = '8';
    index++;
    message[index] = '=';
    index++;
    message[index] = '\0';
    index++;

    // encrypted string: "The token is invalid.\n"
    message[index] = 'J';
    index++;
    message[index] = 'w';
    index++;
    message[index] = 'A';
    index++;
    message[index] = 'g';
    index++;
    message[index] = 'b';
    index++;
    message[index] = 'B';
    index++;
    message[index] = 'g';
    index++;
    message[index] = 'B';
    index++;
    message[index] = 'L';
    index++;
    message[index] = 'h';
    index++;
    message[index] = 'M';
    index++;
    message[index] = 'L';
    index++;
    message[index] = 'U';
    index++;
    message[index] = 'i';
    index++;
    message[index] = '0';
    index++;
    message[index] = 'S';
    index++;
    message[index] = 'b';
    index++;
    message[index] = 'i';
    index++;
    message[index] = 'o';
    index++;
    message[index] = 'r';
    index++;
    message[index] = 'A';
    index++;
    message[index] = 'Q';
    index++;
    message[index] = 'g';
    index++;
    message[index] = '4';
    index++;
    message[index] = 'A';
    index++;
    message[index] = 'T';
    index++;
    message[index] = 'F';
    index++;
    message[index] = 'd';
    index++;
    message[index] = 'a';
    index++;
    message[index] = 'w';
    index++;
    message[index] = '=';
    index++;
    message[index] = '=';
    index++;
    message[index] = '\0';

    decrypt_print(message + (result == 1) * 29);

    RETURN(result);
}
