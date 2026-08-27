#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

/**
 * @brief Encrypts the contents of a file using Blowfish in CBC mode.
 *
 * Reads data from the input file stream in fixed-size chunks, encrypts it
 * using the provided key and IV, and writes the resulting ciphertext to
 * the output file stream.
 *
 * @param in  Input file stream (plaintext), opened for reading in binary mode.
 * @param out Output file stream (ciphertext), opened for writing in binary mode.
 * @param key Encryption key (must match the key length expected by EVP_bf_cbc()).
 * @param iv  Initialization vector for CBC mode.
 *
 * @note Uses OpenSSL 3.x-style initialization (EVP_CipherInit_ex with key/iv
 *       passed directly), so there is no need to call EVP_CIPHER_CTX_set_key_length().
 * @note On error, the function prints a message and returns early, leaving
 *       the output file potentially incomplete.
 */
void encrypt(FILE *in, FILE *out, char* key, char* iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Error creating context\n");
        return;
    }

    EVP_CIPHER_CTX_reset(ctx);

    // Direct initialization for OpenSSL 3.x without using set_key_length
    if (EVP_CipherInit_ex(ctx, EVP_bf_cbc(), NULL, (unsigned char*)key, (unsigned char*)iv, 1) != 1) {
        printf("Error initializing encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    unsigned char in_buf[1024];
    unsigned char out_buf[1024 + EVP_MAX_BLOCK_LENGTH];
    int num_bytes_read, out_len;

    // Process the input file in chunks
    while ((num_bytes_read = fread(in_buf, 1, 1024, in)) > 0) {
        if (!EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf, num_bytes_read)) {
            EVP_CIPHER_CTX_free(ctx);
            return;
        }
        fwrite(out_buf, 1, out_len, out);
    }

    // Finalize encryption (handles final block/padding)
    if (!EVP_CipherFinal_ex(ctx, out_buf, &out_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    fwrite(out_buf, 1, out_len, out);

    EVP_CIPHER_CTX_free(ctx);
}

/**
 * @brief Decrypts the contents of a file using Blowfish in CBC mode.
 *
 * Reads ciphertext from the input file stream in fixed-size chunks, decrypts
 * it using the provided key and IV, and writes the resulting plaintext to
 * the output file stream.
 *
 * @param in  Input file stream (ciphertext), opened for reading in binary mode.
 * @param out Output file stream (plaintext), opened for writing in binary mode.
 * @param key Decryption key (must match the key used for encryption).
 * @param iv  Initialization vector used during encryption.
 *
 * @note Uses OpenSSL 3.x-style initialization (EVP_CipherInit_ex with key/iv
 *       passed directly).
 * @note On error, the function prints a message and returns early, leaving
 *       the output file potentially incomplete.
 */
void decrypt(FILE *in, FILE *out, char* key, char* iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Error creating context\n");
        return;
    }

    EVP_CIPHER_CTX_reset(ctx);

    // Decryption mode (last argument is 0)
    if (EVP_CipherInit_ex(ctx, EVP_bf_cbc(), NULL, (unsigned char*)key, (unsigned char*)iv, 0) != 1) {
        printf("Error initializing decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    unsigned char in_buf[1024];
    unsigned char out_buf[1024 + EVP_MAX_BLOCK_LENGTH];
    int num_bytes_read, out_len;

    // Process the input file in chunks
    while ((num_bytes_read = fread(in_buf, 1, 1024, in)) > 0) {
        if (!EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf, num_bytes_read)) {
            EVP_CIPHER_CTX_free(ctx);
            return;
        }
        fwrite(out_buf, 1, out_len, out);
    }

    // Finalize decryption (handles final block/padding removal)
    if (!EVP_CipherFinal_ex(ctx, out_buf, &out_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    fwrite(out_buf, 1, out_len, out);

    EVP_CIPHER_CTX_free(ctx);
}
