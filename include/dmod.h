#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif
    struct dmod_preamble
    {
        uint64_t magic;
        uint16_t version;
        uint32_t checksum;
    } __attribute__((packed));

    struct dmod_data_item
    {
        uint64_t keysize;
        uint64_t valuesize;

        uint8_t *key;
        uint8_t *value;
    } __attribute__((packed));

    struct dmod_data
    {
        uint32_t magic;
        uint64_t flags;
        uint64_t count;
        uint64_t length;
        uint64_t offset;
        uint32_t checksum;
    } __attribute__((packed));

    struct dmod_crypto
    {
        uint32_t magic;
        uint16_t sym_cipher_algo;
        uint16_t digest_algo;
        uint8_t password_checksum[3];
        uint8_t iv[16];
        uint8_t digital_signature[64];
        uint8_t public_key[32];
        uint64_t x509_certificate_offset;
        uint32_t checksum;
    } __attribute__((packed));

    struct dmod_header
    {
        // PREAMBLE
        struct dmod_preamble preamble;

        // DATA
        struct dmod_data data;

        // CRYPTO
        struct dmod_crypto crypto;

        // EXPANSION
        uint8_t reserved[256 - (sizeof(struct dmod_preamble) + sizeof(struct dmod_data) + sizeof(struct dmod_crypto) + 4)];

        // CHECKSUM
        uint32_t checksum;
    } __attribute__((packed));

    struct dmod_content_ctx
    {
        struct dmod_header *header;
        uint32_t data_offset;
        uint32_t crypto_offset;
        uint32_t entry_offset;
        uint32_t text_offset;
        uint8_t enc_key[32];

        uint32_t data_count;
        void *pkey_ptr;

        // List
        struct dmod_data_item *data_list;
    };

    enum DMOD_CIPHER
    {
        DMOD_CIPHER_NONE = 0,
        DMOD_CIPHER_AES_128_CTR = 0x001,
        DMOD_CIPHER_AES_256_CTR = 0x002,
        DMOD_CIPHER_CHACHA20 = 0x003,
    };

    enum DMOD_COMPRESSOR
    {
        DMOD_COMPRESSOR_NONE = 0,
        DMOD_COMPRESSOR_ZLIB = 0x001,
        DMOD_COMPRESSOR_LZMA = 0x002,
        DMOD_COMPRESSOR_LZ4 = 0x003,
        DMOD_COMPRESSOR_LZ4HC = 0x004,
        DMOD_COMPRESSOR_ZSTD = 0x005,
    };

#define DMOD_VERSION 0x0002

#define DMOD_HEADER_SIZE sizeof(struct dmod_header)
#define DMOD_PREAMBLE_SIZE sizeof(struct dmod_preamble)
#define DMOD_DATA_SIZE sizeof(struct dmod_data)
#define DMOD_CRYPTO_SIZE sizeof(struct dmod_crypto)

#define DMOD_PREAMBLE_MAGIC 0x4a572f444f4d447f
#define DMOD_DATA_MAGIC 0x4a7dccf1
#define DMOD_CRYPTO_MAGIC 0xbe54970e

#define DMOD_DATA_COMPRESS_MASK 0x000f
#define DMOD_DATA_FLAG_NONE 0x0000
#define DMOD_DATA_COMPRESS_ALGO_ZLIB 0x0001
#define DMOD_DATA_COMPRESS_ALGO_LZMA 0x0002
#define DMOD_DATA_COMPRESS_ALGO_LZ4 0x0003
#define DMOD_DATA_COMPRESS_ALGO_LZ4HC 0x0004
#define DMOD_DATA_COMPRESS_ALGO_ZSTD 0x0005
#define DMOD_DATA_ENCRYPT 0x0010

#define DMOD_SYM_CIPHER_ALGO_NONE 0x0000
#define DMOD_SYM_CIPHER_ALGO_AES_128 0x0001
#define DMOD_SYM_CIPHER_ALGO_AES_256 0x0002
#define DMOD_SYM_CIPHER_ALGO_CHACHA20 0x0003

#define DMOD_DIGEST_ALGO_NONE 0x0000
#define DMOD_DIGEST_ALGO_SHA_256 0x0001
#define DMOD_DIGEST_ALGO_SHA_3_256 0x0002

#define DMOD_SYM_CIPHER_KEY_SIZE 32

    /// @brief Initialize the library
    /// @return 0 on success, 1 on failure
    int dmod_lib_init(void);

    /// @brief Compute the checksum of the header preamble
    /// @param preamble DMOD header preamble to compute the checksum
    /// @return The 32 bit checksum of the header preamble
    uint32_t dmod_preamble_checksum(const struct dmod_preamble *preamble);

    /// @brief Compute the checksum of the data
    /// @param data DMOD data to compute the checksum
    /// @return The 32 bit checksum of the data
    uint32_t dmod_data_checksum(const struct dmod_data *data);

    /// @brief Compute the checksum of the crypto section
    /// @param data DMOD crypto section to compute the checksum
    /// @return The 32 bit checksum of the crypto section
    uint32_t dmod_crypto_checksum(const struct dmod_crypto *data);

    /// @brief Compute the checksum of the entire header
    /// @param header DMOD header to compute the checksum
    /// @return The 32 bit checksum of the header
    uint32_t dmod_header_checksum(const struct dmod_header *header);

    /// @brief Verify the header is valid
    /// @param header DMOD header to verify
    /// @return 0 if the header is valid, 1 otherwise
    int dmod_verify_header(const struct dmod_header *header);

    /// @brief Initialize a DMOD header with default values
    /// @param header DMOD header to initialize. Does not allocate
    void dmod_header_init(struct dmod_header *header);

    /// @brief Finalize a DMOD header by computing the checksums
    /// @param header DMOD header to finalize
    void dmod_header_final(struct dmod_header *header);

    /// @brief Add a data item to the data section
    /// @param ctx DMOD maker context
    /// @param key Metadata key
    /// @param key_size Metadata key size in bytes
    /// @param value Metadata value
    /// @param value_size Metadata value size in bytes
    /// @return 0 if the data item was added, 1 otherwise
    int dmod_add_data(struct dmod_content_ctx *ctx, const char *key, size_t key_size, const char *value, size_t value_size);

    /// @brief Write finalized DMOD module to a file
    /// @param ctx DMOD maker context
    /// @param path Path to write the DMOD module to
    /// @return 0 if the DMOD module was written, 1 otherwise
    int dmod_write(struct dmod_content_ctx *ctx, const char *path);

    /// @brief Read a DMOD module header. Does not verify the header
    /// @param header DMOD header to read
    /// @param path Path to the DMOD module
    /// @return 0 if the DMOD module header was read, 1 otherwise
    int dmod_read_header(struct dmod_header *header, const char *path);

    /// @brief Read a DMOD module data section (including all content)
    /// @param content malloc'd array of content items
    /// @param header DMOD header
    /// @param path Path to the DMOD module
    /// @param enc_key 32 byte encryption. If NULL, no decryption is performed
    /// @return 0 if the DMOD module data section was read, else > 0
    /// @note The caller is responsible for freeing the content array
    /// @note If compression is used, the content will be decompressed based on the header
    int dmod_read_data(struct dmod_data_item *content, dmod_header *header, const char *path, uint8_t *enc_key);

    /// @brief Read a DMOD module data item
    /// @param content DMOD data item to read
    /// @param header DMOD header
    /// @param path Path to the DMOD module
    /// @param key Data item key
    /// @param key_size Data item key size in bytes
    int dmod_read_data_item(struct dmod_data_item *content, dmod_header *header, const char *path, const char *key, size_t key_size);

    /// @brief Set the symetric stream cipher to use
    /// @param ctx DMOD maker context
    /// @param cipher Symetric stream cipher to use
    void dmod_set_cipher(struct dmod_content_ctx *ctx, DMOD_CIPHER cipher);

    /// @brief Initialize a DMOD maker context with default values
    /// @return A DMOD maker context
    struct dmod_content_ctx *dmod_ctx_new(void);

    /// @brief Free a DMOD maker context
    /// @param ctx DMOD maker context to free
    void dmod_ctx_free(struct dmod_content_ctx *ctx);

    /// @brief Set the symetric stream cipher key
    /// @param ctx DMOD maker context
    /// @param key 32 byte key
    void dmod_set_key(struct dmod_content_ctx *ctx, const uint8_t *key);

    /// @brief Set the symetric stream cipher nonce
    /// @param ctx DMOD maker context
    /// @param nonce 16 byte nonce (must be 16 bytes)
    void dmod_set_iv(struct dmod_content_ctx *ctx, const uint8_t *nonce);

    /// @brief Set the Ed25519 private key PEM file path
    /// @param ctx DMOD maker context
    /// @param path Path to the Ed25519 private key PEM file
    /// @return 0 if the Ed25519 private key PEM file was loaded, 1 otherwise
    int dmod_load_private_key_pem_file(struct dmod_content_ctx *ctx, const char *path);

    /// @brief Set the Ed25519 private key PEM
    /// @param ctx DMOD maker context
    /// @param pem NULL terminated string containing the Ed25519 private key PEM
    /// @return 0 if the Ed25519 private key PEM was loaded, 1 otherwise
    int dmod_load_private_key_pem(struct dmod_content_ctx *ctx, const char *pem);

    /// @brief Set a flag in the data section
    /// @param ctx DMOD maker context
    /// @param flags Flags to set
    void dmod_set_data_flags(struct dmod_content_ctx *ctx, uint16_t flags);

    /// @brief Verify a key matches the password checksum
    /// @param header DMOD header
    /// @param key Key to verify
    /// @param key_size Key size in bytes
    /// @return 0 if the key matches the password checksum, 1 otherwise
    int dmod_verify_password(const struct dmod_header *header, const uint8_t *key, size_t key_size);

    /// @brief Encrypt a buffer with a symetric stream cipher
    /// @param in Input buffer
    /// @param out Output buffer
    /// @param len Length of the input buffer
    /// @param key Symetric stream cipher key 32 bytes
    /// @param nonce Symetric stream cipher nonce 16 bytes
    /// @param type Symetric stream cipher type
    /// @return 0 if the buffer was encrypted, 1 otherwise
    int dmod_encrypt(const void *in, void *out, size_t len, const void *key, const void *nonce, DMOD_CIPHER type);

    /// @brief Decrypt a buffer with a symetric stream cipher
    /// @param in Input buffer
    /// @param out Output buffer
    /// @param len Length of the input buffer
    /// @param key Symetric stream cipher key 32 bytes
    /// @param nonce Symetric stream cipher nonce 16 bytes
    /// @param type Symetric stream cipher type
    /// @return 0 if the buffer was decrypted, 1 otherwise
    int dmod_decrypt(const void *in, void *out, size_t len, const void *key, const void *nonce, DMOD_CIPHER type);

    /// @brief Compress or decompress a buffer
    /// @param in Input buffer
    /// @param out Pointer to pointer to output buffer
    /// @param len Length of the input buffer
    /// @param outlen Pointer to store the length of the output buffer
    /// @param op Operation to perform 0 or 1. 0 is compress, 1 is decompress
    /// @param mode Compression mode
    /// @return 0 if the buffer was compressed or decompressed, 1 otherwise
    int xpress_buffer(const void *in, uint8_t **out, size_t len, size_t *outlen, int op, DMOD_COMPRESSOR mode);

    /// @brief Derive a 32 byte key from a password
    /// @param password Password to derive the key from
    /// @param len Length of the password
    /// @param outkey Pointer to store the derived 32 byte key
    void dmod_derive_key(const uint8_t *password, size_t len, uint8_t *outkey);

    /// @brief DMOD standard hash function
    /// @param in Input buffer
    /// @param len Length of the input buffer
    /// @param out 32 byte output buffer
    void dmod_hash(const void *in, size_t len, uint8_t *out);

#ifdef __cplusplus
}
#endif