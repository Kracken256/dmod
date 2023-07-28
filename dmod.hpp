#pragma once

#include <cstdint>
#include <vector>
#include <map>
#include <string>


typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

struct dmod_preamble
{
    u64 magic;
    u16 version;
    u32 checksum;
} __attribute__((packed));

struct dmod_metadata_item
{
    u32 index;
    u16 keysize;
    u16 valuesize;

    u8 *key;
    u8 *value;
} __attribute__((packed));

struct dmod_metadata
{
    u32 magic;
    u16 flags;
    u32 length;
    u64 offset;
    u32 checksum;
} __attribute__((packed));

struct dmod_crypto
{
    u32 magic;
    u16 sym_cipher_algo;
    u16 digest_algo;
    u8 cipher_data[64];
    u8 digital_signature[64];
    u8 public_key[32];
    u64 x509_certificate_offset;
    u32 checksum;
} __attribute__((packed));

struct dmod_entry
{
    u32 symbols_count;
    u64 symbols_entry_offset;
    u64 text_entry_offset;
} __attribute__((packed));

struct dmod_header
{
    // PREAMBLE
    struct dmod_preamble preamble;

    // METADATA
    struct dmod_metadata metadata;

    // CRYPTO
    struct dmod_crypto crypto;

    // ENTRY
    struct dmod_entry entry;

    // EXPANSION
    u8 reserved[272];

    // CHECKSUM
    u32 checksum;
} __attribute__((packed));

struct dmod_maker_ctx
{
    struct dmod_header *header;
    u32 metadata_offset;
    u32 crypto_offset;
    u32 entry_offset;
    u32 text_offset;
    u8 enc_key[32];
    u8 iv[16];

    u32 metadata_count;

    // List
    std::vector<dmod_metadata_item> metadata;
};

enum DMOD_CIPHER
{
    DMOD_CIPHER_NONE = 0,
    DMOD_CIPHER_AES_128_CTR = 0x001,
    DMOD_CIPHER_AES_256_CTR = 0x002,
    DMOD_CIPHER_CHACHA20 = 0x003,
};

enum DMOD_COMPRESSOR {
    DMOD_COMPRESSOR_NONE = 0,
    DMOD_COMPRESSOR_ZLIB = 0x001,
    DMOD_COMPRESSOR_LZMA = 0x002,
    DMOD_COMPRESSOR_LZ4 = 0x003,
    DMOD_COMPRESSOR_LZ4HC = 0x004,
    DMOD_COMPRESSOR_ZSTD = 0x005,
};

#define DMOD_HEADER_SIZE sizeof(struct dmod_header)
#define DMOD_PREAMBLE_SIZE sizeof(struct dmod_preamble)
#define DMOD_METADATA_SIZE sizeof(struct dmod_metadata)
#define DMOD_CRYPTO_SIZE sizeof(struct dmod_crypto)
#define DMOD_ENTRY_SIZE sizeof(struct dmod_entry)

#define DMOD_PREAMBLE_MAGIC 0x4a572f444f4d447f
#define DMOD_METADATA_MAGIC 0x4a7dccf1
#define DMOD_CRYPTO_MAGIC 0xbe54970e

#define DMOD_VERSION 0x0001

#define DMOD_METADATA_COMPRESS_MASK 0x000f
#define DMOD_METADATA_FLAG_NONE 0x0000
#define DMOD_METADATA_COMPRESS_ALGO_ZLIB 0x0001
#define DMOD_METADATA_COMPRESS_ALGO_LZMA 0x0002
#define DMOD_METADATA_COMPRESS_ALGO_LZ4 0x0003
#define DMOD_METADATA_COMPRESS_ALGO_LZ4HC 0x0004
#define DMOD_METADATA_COMPRESS_ALGO_ZSTD 0x0005
#define DMOD_METADATA_ENCRYPT 0x0010

#define DMOD_SYM_CIPHER_ALGO_NONE 0x0000
#define DMOD_SYM_CIPHER_ALGO_AES_128 0x0001
#define DMOD_SYM_CIPHER_ALGO_AES_256 0x0002
#define DMOD_SYM_CIPHER_ALGO_CHACHA20 0x0003

#define DMOD_DIGEST_ALGO_NONE 0x0000
#define DMOD_DIGEST_ALGO_SHA_256 0x0001
#define DMOD_DIGEST_ALGO_SHA_3_256 0x0002

#define DMOD_SYM_CIPHER_KEY_SIZE 32

void dmod_lib_init();

u32 dmod_check32(const void *data, u32 n_bytes);

u32 dmod_preamble_checksum(const struct dmod_header *header);

u32 dmod_metadata_checksum(const struct dmod_metadata *data);

u32 dmod_crypto_checksum(const struct dmod_crypto *data);

u32 dmod_header_checksum(const struct dmod_header *header);

int dmod_verify_header(const struct dmod_header *header);

int dmod_verify_header_signature(const struct dmod_header *header);

void dmod_header_init(struct dmod_header *header);

void dmod_header_final(struct dmod_header *header);

void dmod_add_metadata(struct dmod_maker_ctx *ctx, std::string key, std::string value);

void dmod_write(struct dmod_maker_ctx *ctx, std::string path);

void dmod_set_cipher(struct dmod_maker_ctx *ctx, DMOD_CIPHER cipher);

void dmod_ctx_init(struct dmod_maker_ctx *ctx);

void dmod_ctx_free(struct dmod_maker_ctx *ctx);

void dmod_set_key(struct dmod_maker_ctx *ctx, const u8 *key);

void dmod_set_iv(struct dmod_maker_ctx *ctx, const u8 *iv);

void dmod_set_metadata_flags(struct dmod_maker_ctx *ctx, u16 flags);


