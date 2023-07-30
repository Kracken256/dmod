#include <dmod.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <assert.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <zlib.h>

static uint32_t dmod_check32(const void *data, uint32_t n_bytes)
{
    uint8_t digest[16];

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    const EVP_MD *md = EVP_md5();

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, n_bytes);
    EVP_DigestFinal_ex(mdctx, digest, NULL);
    EVP_MD_CTX_free(mdctx);

    return *(uint32_t *)digest;
}

uint32_t dmod_preamble_checksum(const struct dmod_preamble *header)
{
    return dmod_check32(header, DMOD_PREAMBLE_SIZE - 4);
}

uint32_t dmod_metadata_checksum(const struct dmod_metadata *data)
{
    return dmod_check32(data, DMOD_METADATA_SIZE - 4);
}

uint32_t dmod_crypto_checksum(const struct dmod_crypto *data)
{
    return dmod_check32(data, DMOD_CRYPTO_SIZE - 4);
}

uint32_t dmod_header_checksum(const struct dmod_header *header)
{
    return dmod_check32(header, DMOD_HEADER_SIZE - 4);
}

void dmod_header_init(struct dmod_header *header)
{
    header->preamble.magic = DMOD_PREAMBLE_MAGIC;
    header->preamble.version = DMOD_VERSION;

    header->metadata.magic = DMOD_METADATA_MAGIC;
    header->metadata.flags = 0;
    header->metadata.count = 0;
    header->metadata.offset = 0;
    header->metadata.length = 0;

    header->crypto.magic = DMOD_CRYPTO_MAGIC;
    header->crypto.sym_cipher_algo = DMOD_SYM_CIPHER_ALGO_NONE;
    header->crypto.digest_algo = DMOD_DIGEST_ALGO_NONE;
    header->crypto.x509_certificate_offset = 0;
    memset(header->crypto.iv, 0, sizeof(header->crypto.iv));
    memset(header->crypto.digital_signature, 0, sizeof(header->crypto.digital_signature));
    memset(header->crypto.public_key, 0, sizeof(header->crypto.public_key));
    memset(header->crypto.password_checksum, 0, sizeof(header->crypto.password_checksum));

    header->entry.symbols_entry_offset = 0;
    header->entry.text_entry_offset = 0;

    memset(header->reserved, 0, sizeof(header->reserved));
}

void dmod_header_final(struct dmod_header *header)
{
    header->preamble.checksum = dmod_preamble_checksum(&header->preamble);
    header->metadata.checksum = dmod_metadata_checksum(&header->metadata);
    header->crypto.checksum = dmod_crypto_checksum(&header->crypto);
    header->checksum = dmod_header_checksum(header);
}

int dmod_add_metadata(dmod_maker_ctx *ctx, const char *key, size_t key_size, const char *value, size_t value_size)
{
    dmod_metadata_item item;
    item.key = nullptr;
    item.value = nullptr;
    item.keysize = key_size;
    item.valuesize = value_size;
    item.key = (uint8_t *)malloc(key_size);
    item.value = (uint8_t *)malloc(value_size);
    memcpy(item.key, key, key_size);
    memcpy(item.value, value, value_size);
    ctx->metadata_count++;

    ctx->metadata_list = (dmod_metadata_item *)realloc(ctx->metadata_list, ctx->metadata_count * sizeof(dmod_metadata_item));
    ctx->metadata_list[ctx->metadata_count - 1] = item;

    if (ctx->header->metadata.offset == 0)
    {
        ctx->header->metadata.offset = DMOD_HEADER_SIZE;
    }

    ctx->header->metadata.count = ctx->metadata_count;

    ctx->header->metadata.length += 16 + key_size + value_size;

    return 0;
}

int xpress_buffer(const void *in, uint8_t **out, size_t len, size_t *outlen, int op, DMOD_COMPRESSOR mode)
{
    if (mode == DMOD_COMPRESSOR_NONE)
    {
        *out = (uint8_t *)malloc(len);
        memcpy(*out, in, len);
        *outlen = len;
        return 0;
    }

    if (op != 0 && op != 1)
    {
        return 1;
    }

    if (!in || !out || !outlen)
    {
        return 1;
    }

    // Do compression
    if (op == 0)
    {
        if (mode == DMOD_COMPRESSOR_ZLIB)
        {
            std::vector<uint8_t> buffer;

            const size_t BUFSIZE = 4096;
            uint8_t temp_buffer[BUFSIZE];

            z_stream strm;
            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.next_in = (uint8_t *)in;
            strm.avail_in = len;
            strm.next_out = temp_buffer;
            strm.avail_out = BUFSIZE;

            deflateInit(&strm, Z_BEST_COMPRESSION);

            while (strm.avail_in != 0)
            {
                int res = deflate(&strm, Z_NO_FLUSH);
                if (res != Z_OK)
                {
                    // Handle error
                    deflateEnd(&strm);
                    return 1;
                }

                if (strm.avail_out == 0)
                {
                    buffer.insert(buffer.end(), temp_buffer, temp_buffer + BUFSIZE);
                    strm.next_out = temp_buffer;
                    strm.avail_out = BUFSIZE;
                }
            }

            int deflate_res = Z_OK;
            while (deflate_res == Z_OK)
            {
                if (strm.avail_out == 0)
                {
                    buffer.insert(buffer.end(), temp_buffer, temp_buffer + BUFSIZE);
                    strm.next_out = temp_buffer;
                    strm.avail_out = BUFSIZE;
                }
                deflate_res = deflate(&strm, Z_FINISH);
            }

            assert(deflate_res == Z_STREAM_END);
            buffer.insert(buffer.end(), temp_buffer, temp_buffer + BUFSIZE - strm.avail_out);
            deflateEnd(&strm);

            *out = (uint8_t *)malloc(buffer.size());
            memcpy(*out, buffer.data(), buffer.size());
            *outlen = buffer.size();
            return 0;
        }
        else
        {
            return 1;
        }
        return 0;
    }

    // Do decompression
    if (mode == DMOD_COMPRESSOR_ZLIB)
    {
        std::vector<uint8_t> out_buffer;
        z_stream strm;
        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.next_in = (uint8_t *)in;
        strm.avail_in = len;

        // Dynamic output buffer
        strm.next_out = NULL;
        strm.avail_out = 0;

        inflateInit(&strm);

        int res = Z_OK;
        while (res == Z_OK)
        {
            uint8_t buf[4096];
            strm.next_out = buf;
            strm.avail_out = sizeof(buf);

            res = inflate(&strm, Z_NO_FLUSH);
            assert(res != Z_STREAM_ERROR);

            switch (res)
            {
            case Z_NEED_DICT:
                res = Z_DATA_ERROR;
                break; // Prevent fall-through to Z_DATA_ERROR
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                inflateEnd(&strm);
                return 1;
            }

            size_t have = sizeof(buf) - strm.avail_out;
            out_buffer.insert(out_buffer.end(), buf, buf + have);
        }

        inflateEnd(&strm);

        // Allocate output buffer
        *out = (uint8_t *)malloc(out_buffer.size());
        memcpy(*out, out_buffer.data(), out_buffer.size());
        *outlen = out_buffer.size();
        return 0;
    }

    return 0;
}

int dmod_encrypt(const void *in, void *out, size_t len, const void *key, const void *nonce, DMOD_CIPHER type)
{
    if (type == DMOD_CIPHER_NONE)
    {
        memcpy(out, in, len);
        return 0;
    }

    if (!(type == DMOD_CIPHER_AES_128_CTR || type == DMOD_CIPHER_AES_256_CTR || type == DMOD_CIPHER_CHACHA20))
    {
        return 1;
    }

    EVP_CIPHER_CTX *ctx;
    int len_out = 0;
    int final_len_out = 0;

    EVP_CIPHER *cipher_type;

    switch (type)
    {
    case DMOD_CIPHER_AES_128_CTR:
        cipher_type = (EVP_CIPHER *)EVP_aes_128_ctr();
        break;
    case DMOD_CIPHER_AES_256_CTR:
        cipher_type = (EVP_CIPHER *)EVP_aes_256_ctr();
        break;
    case DMOD_CIPHER_CHACHA20:
        cipher_type = (EVP_CIPHER *)EVP_chacha20();
        break;
    default:
        return 1;
    }

    ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit(ctx, cipher_type, (const unsigned char *)key, (const unsigned char *)nonce);

    EVP_EncryptUpdate(ctx, (unsigned char *)out, &len_out, (const unsigned char *)in, len);

    EVP_EncryptFinal(ctx, (unsigned char *)out + len_out, &final_len_out);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int dmod_decrypt(const void *in, void *out, size_t len, const void *key, const void *nonce, DMOD_CIPHER type)
{
    return dmod_encrypt(in, out, len, key, nonce, type);
}

int dmod_write(dmod_maker_ctx *ctx, const char *path)
{
    printf("Writing DMOD to %s\n", path);
    FILE *outfile = fopen(path, "wb");

    ctx->metadata_offset = DMOD_HEADER_SIZE;

    printf("Writing header\n");

    fwrite(ctx->header, DMOD_HEADER_SIZE, 1, outfile);

    printf("Writing metadata\n");

    if (ctx->metadata_count > 0)
    {
        uint8_t *plaintext_buffer = nullptr;
        size_t buffer_size = 0;

        for (uint32_t i = 0; i < ctx->metadata_count; i++)
        {
            if (plaintext_buffer == nullptr)
            {
                plaintext_buffer = (uint8_t *)malloc(16);
            }

            memcpy(plaintext_buffer + buffer_size, &ctx->metadata_list[i].keysize, 8);
            memcpy(plaintext_buffer + buffer_size + 8, &ctx->metadata_list[i].valuesize, 8);

            size_t new_buf_size = buffer_size + 16 + ctx->metadata_list[i].keysize + ctx->metadata_list[i].valuesize + 16;

            plaintext_buffer = (uint8_t *)realloc(plaintext_buffer, new_buf_size);

            memcpy(plaintext_buffer + buffer_size + 16, ctx->metadata_list[i].key, ctx->metadata_list[i].keysize);
            memcpy(plaintext_buffer + buffer_size + 16 + ctx->metadata_list[i].keysize, ctx->metadata_list[i].value, ctx->metadata_list[i].valuesize);

            buffer_size += ctx->metadata_list[i].keysize + ctx->metadata_list[i].valuesize + 16;
        }

        uint8_t *compressed = nullptr;
        size_t compressed_size = 0;
        if (ctx->header->metadata.flags & DMOD_METADATA_COMPRESS_MASK)
            printf("Compressing metadata...\n");
        printf("Metadata size: %lu\n", buffer_size);
        if (xpress_buffer(plaintext_buffer, (uint8_t **)&compressed, buffer_size, &compressed_size, 0, (DMOD_COMPRESSOR)(ctx->header->metadata.flags & DMOD_METADATA_COMPRESS_MASK)) != 0)
        {
            printf("Failed to compress metadata\n");
            exit(1);
        }

        if (ctx->header->metadata.flags & DMOD_METADATA_COMPRESS_MASK)
            printf("Compressed metadata from %lu to %lu\n", buffer_size, compressed_size);

        // Calc the sha256 hash of the metadata
        uint8_t digest[32];
        dmod_hash(compressed, compressed_size, digest);

        uint8_t hash_enc[32];
        dmod_encrypt(digest, hash_enc, 32, ctx->enc_key, ctx->header->crypto.iv, (DMOD_CIPHER)ctx->header->crypto.sym_cipher_algo);

        uint8_t *ciphertext = (uint8_t *)malloc(compressed_size);

        printf("Encrypting metadata...\n");
        if (dmod_encrypt(compressed, ciphertext, compressed_size, ctx->enc_key, ctx->header->crypto.iv, (DMOD_CIPHER)ctx->header->crypto.sym_cipher_algo))
        {
            printf("Failed to encrypt metadata\n");
            exit(1);
        }
        
        printf("Writing metadata to %u\n", ctx->metadata_offset);
        fwrite(ciphertext, compressed_size, 1, outfile);
        fwrite(hash_enc, 32, 1, outfile);

        printf("DMOD file created. SUCCESS.\n");
        free(plaintext_buffer);
        free(ciphertext);
        free(compressed);

        if (ctx->header->metadata.flags & DMOD_METADATA_COMPRESS_MASK)
        {
            ctx->header->metadata.length = compressed_size;

            dmod_header_final(ctx->header);

            // Rewrite header
            fseek(outfile, 0, SEEK_SET);
            fwrite(ctx->header, DMOD_HEADER_SIZE, 1, outfile);
        }
    }

    fclose(outfile);

    return 0;
}

void dmod_set_cipher(dmod_maker_ctx *ctx, DMOD_CIPHER cipher)
{
    ctx->header->crypto.sym_cipher_algo = (uint16_t)cipher;
    ctx->header->metadata.flags |= DMOD_METADATA_ENCRYPT;
}

dmod_maker_ctx *dmod_ctx_new()
{
    dmod_maker_ctx *ctx = (dmod_maker_ctx *)malloc(sizeof(dmod_maker_ctx));
    ctx->metadata_offset = 0;
    ctx->crypto_offset = 0;
    ctx->entry_offset = 0;
    ctx->text_offset = 0;
    ctx->metadata_count = 0;

    ctx->header = (dmod_header *)malloc(sizeof(dmod_header));
    memset(ctx->header, 0, sizeof(dmod_header));

    dmod_header_init(ctx->header);

    return ctx;
}

void dmod_ctx_free(dmod_maker_ctx *ctx)
{
    for (uint32_t i = 0; i < ctx->metadata_count; i++)
    {
        if (ctx->metadata_list[i].key != NULL)
            free(ctx->metadata_list[i].key);

        if (ctx->metadata_list[i].value != NULL)
            free(ctx->metadata_list[i].value);

        ctx->metadata_list[i].key = NULL;
        ctx->metadata_list[i].value = NULL;
    }

    free(ctx->metadata_list);
    free(ctx->header);
    free(ctx);
}

void dmod_set_key(dmod_maker_ctx *ctx, const uint8_t *key)
{
    memcpy(ctx->enc_key, key, sizeof(ctx->enc_key));

    // Checksum
    uint8_t digest[32];

    dmod_hash(key, sizeof(ctx->enc_key), digest);

    memcpy(ctx->header->crypto.password_checksum, digest, sizeof(ctx->header->crypto.password_checksum));
}

void dmod_set_iv(dmod_maker_ctx *ctx, const uint8_t *iv)
{
    memcpy(ctx->header->crypto.iv, iv, sizeof(ctx->header->crypto.iv));
}

void dmod_set_metadata_flags(dmod_maker_ctx *ctx, uint16_t flags)
{
    ctx->header->metadata.flags |= flags;
}

int dmod_lib_init()
{
    OpenSSL_add_all_algorithms();

    return 0;
}

int dmod_verify_password(const dmod_header *header, const uint8_t *key, size_t key_size)
{
    uint8_t digest[32];

    dmod_hash(key, key_size, digest);

    return memcmp(digest, header->crypto.password_checksum, sizeof(header->crypto.password_checksum)) != 0;
}

void dmod_derive_key(const uint8_t *password, size_t len, uint8_t *outkey)
{
    dmod_hash(password, len, outkey);
}

int dmod_verify_header(const dmod_header *header)
{
    if (!header)
        return 1;
    // Check magic
    if (header->preamble.magic != DMOD_PREAMBLE_MAGIC)
    {
        return 1;
    }

    // Checksum on header preamble
    uint64_t checksum = dmod_preamble_checksum(&header->preamble);
    if (checksum != header->preamble.checksum)
    {
        return 1;
    }

    // Check version
    if (header->preamble.version != DMOD_VERSION)
    {
        return 1;
    }

    // Metadata section
    if (header->metadata.magic != DMOD_METADATA_MAGIC)
    {
        return 1;
    }

    // Checksum on metadata
    checksum = dmod_metadata_checksum(&header->metadata);
    if (checksum != header->metadata.checksum)
    {
        return 1;
    }

    // Crypto section
    if (header->crypto.magic != DMOD_CRYPTO_MAGIC)
    {
        return 1;
    }

    // Checksum on crypto
    checksum = dmod_crypto_checksum(&header->crypto);
    if (checksum != header->crypto.checksum)
    {
        return 1;
    }

    checksum = dmod_header_checksum(header);
    if (checksum != header->checksum)
    {
        return 1;
    }

    return 0;
}

void dmod_hash(const void *in, size_t len, uint8_t *out)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    const EVP_MD *md = EVP_sha256();

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, in, len);
    EVP_DigestFinal_ex(mdctx, out, NULL);
    EVP_MD_CTX_free(mdctx);
}