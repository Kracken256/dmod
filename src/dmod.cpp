#include <dmod.hpp>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <assert.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <zlib.h>

u32 dmod_check32(const void *data, u32 n_bytes)
{
    u8 digest[16];

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    const EVP_MD *md = EVP_md5();

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, n_bytes);
    EVP_DigestFinal_ex(mdctx, digest, NULL);
    EVP_MD_CTX_free(mdctx);

    return *(u32 *)digest;
}

u32 dmod_preamble_checksum(const struct dmod_header *header)
{
    return dmod_check32(&header->preamble, DMOD_PREAMBLE_SIZE - 4);
}

u32 dmod_metadata_checksum(const struct dmod_metadata *data)
{
    return dmod_check32(data, DMOD_METADATA_SIZE - 4);
}

u32 dmod_crypto_checksum(const struct dmod_crypto *data)
{
    return dmod_check32(data, DMOD_CRYPTO_SIZE - 4);
}

u32 dmod_header_checksum(const struct dmod_header *header)
{
    return dmod_check32(header, DMOD_HEADER_SIZE - 4);
}

void dmod_header_init(struct dmod_header *header)
{
    header->preamble.magic = DMOD_PREAMBLE_MAGIC;
    header->preamble.version = DMOD_VERSION;

    header->metadata.magic = DMOD_METADATA_MAGIC;
    header->metadata.flags = 0;
    header->metadata.length = 0;
    header->metadata.offset = 0;

    header->crypto.magic = DMOD_CRYPTO_MAGIC;
    header->crypto.sym_cipher_algo = DMOD_SYM_CIPHER_ALGO_NONE;
    header->crypto.digest_algo = DMOD_DIGEST_ALGO_NONE;
    header->crypto.x509_certificate_offset = 0;
    memset(header->crypto.cipher_data, 0, sizeof(header->crypto.cipher_data));
    memset(header->crypto.digital_signature, 0, sizeof(header->crypto.digital_signature));
    memset(header->crypto.public_key, 0, sizeof(header->crypto.public_key));

    header->entry.symbols_entry_offset = 0;
    header->entry.text_entry_offset = 0;

    memset(header->reserved, 0, sizeof(header->reserved));
}

void dmod_header_final(struct dmod_header *header)
{
    header->preamble.checksum = dmod_preamble_checksum(header);
    header->metadata.checksum = dmod_metadata_checksum(&header->metadata);
    header->crypto.checksum = dmod_crypto_checksum(&header->crypto);
    header->checksum = dmod_header_checksum(header);
}

void dmod_add_metadata(dmod_maker_ctx *ctx, std::string key, std::string value)
{
    dmod_metadata_item item;
    item.key = nullptr;
    item.value = nullptr;
    item.keysize = key.length();
    item.valuesize = value.length();
    item.key = (u8 *)malloc(item.keysize + 1);
    item.value = (u8 *)malloc(item.valuesize + 1);
    memcpy(item.key, key.c_str(), item.keysize);
    memcpy(item.value, value.c_str(), item.valuesize);
    item.key[item.keysize] = 0;
    item.value[item.valuesize] = 0;
    ctx->metadata.push_back(item);
    ctx->metadata_count++;

    if (ctx->header->metadata.offset == 0)
    {
        ctx->header->metadata.offset = DMOD_HEADER_SIZE;
    }

    ctx->header->metadata.length = ctx->metadata_count;
}
void compress_memory(void *in_data, size_t in_data_size, std::vector<uint8_t> &out_data)
{
    std::vector<uint8_t> buffer;

    const size_t BUFSIZE = 4096;
    uint8_t temp_buffer[BUFSIZE];

    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.next_in = reinterpret_cast<uint8_t *>(in_data);
    strm.avail_in = in_data_size;
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
            return;
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

    out_data = buffer;
}

int xcrypt_buffer(const void *in, void *out, size_t len, const void *key, const void *iv, DMOD_CIPHER type)
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

    EVP_EncryptInit(ctx, cipher_type, (const unsigned char *)key, (const unsigned char *)iv);

    EVP_EncryptUpdate(ctx, (unsigned char *)out, &len_out, (const unsigned char *)in, len);

    EVP_EncryptFinal(ctx, (unsigned char *)out + len_out, &final_len_out);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int xpress_buffer(const void *in, u8 **out, size_t len, size_t *outlen, int op, DMOD_COMPRESSOR mode)
{
    if (mode == DMOD_COMPRESSOR_NONE)
    {
        *out = (u8 *)malloc(len);
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
            compress_memory((void *)in, len, buffer);
            *out = (u8 *)malloc(buffer.size());
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
        strm.zalloc = 0;
        strm.zfree = 0;
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
        *out = (u8 *)malloc(out_buffer.size());
        memcpy(*out, out_buffer.data(), out_buffer.size());
        *outlen = out_buffer.size();
        return 0;
    }

    return 0;
}

void dmod_write(dmod_maker_ctx *ctx, std::string path)
{
    printf("Writing DMOD to %s\n", path.c_str());
    FILE *outfile = fopen(path.c_str(), "wb");

    ctx->metadata_offset = DMOD_HEADER_SIZE;

    printf("Writing header\n");

    fwrite(ctx->header, DMOD_HEADER_SIZE, 1, outfile);

    printf("Writing metadata\n");

    if (ctx->metadata_count > 0)
    {
        u8 *plaintext_buffer = nullptr;
        size_t buffer_size = 0;

        for (u32 i = 0; i < ctx->metadata_count; i++)
        {
            printf("Processing metadata %s : %s\n", ctx->metadata[i].key, ctx->metadata[i].value);
            if (plaintext_buffer == nullptr)
            {
                plaintext_buffer = (u8 *)malloc(4);
            }

            memcpy(plaintext_buffer + buffer_size, &ctx->metadata[i].keysize, 2);
            memcpy(plaintext_buffer + buffer_size + 2, &ctx->metadata[i].valuesize, 2);

            size_t new_buf_size = buffer_size + 4 + ctx->metadata[i].keysize + ctx->metadata[i].valuesize + 4;

            plaintext_buffer = (u8 *)realloc(plaintext_buffer, new_buf_size);

            memcpy(plaintext_buffer + buffer_size + 4, ctx->metadata[i].key, ctx->metadata[i].keysize);
            memcpy(plaintext_buffer + buffer_size + 4 + ctx->metadata[i].keysize, ctx->metadata[i].value, ctx->metadata[i].valuesize);

            buffer_size += ctx->metadata[i].keysize + ctx->metadata[i].valuesize + 4;
        }

        u8 *compressed = nullptr;
        size_t compressed_size = 0;
        if (ctx->header->metadata.flags & DMOD_METADATA_COMPRESS_MASK)
            printf("Compressing metadata...\n");
        printf("Metadata size: %lu\n", buffer_size);
        if (xpress_buffer(plaintext_buffer, (u8 **)&compressed, buffer_size, &compressed_size, 0, (DMOD_COMPRESSOR)(ctx->header->metadata.flags & DMOD_METADATA_COMPRESS_MASK)) != 0)
        {
            printf("Failed to compress metadata\n");
            exit(1);
        }

        if (ctx->header->metadata.flags & DMOD_METADATA_COMPRESS_MASK)
            printf("Compressed metadata from %lu to %lu\n", buffer_size, compressed_size);

        u8 *ciphertext = (u8 *)malloc(compressed_size);

        printf("Encrypting metadata...\n");
        if (xcrypt_buffer(compressed, ciphertext, compressed_size, ctx->enc_key, ctx->iv, (DMOD_CIPHER)ctx->header->crypto.sym_cipher_algo))
        {
            printf("Failed to encrypt metadata\n");
            exit(1);
        }

        printf("Writing metadata to %u\n", ctx->metadata_offset);
        fwrite(ciphertext, compressed_size, 1, outfile);

        printf("DMOD file created. SUCCESS.\n");
        free(plaintext_buffer);
        free(ciphertext);
        free(compressed);
    }

    fclose(outfile);
}

void dmod_set_cipher(dmod_maker_ctx *ctx, DMOD_CIPHER cipher)
{
    ctx->header->crypto.sym_cipher_algo = (u16)cipher;
    ctx->header->metadata.flags |= DMOD_METADATA_ENCRYPT;
}

void dmod_ctx_init(dmod_maker_ctx *ctx)
{
    ctx->metadata_offset = 0;
    ctx->crypto_offset = 0;
    ctx->entry_offset = 0;
    ctx->text_offset = 0;
    ctx->metadata_count = 0;
}

void dmod_ctx_free(dmod_maker_ctx *ctx)
{
    for (u32 i = 0; i < ctx->metadata_count; i++)
    {
        if (ctx->metadata[i].key != NULL)
            free(ctx->metadata[i].key);

        if (ctx->metadata[i].value != NULL)
            free(ctx->metadata[i].value);
    }
}

void dmod_set_key(dmod_maker_ctx *ctx, const u8 *key)
{
    memcpy(ctx->enc_key, key, sizeof(ctx->enc_key));
}

void dmod_set_iv(dmod_maker_ctx *ctx, const u8 *iv)
{
    memcpy(ctx->iv, iv, sizeof(ctx->iv));
}

void dmod_set_metadata_flags(dmod_maker_ctx *ctx, u16 flags)
{
    ctx->header->metadata.flags |= flags;
}

void dmod_lib_init()
{

    SSL_library_init();
    OpenSSL_add_all_algorithms();
}