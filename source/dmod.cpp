#include <dmod.h>
#include <string.h>
#include <map>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <assert.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <zlib.h>

#include <string>
#include <fstream>

int do_sign(EVP_PKEY *ed_key, const unsigned char *msg, size_t msg_len, uint8_t sig[64])
{
    size_t sig_len;
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();

    EVP_DigestSignInit_ex(md_ctx, NULL, NULL, NULL, NULL, ed_key, NULL);
    EVP_DigestSign(md_ctx, NULL, &sig_len, msg, msg_len);
    if (sig_len != 64)
    {
        return 1;
    }

    EVP_DigestSign(md_ctx, sig, &sig_len, msg, msg_len);
    EVP_MD_CTX_free(md_ctx);

    return 0;
}

int verify_signature(EVP_PKEY *ed_key, const unsigned char *msg, size_t msg_len, uint8_t sig[64])
{
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();

    EVP_DigestVerifyInit_ex(md_ctx, NULL, NULL, NULL, NULL, ed_key, NULL);
    int ret = EVP_DigestVerify(md_ctx, sig, 64, msg, msg_len);

    EVP_MD_CTX_free(md_ctx);

    return ret == 1;
}

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

uint32_t dmod_data_checksum(const struct dmod_data *data)
{
    return dmod_check32(data, DMOD_DATA_SIZE - 4);
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

    header->data.magic = DMOD_DATA_MAGIC;
    header->data.flags = 0;
    header->data.count = 0;
    header->data.offset = 0;
    header->data.length = 0;

    header->crypto.magic = DMOD_CRYPTO_MAGIC;
    header->crypto.sym_cipher_algo = DMOD_SYM_CIPHER_ALGO_NONE;
    header->crypto.digest_algo = DMOD_DIGEST_ALGO_NONE;
    header->crypto.x509_certificate_offset = 0;
    memset(header->crypto.iv, 0, sizeof(header->crypto.iv));
    memset(header->crypto.digital_signature, 0, sizeof(header->crypto.digital_signature));
    memset(header->crypto.public_key, 0, sizeof(header->crypto.public_key));
    memset(header->crypto.password_checksum, 0, sizeof(header->crypto.password_checksum));

    memset(header->reserved, 0, sizeof(header->reserved));
}

void dmod_header_final(struct dmod_header *header)
{
    header->preamble.checksum = dmod_preamble_checksum(&header->preamble);
    header->data.checksum = dmod_data_checksum(&header->data);
    header->crypto.checksum = dmod_crypto_checksum(&header->crypto);
    header->checksum = dmod_header_checksum(header);
}

int dmod_add_data(dmod_content_ctx *ctx, const char *key, size_t key_size, const char *value, size_t value_size)
{
    dmod_data_item item;
    item.key = nullptr;
    item.value = nullptr;
    item.keysize = key_size;
    item.valuesize = value_size;
    item.key = (uint8_t *)malloc(key_size);
    item.value = (uint8_t *)malloc(value_size);
    memcpy(item.key, key, key_size);
    memcpy(item.value, value, value_size);
    ctx->data_count++;

    ctx->data_list = (dmod_data_item *)realloc(ctx->data_list, ctx->data_count * sizeof(dmod_data_item));
    ctx->data_list[ctx->data_count - 1] = item;

    if (ctx->header->data.offset == 0)
    {
        ctx->header->data.offset = DMOD_HEADER_SIZE;
    }

    ctx->header->data.count = ctx->data_count;

    ctx->header->data.length += 16 + key_size + value_size;

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

int dmod_write(dmod_content_ctx *ctx, const char *path)
{
    FILE *outfile = fopen(path, "wb");

    ctx->data_offset = DMOD_HEADER_SIZE;

    fwrite(ctx->header, DMOD_HEADER_SIZE, 1, outfile);

    if (ctx->data_count > 0)
    {
        uint8_t *plaintext_buffer = nullptr;
        size_t buffer_size = 0;

        for (uint32_t i = 0; i < ctx->data_count; i++)
        {
            if (plaintext_buffer == nullptr)
            {
                plaintext_buffer = (uint8_t *)malloc(16);
            }

            memcpy(plaintext_buffer + buffer_size, &ctx->data_list[i].keysize, 8);
            memcpy(plaintext_buffer + buffer_size + 8, &ctx->data_list[i].valuesize, 8);

            size_t new_buf_size = buffer_size + 16 + ctx->data_list[i].keysize + ctx->data_list[i].valuesize + 16;

            plaintext_buffer = (uint8_t *)realloc(plaintext_buffer, new_buf_size);

            memcpy(plaintext_buffer + buffer_size + 16, ctx->data_list[i].key, ctx->data_list[i].keysize);
            memcpy(plaintext_buffer + buffer_size + 16 + ctx->data_list[i].keysize, ctx->data_list[i].value, ctx->data_list[i].valuesize);

            buffer_size += ctx->data_list[i].keysize + ctx->data_list[i].valuesize + 16;
        }

        uint8_t *compressed = nullptr;
        size_t compressed_size = 0;
        if (ctx->header->data.flags & DMOD_DATA_COMPRESS_MASK)
            printf("Compressing data...\n");
        printf("Data size: %lu\n", buffer_size);
        if (xpress_buffer(plaintext_buffer, (uint8_t **)&compressed, buffer_size, &compressed_size, 0, (DMOD_COMPRESSOR)(ctx->header->data.flags & DMOD_DATA_COMPRESS_MASK)) != 0)
        {
            printf("Failed to compress data\n");
            exit(1);
        }

        if (ctx->header->data.flags & DMOD_DATA_COMPRESS_MASK)
            printf("Compressed data from %lu to %lu\n", buffer_size, compressed_size);

        // Calc the sha256 hash of the data
        uint8_t digest[32];
        dmod_hash(compressed, compressed_size, digest);

        uint8_t hash_enc[32];
        dmod_encrypt(digest, hash_enc, 32, ctx->enc_key, ctx->header->crypto.iv, (DMOD_CIPHER)ctx->header->crypto.sym_cipher_algo);

        uint8_t *ciphertext = (uint8_t *)malloc(compressed_size);

        printf("Encrypting data...\n");
        if (dmod_encrypt(compressed, ciphertext, compressed_size, ctx->enc_key, ctx->header->crypto.iv, (DMOD_CIPHER)ctx->header->crypto.sym_cipher_algo))
        {
            printf("Failed to encrypt data\n");
            return 1;
        }

        fwrite(ciphertext, compressed_size, 1, outfile);
        fwrite(hash_enc, 32, 1, outfile);

        free(plaintext_buffer);
        free(ciphertext);
        free(compressed);

        if (ctx->pkey_ptr != nullptr)
        {
            EVP_PKEY *pkey = (EVP_PKEY *)ctx->pkey_ptr;

            // Get public key
            uint8_t pubkey[64];
            size_t pubkey_size = 0;
            EVP_PKEY_get_raw_public_key(pkey, nullptr, &pubkey_size);
            if (pubkey_size != 32)
            {
                printf("Invalid public key size\n");
                return 1;
            }

            EVP_PKEY_get_raw_public_key(pkey, pubkey, &pubkey_size);

            memcpy(ctx->header->crypto.public_key, pubkey, 32);

            uint8_t signature[64];
            if (do_sign(pkey, hash_enc, 32, signature) != 0)
            {
                printf("Failed to sign data\n");
                return 1;
            }
            else
            {
                printf("Signed data\n");
            }

            memcpy(ctx->header->crypto.digital_signature, signature, 64);
        }

        if (ctx->header->data.flags & DMOD_DATA_COMPRESS_MASK)
        {
            ctx->header->data.length = compressed_size;
        }

        dmod_header_final(ctx->header);

        // Rewrite header
        fseek(outfile, 0, SEEK_SET);
        fwrite(ctx->header, DMOD_HEADER_SIZE, 1, outfile);
    }

    fclose(outfile);

    return 0;
}

void dmod_set_cipher(dmod_content_ctx *ctx, DMOD_CIPHER cipher)
{
    ctx->header->crypto.sym_cipher_algo = (uint16_t)cipher;
    ctx->header->data.flags |= DMOD_DATA_ENCRYPT;
}

dmod_content_ctx *dmod_ctx_new()
{
    dmod_content_ctx *ctx = (dmod_content_ctx *)malloc(sizeof(dmod_content_ctx));
    ctx->data_offset = 0;
    ctx->crypto_offset = 0;
    ctx->entry_offset = 0;
    ctx->text_offset = 0;
    ctx->data_count = 0;
    ctx->data_list = nullptr;
    ctx->pkey_ptr = nullptr;

    ctx->header = (dmod_header *)malloc(sizeof(dmod_header));
    memset(ctx->header, 0, sizeof(dmod_header));

    dmod_header_init(ctx->header);

    return ctx;
}

void dmod_ctx_free(dmod_content_ctx *ctx)
{
    if (ctx->data_list)
        free(ctx->data_list);

    if (ctx->header)
        free(ctx->header);

    if (ctx)
        free(ctx);
}

void dmod_set_key(dmod_content_ctx *ctx, const uint8_t *key)
{
    memcpy(ctx->enc_key, key, sizeof(ctx->enc_key));

    // Checksum
    uint8_t digest[32];

    dmod_hash(key, sizeof(ctx->enc_key), digest);

    memcpy(ctx->header->crypto.password_checksum, digest, sizeof(ctx->header->crypto.password_checksum));
}

void dmod_set_iv(dmod_content_ctx *ctx, const uint8_t *iv)
{
    memcpy(ctx->header->crypto.iv, iv, sizeof(ctx->header->crypto.iv));
}

int dmod_load_private_key_pem_file(dmod_content_ctx *ctx, const char *path)
{
    EVP_PKEY *ed_key = NULL;
    FILE *fp = fopen(path, "r");
    if (fp == NULL)
    {
        return 1;
    }
    ed_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    ctx->pkey_ptr = ed_key;

    return 0;
}

int dmod_load_private_key_pem(dmod_content_ctx *ctx, const char *pem)
{
    EVP_PKEY *ed_key = NULL;
    BIO *bio = BIO_new_mem_buf(pem, -1);
    if (bio == NULL)
    {
        return 1;
    }
    ed_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    ctx->pkey_ptr = ed_key;

    return 0;
}

void dmod_set_data_flags(dmod_content_ctx *ctx, uint16_t flags)
{
    ctx->header->data.flags |= flags;
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

    // Data section
    if (header->data.magic != DMOD_DATA_MAGIC)
    {
        return 1;
    }

    // Checksum on data
    checksum = dmod_data_checksum(&header->data);
    if (checksum != header->data.checksum)
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

int dmod_read_header(struct dmod_header *header, const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (fp == NULL)
    {
        return 1;
    }

    size_t bytes_read = fread(header, DMOD_HEADER_SIZE, 1, fp);

    fclose(fp);

    return bytes_read != DMOD_HEADER_SIZE;
}

int dmod_read_data(dmod_data_item **content, dmod_header *header, const char *path, uint8_t *enc_key)
{
    if (dmod_verify_header(header) != 0)
    {
        return 1;
    }

    size_t content_length = header->data.length;

    uint8_t *contents = new uint8_t[content_length];

    size_t bytes_read = 0;

    std::ifstream file(path, std::ios::binary);

    while (file.read((char *)contents + bytes_read, content_length - bytes_read) && bytes_read < content_length)
    {
        bytes_read += file.gcount();
    }

    if (header->data.flags & DMOD_DATA_ENCRYPT)
    {
        if (dmod_verify_password(header, enc_key, 32) != 0)
        {
            file.close();
            delete[] contents;
            return 2;
        }

        uint8_t *plaintext = new uint8_t[content_length];

        if (dmod_decrypt(contents, plaintext, content_length, enc_key, header->crypto.iv, (DMOD_CIPHER)header->crypto.sym_cipher_algo) != 0)
        {
            file.close();
            delete[] contents;
            delete[] plaintext;
            return 3;
        }

        delete[] contents;

        contents = plaintext;

        uint8_t digest_data[32];
        if ((file.readsome((char *)digest_data, sizeof(digest_data)) != sizeof(digest_data)))
        {
            file.close();
            delete[] contents;
            return 4;
        }

        uint8_t digest_enc[32];
        uint8_t digest[32];
        dmod_hash(contents, content_length, digest_enc);

        if (dmod_decrypt(digest_enc, digest, 32, enc_key, header->crypto.iv, (DMOD_CIPHER)header->crypto.sym_cipher_algo) != 0)
        {
            file.close();
            delete[] contents;
            return 5;
        }

        if (memcmp(digest, digest_data, sizeof(digest)) != 0)
        {
            file.close();
            delete[] contents;
            return 6;
        }
    }

    if (header->data.flags & DMOD_DATA_COMPRESS_MASK)
    {
        uint8_t *decompressed;
        size_t decompressed_size;
        if (xpress_buffer(contents, &decompressed, content_length, &decompressed_size, 1, (DMOD_COMPRESSOR)(header->data.flags & DMOD_DATA_COMPRESS_MASK)) != 0)
        {
            file.close();
            delete[] contents;
            return 7;
        }

        delete[] contents;

        contents = decompressed;
        content_length = decompressed_size;
    }

    file.close();

    size_t pos = 0;
    size_t inner_data_length = 0;

    do
    {
        uint64_t key_len = *(uint64_t *)&contents[pos];
        pos += sizeof(uint64_t);
        uint64_t val_len = *(uint64_t *)&contents[pos];
        pos += sizeof(uint64_t);

        pos += key_len + val_len;

        inner_data_length += sizeof(uint64_t) + sizeof(uint64_t) + key_len + val_len;

    } while (pos < content_length);

    if (inner_data_length != content_length)
    {
        delete[] contents;
        return 8;
    }

    *content = (struct dmod_data_item *)contents;

    return 0;
}