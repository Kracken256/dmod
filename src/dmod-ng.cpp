#include <dmod.h>
#include <string.h>
#include <vector>
#include <string>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <map>
#include <openssl/evp.h>

#ifdef _WIN32
#include <windows.h>
#elif __linux__
#include <termios.h>
#include <unistd.h>
#endif

enum OpMode
{
    None = 0,
    Inspect,
    Pack,
    Unpack,
    Encrypt,
    Sign,
    Verify,
    Help,
    Version,
};

struct param_block
{
    OpMode mode;
    std::string dmod_file_out;
    std::string dmod_file_in;
    std::string signkey_file;
    std::string verifykey_file;
    std::vector<std::string> files_in;
    std::map<std::string, std::string> metadata;
    bool list_metadata;
    bool should_exit;
};

void println(std::string msg = "");

void print_help();

bool contains_arg(const std::vector<std::string> &args, const std::string &arg, size_t pos = -1);

param_block parse_get_mode(const std::vector<std::string> &args);

int inspect_mode(const std::string &dmod_file);
int compress_mode(const std::vector<std::string> &args);
int decompress_mode(const std::vector<std::string> &args);

int print_metadata(const std::string &dmod_file);

bool verify_dmod_file(const std::string &dmod_file);

std::string get_password(std::string prompt);

int main(int argc, char *argv[])
{
    std::vector<std::string> arguments = std::vector<std::string>(argv + 1, argv + argc);

    uint8_t enc_key[32];

    uint8_t ivkey[16];
    memset(ivkey, 0xac, 16);

    struct dmod_maker_ctx *ctx = dmod_ctx_new();

    char password[] = "1234";

    dmod_derive_key((uint8_t *)password, 4, enc_key);

    dmod_set_cipher(ctx, DMOD_CIPHER_AES_256_CTR);
    dmod_set_key(ctx, enc_key);
    dmod_set_iv(ctx, ivkey);

    // Set compress
    dmod_set_metadata_flags(ctx, DMOD_COMPRESSOR_ZLIB);

    // Test add metadata
    dmod_add_metadata(ctx, "author.email", 12, "wesjones2004@gmail.com", 22);
    // dmod_add_metadata(ctx, "author.name", "Wesley Jones");
    // dmod_add_metadata(ctx, "author.website", "https://wesjones2004.github.io");
    // dmod_add_metadata(ctx, "software.version", "0.0.1");
    // dmod_add_metadata(ctx, "software.name", "dmod");
    // dmod_add_metadata(ctx, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d", "non-printable");
    // dmod_add_metadata(ctx, "software.description", "A module format for myself");
    // dmod_add_metadata(ctx, "software.license", "Proprietary");

    dmod_header_final(ctx->header);

    dmod_write(ctx, "module.dmod");

    dmod_ctx_free(ctx);

    println();
    println();

    param_block mode = parse_get_mode(arguments);

    if (mode.should_exit)
    {
        return 1;
    }

    switch (mode.mode)
    {
    case OpMode::Help:
        print_help();
        return 0;
    case OpMode::Version:
        println("dmod-ng v0.1-dev");
        return 0;
    }

    if (mode.mode == OpMode::Inspect)
    {
        int res = inspect_mode(mode.dmod_file_in);
        int pres = 0;

        // TODO print metadata
        if (mode.list_metadata)
        {
            pres = print_metadata(mode.dmod_file_in);
        }

        return res || pres;
    }

    if (mode.list_metadata)
    {
        int res = print_metadata(mode.dmod_file_in);
        return res;
    }

    return 0;
}

param_block parse_get_mode(const std::vector<std::string> &args)
{
    param_block params;
    params.mode = OpMode::None;

    if (args.size() < 1)
    {
        params.mode = OpMode::Help;
        return params;
    }

    std::string mblock = args[0];

    if (std::filesystem::exists(mblock) && args.size() == 1)
    {
        params.dmod_file_in = mblock;
        params.mode = OpMode::Inspect;
        return params;
    }

    for (char c : mblock)
    {
        switch (c)
        {
        case 'i':
            if (params.mode != OpMode::None && params.mode != OpMode::Inspect)
            {
                println("Multiple modes specified. Can not use 'i' with other modes.");
                params.should_exit = true;
                return params;
            }
            params.mode = OpMode::Inspect;
            break;
        case 'c':
            if (params.mode != OpMode::None && params.mode != OpMode::Pack)
            {
                println("Multiple modes specified. Can not use 'c' with other modes.");
                params.should_exit = true;
                return params;
            }
            params.mode = OpMode::Pack;
            break;
        case 'x':
            if (params.mode != OpMode::None && params.mode != OpMode::Unpack)
            {
                println("Multiple modes specified. Can not use 'x' with other modes.");
                params.should_exit = true;
                return params;
            }
            params.mode = OpMode::Unpack;
            break;
        case 'e':
            if (params.mode != OpMode::None && params.mode != OpMode::Encrypt)
            {
                println("Multiple modes specified. Can not use 'e' with other modes.");
                params.should_exit = true;
                return params;
            }
            params.mode = OpMode::Encrypt;
            break;
        case 's':
            if (params.mode != OpMode::None && params.mode != OpMode::Sign)

            {
                println("Multiple modes specified. Can not use 's' with other modes.");
                params.should_exit = true;
                return params;
            }
            params.mode = OpMode::Sign;
            break;
        case 'v':
            if (params.mode != OpMode::None && params.mode != OpMode::Verify)
            {
                println("Multiple modes specified. Can not use 'v' with other modes.");
                params.should_exit = true;
                return params;
            }
            params.mode = OpMode::Verify;
            break;
        case 'l':
            params.list_metadata = true;
            break;

        default:
            println("Unknown mode '" + std::string(1, c) + "'");
            params.should_exit = true;
            break;
        }
    }

    if (contains_arg(args, "--help"))
    {
        params.mode = OpMode::Help;
    }

    if (contains_arg(args, "--version"))
    {
        params.mode = OpMode::Version;
    }

    // Check correct modes

    if (params.mode == OpMode::Inspect)
    {
        if (args.size() < 2)
        {
            println("Missing input file. Usage: dmod-ng i <file>");
            params.should_exit = true;
            return params;
        }

        if (!std::filesystem::exists(args[1]))
        {
            println("The file '" + args[1] + "' does not exist");
            params.should_exit = true;
            return params;
        }

        params.dmod_file_in = args[1];

        return params;
    }

    if (params.list_metadata)
    {
        if (args.size() < 2)
        {
            println("Missing input file. Usage: dmod-ng l <file>");
            params.should_exit = true;
            return params;
        }

        if (!std::filesystem::exists(args[1]))
        {
            println("The file '" + args[1] + "' does not exist");
            params.should_exit = true;
            return params;
        }

        params.dmod_file_in = args[1];

        return params;
    }

    if (params.mode == None && !params.list_metadata)
    {
        params.mode = OpMode::Help;
        return params;
    }

    return params;
}

bool contains_arg(const std::vector<std::string> &args, const std::string &arg, size_t pos)
{
    // If -1 search any position
    if (pos == -1)
    {
        for (size_t i = 0; i < args.size(); i++)
        {
            if (args[i] == arg)
            {
                return true;
            }
        }
    }
    else
    {
        if (pos >= args.size())
        {
            return false;
        }

        if (args[pos] == arg)
        {
            return true;
        }
    }

    return false;
}

void print_help()
{
    println("dmod-ng v0.1-dev - An extensible container format for modules");
    println("Usage: dmod-ng [OPTION...] <output> <input>");
    println();
    println("Options:");
    println("  --help, -h: Print this help message");
    println("  --version, -v: Print the version of dmod-ng");
    println("  i: Inspect mode");
    println("  c: Pack mode");
    println("  x: Unpack mode");
    println("  e: Apply encryption");
    println("  s: Add digital signature");
    println("  v: Verify the module's signature");
    println("  l: List metadata");
    println();

    println("  --sign-key [path]: The private key to sign the module with");
    println("  --verify-key [path]: The public key to verify the module with");
    println("  --extract-path [path]: The path to extract the module to");

    println();

    println("  --metadata [key] [value], -m [key] [value]: Add metadata to the module");
    println("  --remove-metadata [key], -r [key]: Remove metadata from the module");
    println("  --extract-metadata, -x: Extract metadata from the module to a CSV file");

    println();

    println("Examples:");
    println("  dmod-ng i module.dmod\t\t\t\t\t\tInspect the module");
    println("  dmod-ng il module.dmod\t\t\t\t\tInspect the module and list the metadata");
    println("  dmod-ng c module.dmod module/\t\t\t\t\tPack the module");
    println("  dmod-ng ce module.dmod module/\t\t\t\tPack the module and encrypt it");
    println("  dmod-ng cse --sign-key /path/private.pem module.dmod module/\tPack the module, encrypt it, and sign it");
    println("  dmod-ng s --sign-key /path/private.pem module.dmod\t\tSign an existing module");
    println("  dmod-ng x module.dmod\t\t\t\t\t\tUnpack the module");
    println("  dmod-ng x module.dmod --extract-path module/\t\t\tUnpack the module to the module/ directory");

    println();
    println("Author: Wesley Jones <@Kracken256>");
    println("License: Copywrite (c) Proprietary - All Rights Reserved");
    println();
}

void println(std::string msg)
{
    std::cout << msg << std::endl;
}

std::string to_version(uint16_t num)
{
    std::string result;
    switch (num)
    {
    case 0:
        result = "Nil";
        break;
    case 1:
        result = "v0.1";
        break;
    default:
        result = "Unknown";
        break;
    }

    if (num & 0x8000)
    {
        result += "-dev";
    }

    return result;
}

std::string to_symmetric_algorithm(uint16_t num)
{
    std::string result;

    switch (num)
    {
    case DMOD_CIPHER_NONE:
        result = "None";
        break;
    case DMOD_CIPHER_AES_128_CTR:
        result = "AES-128-CTR (128-bit key)";
        break;
    case DMOD_CIPHER_AES_256_CTR:
        result = "AES-256-CTR (256-bit key)";
        break;
    case DMOD_CIPHER_CHACHA20:
        result = "ChaCha20 (256-bit key)";
        break;
    default:
        result = "Unknown (" + std::to_string(num) + ")";
        break;
    }

    return result;
}

std::string to_digest_algorithm(uint16_t num)
{
    std::string result;

    switch (num)
    {
    case DMOD_DIGEST_ALGO_NONE:
        result = "None";
        break;
    case DMOD_DIGEST_ALGO_SHA_256:
        result = "SHA-256";
        break;
    case DMOD_DIGEST_ALGO_SHA_3_256:
        result = "SHA-3-256";
        break;
    default:
        result = "Unknown (" + std::to_string(num) + ")";
        break;
    }

    return result;
}

std::string to_hexstring(const uint8_t *bytes, size_t len, size_t indent = 0)
{
    std::stringstream ss;
    for (int i = 0; i < len; i++)
    {
        if (i % 10 == 0 && i != 0)
        {
            ss << "\n"
               << std::string(indent, ' ');
        }

        ss << std::setw(2) << std::setfill('0') << std::hex << (int)(bytes[i]);

        if (i != len - 1 && i % 10 != 9)
        {
            ss << ":";
        }
    }

    return ss.str();
}

bool verify_dmod_file(const std::string &dmod_file)
{
    if (!std::filesystem::exists(dmod_file))
    {
        return false;
    }

    std::ifstream input_stream(dmod_file, std::ios::binary);

    if (!input_stream.is_open())
    {
        return false;
    }

    struct dmod_header header;

    if (input_stream.readsome((char *)&header, sizeof(struct dmod_header)) != sizeof(struct dmod_header))
    {
        return false;
    }

    input_stream.close();

    return dmod_verify_header(&header) == 0;
}

int inspect_mode(const std::string &dmod_file)
{
    if (!std::filesystem::exists(dmod_file))
    {
        println("Input file does not exist");
        return 1;
    }

    std::ifstream input_stream(dmod_file, std::ios::binary);

    if (!input_stream.is_open())
    {
        println("Failed to open input file");
        return 1;
    }

    struct dmod_header header;
    bool preamble_valid = false;
    bool metadata_valid = false;
    bool crypto_valid = false;
    bool full_header_valid = false;

    if (input_stream.readsome((char *)&header, sizeof(struct dmod_header)) != sizeof(struct dmod_header))
    {
        println("Failed to read header. The file may be corrupted");
        return 1;
    }

    input_stream.close();

    // Check magic
    if (header.preamble.magic != DMOD_PREAMBLE_MAGIC)
    {
        println("The magic number is incorrect. The file may be corrupted");
        std::cout << "Expected magic value = " << std::setw(8) << std::setfill('0') << std::hex << DMOD_PREAMBLE_MAGIC << std::endl;
        std::cout << "Actual magic value = " << std::setw(8) << std::setfill('0') << std::hex << header.preamble.magic << std::endl;
        println();
    }

    // Checksum on header preamble
    uint64_t checksum = dmod_preamble_checksum(&header.preamble);
    if (checksum != header.preamble.checksum)
    {
        println("The checksum is incorrect. The file may be corrupted");
        std::cout << "Expected checksum = " << std::setw(8) << std::setfill('0') << std::hex << checksum << std::endl;
        std::cout << "Actual checksum = " << std::setw(8) << std::setfill('0') << std::hex << header.preamble.checksum << std::endl;
        println();
    }
    else
    {
        preamble_valid = true;
    }

    // Check version
    if (header.preamble.version != DMOD_VERSION)
    {
        println("This version of dmod-ng does not support the version of this module");
        std::cout << "Expected version = " << DMOD_VERSION << std::endl;
        std::cout << "Actual version = " << header.preamble.version << std::endl;
        println();
    }

    // Metadata section
    if (header.metadata.magic != DMOD_METADATA_MAGIC)
    {
        println("The metadata magic number is incorrect. The file may be corrupted");
        std::cout << "Expected magic value = " << std::setw(8) << std::setfill('0') << std::hex << DMOD_METADATA_MAGIC << std::endl;
        std::cout << "Actual magic value = " << std::setw(8) << std::setfill('0') << std::hex << header.metadata.magic << std::endl;
        println();
    }

    // Checksum on metadata
    checksum = dmod_metadata_checksum(&header.metadata);
    if (checksum != header.metadata.checksum)
    {
        println("The metadata checksum is incorrect. The file may be corrupted");
        std::cout << "Expected checksum = " << std::setw(8) << std::setfill('0') << std::hex << checksum << std::endl;
        std::cout << "Actual checksum = " << std::setw(8) << std::setfill('0') << std::hex << header.metadata.checksum << std::endl;
        println();
    }
    else
    {
        metadata_valid = true;
    }

    // Crypto section
    if (header.crypto.magic != DMOD_CRYPTO_MAGIC)
    {
        println("The crypto magic number is incorrect. The file may be corrupted");
        std::cout << "Expected magic value = " << std::setw(8) << std::setfill('0') << std::hex << DMOD_CRYPTO_MAGIC << std::endl;
        std::cout << "Actual magic value = " << std::setw(8) << std::setfill('0') << std::hex << header.crypto.magic << std::endl;
        println();
    }

    // Checksum on crypto
    checksum = dmod_crypto_checksum(&header.crypto);
    if (checksum != header.crypto.checksum)
    {
        println("The crypto checksum is incorrect. The file may be corrupted");
        std::cout << "Expected checksum = " << std::setw(8) << std::setfill('0') << std::hex << checksum << std::endl;
        std::cout << "Actual checksum = " << std::setw(8) << std::setfill('0') << std::hex << header.crypto.checksum << std::endl;
        println();
    }
    else
    {
        crypto_valid = true;
    }

    checksum = dmod_header_checksum(&header);
    if (checksum != header.checksum)
    {
        println("The header checksum is incorrect. The file may be corrupted");
        std::cout << "Expected checksum = " << std::setw(8) << std::setfill('0') << std::hex << checksum << std::endl;
        std::cout << "Actual checksum = " << std::setw(8) << std::setfill('0') << std::hex << header.checksum << std::endl;
        println();
    }
    else
    {
        full_header_valid = true;
    }

    if (!preamble_valid || !metadata_valid || !crypto_valid || !full_header_valid)
    {
        println();
        println("The file is corrupted");

        println("===================================================");
        println();
    }

    println("Module information:");

    println("  - Module header:");
    println("    - Module preamble:");
    println("      - Version: " + to_version(header.preamble.version));
    std::cout << "      - Checksum: " << std::setw(8) << std::setfill('0') << std::hex << header.preamble.checksum << std::endl;
    println("      - Valid: " + std::string(preamble_valid ? "Yes" : "No"));
    println("      - Bytes: " + to_hexstring((uint8_t *)&header.preamble, sizeof(struct dmod_preamble), 15));

    println("    - Module metadata:");
    println("      - Metadata items: " + std::to_string(header.metadata.count));
    println("      - Offset: " + std::to_string(header.metadata.offset) + " bytes");
    println("      - Size: " + std::to_string(header.metadata.length) + " bytes");
    println("      - Flags:");

    // Check flags
    bool compressed = header.metadata.flags & DMOD_METADATA_COMPRESS_MASK;
    if (compressed)
    {
        println("        - Compressed: Yes");

        switch (header.metadata.flags & DMOD_METADATA_COMPRESS_MASK)
        {
        case DMOD_COMPRESSOR_LZ4:
            println("        - Compression method: LZ4");
            break;
        case DMOD_COMPRESSOR_ZSTD:
            println("        - Compression method: ZSTD");
            break;
        case DMOD_COMPRESSOR_LZ4HC:
            println("        - Compression method: LZ4HC");
            break;
        case DMOD_COMPRESSOR_ZLIB:
            println("        - Compression method: ZLIB");
            break;
        case DMOD_COMPRESSOR_LZMA:
            println("        - Compression method: LZMA");
            break;
        case DMOD_COMPRESSOR_NONE:
            if (compressed)
            {
                println("        - Warning: Compressed flag is set but no compressor is specified");
            }
            else
            {
                println("        - Algorithm: None");
            }
            break;
        default:
            println("        - Warning: Unknown compressor");
            break;
        }
    }
    else
    {
        println("        - Compressed: No");
    }

    bool encrypted = header.metadata.flags & DMOD_METADATA_ENCRYPT;
    if (encrypted)
    {
        println("        - Encrypted: Yes");
    }
    else
    {
        println("        - Encrypted: No");
    }

    std::cout << "      - Checksum: " << std::setw(8) << std::setfill('0') << std::hex << header.metadata.checksum << std::endl;
    println("      - Valid: " + std::string(metadata_valid ? "Yes" : "No"));
    println("      - Bytes: " + to_hexstring((uint8_t *)&header.metadata, sizeof(struct dmod_metadata), 15));

    println("    - Module crypto settings:");
    println("      - Symmetric algorithm: " + to_symmetric_algorithm(header.crypto.sym_cipher_algo));
    println("      - Digest algorithm: " + to_digest_algorithm(header.crypto.digest_algo));

    uint8_t digital_signature_cmp[sizeof(header.crypto.digital_signature)];
    uint8_t public_key_cmp[sizeof(header.crypto.public_key)];
    memset(digital_signature_cmp, 0, sizeof(digital_signature_cmp));
    memset(public_key_cmp, 0, sizeof(public_key_cmp));

    println("      - Password checksum: " + to_hexstring(header.crypto.password_checksum, sizeof(header.crypto.password_checksum), 23));

    println("      - IV: " + to_hexstring(header.crypto.iv, sizeof(header.crypto.iv), 12));

    if (memcmp(header.crypto.digital_signature, digital_signature_cmp, sizeof(digital_signature_cmp)) == 0)
    {
        println("      - Digital signature: None");
    }
    else
    {
        println("      - Digital signature: " + to_hexstring(header.crypto.digital_signature, sizeof(header.crypto.digital_signature), 27));
    }

    if (memcmp(header.crypto.public_key, public_key_cmp, sizeof(public_key_cmp)) == 0)
    {
        println("      - Public key: None");
    }
    else
    {
        println("      - Public key: " + to_hexstring(header.crypto.public_key, sizeof(header.crypto.public_key), 20));
    }

    if (header.crypto.x509_certificate_offset > 0)
    {
        println("      - X509 certificate offset: " + std::to_string(header.crypto.x509_certificate_offset) + " bytes");
    }
    else
    {
        println("      - X509 certificate offset: None");
    }

    std::cout << "      - Checksum: " << std::setw(8) << std::setfill('0') << std::hex << header.crypto.checksum << std::endl;
    println("      - Valid: " + std::string(crypto_valid ? "Yes" : "No"));
    println("      - Bytes: " + to_hexstring((uint8_t *)&header.crypto, sizeof(struct dmod_crypto), 15));

    println("  - Module entry table:");
    println("    - Symbol count: " + std::to_string(header.entry.symbols_count));
    println("    - Symbol table offset: " + std::to_string(header.entry.symbols_entry_offset) + " bytes");
    println("    - Entry offset: " + std::to_string(header.entry.text_entry_offset) + " bytes");

    uint8_t reserve_cmp[sizeof(header.reserved)];
    memset(reserve_cmp, 0, sizeof(reserve_cmp));

    if (memcmp(header.reserved, reserve_cmp, sizeof(reserve_cmp)) != 0)
    {
        println("  - Warning: Reserved bytes are not zeroed");

        println("    - Bytes: " + to_hexstring(header.reserved, sizeof(header.reserved), 13));
    }

    std::cout << "  - DMOD header checksum: " << std::setw(8) << std::setfill('0') << std::hex << header.checksum << std::endl;
    if (full_header_valid)
    {
        println("  - DMOD header valid: Yes");
    }
    else
    {
        println("  - DMOD header valid: No");
    }

    return 0;
}

int print_metadata(const std::string &dmod_file)
{
    if (!verify_dmod_file(dmod_file))
    {
        println("Error: Invalid DMOD file");
        return 1;
    }

    std::ifstream file(dmod_file, std::ios::binary);

    if (!file.is_open())
    {
        println("Error: Failed to open file");
        return 1;
    }

    struct dmod_header header;
    if ((file.readsome((char *)&header, sizeof(struct dmod_header)) != sizeof(struct dmod_header)))
    {
        println("Error: Failed to read DMOD header");
        return 1;
    }

    file.seekg(header.metadata.offset, std::ios::beg);
    size_t content_length = header.metadata.length;
    println("Metadata:");
    std::cout << "  - Metadata offset: " << header.metadata.offset << std::endl;
    std::cout << "  - Total bytes: " << std::dec << content_length << std::endl;
    std::cout << "  - Item count: " << std::dec << header.metadata.count << std::endl;

    std::map<std::string, std::string> metadata;
    uint8_t *contents = new uint8_t[content_length];

    if (file.readsome((char *)contents, content_length) != content_length)
    {
        println("Error: Failed to read metadata");
        return 1;
    }

    if (header.metadata.flags & DMOD_METADATA_ENCRYPT)
    {
        // std::string password = get_password("Enter password to view metadata: ");

        std::string password = "1234";

        uint8_t enc_key[32];
        dmod_derive_key((const uint8_t *)password.c_str(), password.length(), enc_key);

        if (dmod_verify_password(&header, enc_key, 32) != 0)
        {
            println("Error: Invalid password");
            return 1;
        }

        uint8_t *plaintext = new uint8_t[content_length];

        dmod_decrypt(contents, plaintext, content_length, enc_key, header.crypto.iv, (DMOD_CIPHER)header.crypto.sym_cipher_algo);

        delete[] contents;

        contents = plaintext;
    }

    if (header.metadata.flags & DMOD_METADATA_COMPRESS_MASK)
    {
        uint8_t *decompressed;
        size_t decompressed_size;
        if (xpress_buffer(contents, &decompressed, content_length, &decompressed_size, 1, (DMOD_COMPRESSOR)(header.metadata.flags & DMOD_METADATA_COMPRESS_MASK)) != 0)
        {
            println("Error: Failed to decompress metadata");
            return 1;
        }

        delete[] contents;

        contents = decompressed;
        content_length = decompressed_size;
    }

    size_t pos = 0;

    do
    {
        uint16_t key_len = *(uint16_t *)&contents[pos];
        pos += sizeof(uint16_t);
        uint16_t val_len = *(uint16_t *)&contents[pos];
        pos += sizeof(uint16_t);

        std::string key((char *)&contents[pos], key_len);
        pos += key_len;
        std::string val((char *)&contents[pos], val_len);
        pos += val_len;

        metadata[key] = val;

    } while (pos < content_length);

    delete[] contents;

    for (auto &it : metadata)
    {
        if (it.first.length() > 4096 || it.second.length() > 4096)
        {
            println("Not printing metadata because it is too large");
            continue;
        }

        // Check if key or value is binary (non-printable)

        bool key_is_binary = false;
        bool val_is_binary = false;

        for (size_t i = 0; i < it.first.length(); i++)
        {
            if (!isprint(it.first[i]))
            {
                key_is_binary = true;
                break;
            }
        }

        for (size_t i = 0; i < it.second.length(); i++)
        {
            if (!isprint(it.second[i]))
            {
                val_is_binary = true;
                break;
            }
        }

        if (!key_is_binary && val_is_binary)
        {
            println("    - \"" + it.first + "\": (binary data)");
            continue;
        }

        if (key_is_binary && !val_is_binary)
        {
            println("    - (binary data): \"" + it.second + "\"");
            continue;
        }

        if (key_is_binary && val_is_binary)
        {
            println("    - (binary data): (binary data)");
            continue;
        }

        println("    - \"" + it.first + "\": \"" + it.second + "\"");
    }

    return 0;
}

int compress_mode(const std::vector<std::string> &args)
{
    return 0;
}

int decompress_mode(const std::vector<std::string> &args)
{
    return 0;
}

std::string get_password(std::string prompt)
{
    // Hide password input cross-platform

    std::string password;

#ifdef _WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));

    std::cout << prompt;
    std::getline(std::cin, password);

    SetConsoleMode(hStdin, mode);

    std::cout << std::endl;
#else
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);

    std::cout << prompt;
    std::getline(std::cin, password);

    tcsetattr(STDIN_FILENO, TCSANOW, &tty);

    std::cout << std::endl;
#endif

    return password;
}