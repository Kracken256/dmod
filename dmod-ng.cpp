#include <dmod.hpp>
#include <string.h>
#include <vector>
#include <string>
#include <iostream>
#include <filesystem>
#include <fstream>

enum OpMode
{
    Compress,
    Decompress,
    Inspect,
};

void println(std::string msg = "");

void print_help();

bool contains_arg(const std::vector<std::string> &args, const std::string &arg, size_t pos = -1);

OpMode parse_get_mode(const std::vector<std::string> &args);

int inspect_mode(const std::vector<std::string> &args);
int compress_mode(const std::vector<std::string> &args);
int decompress_mode(const std::vector<std::string> &args);

int main(int argc, char *argv[])
{
    std::vector<std::string> arguments = std::vector<std::string>(argv + 1, argv + argc);

    if (arguments.size() == 0 || contains_arg(arguments, "--help") || contains_arg(arguments, "-h"))
    {
        print_help();
        return 0;
    }

    if (arguments.size() == 1 && (contains_arg(arguments, "--version", 0) || contains_arg(arguments, "-v", 0)))
    {
        println("dmod-ng v0.0.1");
        return 0;
    }

    struct dmod_header header;
    u8 aes_key[32];
    memset(aes_key, 0, 32);

    u8 ivkey[16];
    memset(ivkey, 0, 16);

    dmod_header_init(&header);

    struct dmod_maker_ctx ctx;

    dmod_ctx_init(&ctx);
    ctx.header = &header;

    dmod_set_cipher(&ctx, DMOD_CIPHER_AES_256_CTR);
    dmod_set_key(&ctx, aes_key);
    dmod_set_iv(&ctx, ivkey);

    // Set compress
    dmod_set_metadata_flags(&ctx, DMOD_COMPRESSOR_ZLIB);

    // Test add metadata
    dmod_add_metadata(&ctx, "author.email", "wesjones2004@gmail.com");
    dmod_add_metadata(&ctx, "author.name", "Wesley Jones");
    dmod_add_metadata(&ctx, "author.website", "https://wesjones2004.github.io");
    dmod_add_metadata(&ctx, "software.version", "0.0.1");
    dmod_add_metadata(&ctx, "software.name", "dmod");
    dmod_add_metadata(&ctx, "software.description", "A module format for myself");
    dmod_add_metadata(&ctx, "software.license", "Proprietary");

    dmod_header_final(ctx.header);

    dmod_write(&ctx, "module.dmod");

    dmod_ctx_free(&ctx);

    println();
    println();

    OpMode mode = parse_get_mode(arguments);

    switch (mode)
    {
    case Compress:
        return compress_mode(arguments);
    case Decompress:
        return decompress_mode(arguments);
    case Inspect:
        return inspect_mode(arguments);
    default:
        println("Unknown mode");
        return 1;
    }

    return 0;
}

OpMode parse_get_mode(const std::vector<std::string> &args)
{
    if (contains_arg(args, "--compress", 0) || contains_arg(args, "-c", 0))
    {
        return OpMode::Compress;
    }
    else if (contains_arg(args, "--decompress", 0) || contains_arg(args, "-D", 0))
    {
        return OpMode::Decompress;
    }
    else
    {
        return OpMode::Inspect;
    }
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
    println("Author: Wesley Jones <@Kracken256>");
    println("License: Proprietary");
    println();
    println("Usage: dmod-ng [options] <input> <output>");
    println("Options:");
    println("  --help, -h: Print this help message");
    println("  --version, -v: Print the version of dmod-ng");
    println("  --compress, -c: Compress the module");
    println("  --encrypt, -e: Encrypt the module");
    println("  --decrypt, -d: Decrypt the module");
    println("  --key, -k: Set the key for encryption/decryption");
    println("  --sign, -s: Sign the module");
    println("  --sign-key, -S: Set the key for signing");
    println("  --verify, -V: Verify the module");
    println("  --verify-key, -K: Set the key for verification");
    println("  --decompress, -D: Decompress the module");

    println("  --add-metadata, -a: Add metadata to the module");
    println("  --remove-metadata, -r: Remove metadata from the module");
    println("  --list-metadata, -l: List metadata from the module");
    println("  --extract-metadata, -x: Extract metadata from the module");

    println();
}

void println(std::string msg)
{
    std::cout << msg << std::endl;
}

std::string to_version(u16 num)
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

std::string to_symmetric_algorithm(u16 num)
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

std::string to_digest_algorithm(u16 num)
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

std::string to_hexstring(const u8 *bytes, size_t len, size_t indent = 0)
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

int inspect_mode(const std::vector<std::string> &args)
{
    if (args.size() < 1)
    {
        println("No input file specified");
        return 1;
    }

    std::string input_file = args.back();

    if (!std::filesystem::exists(input_file))
    {
        println("Input file does not exist");
        return 1;
    }

    std::ifstream input_stream(input_file, std::ios::binary);

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

    // Check magic
    if (header.preamble.magic != DMOD_PREAMBLE_MAGIC)
    {
        println("The magic number is incorrect. The file may be corrupted");
        std::cout << "Expected magic value = " << std::setw(8) << std::setfill('0') << std::hex << DMOD_PREAMBLE_MAGIC << std::endl;
        std::cout << "Actual magic value = " << std::setw(8) << std::setfill('0') << std::hex << header.preamble.magic << std::endl;
    }

    // Checksum on header preamble
    u64 checksum = dmod_preamble_checksum((dmod_header *)&header.preamble);
    if (checksum != header.preamble.checksum)
    {
        println("The checksum is incorrect. The file may be corrupted");
        std::cout << "Expected checksum = " << std::setw(8) << std::setfill('0') << std::hex << checksum << std::endl;
        std::cout << "Actual checksum = " << std::setw(8) << std::setfill('0') << std::hex << header.preamble.checksum << std::endl;
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
    }

    // Metadata section
    if (header.metadata.magic != DMOD_METADATA_MAGIC)
    {
        println("The metadata magic number is incorrect. The file may be corrupted");
        std::cout << "Expected magic value = " << std::setw(8) << std::setfill('0') << std::hex << DMOD_METADATA_MAGIC << std::endl;
        std::cout << "Actual magic value = " << std::setw(8) << std::setfill('0') << std::hex << header.metadata.magic << std::endl;
    }

    // Checksum on metadata
    checksum = dmod_metadata_checksum(&header.metadata);
    if (checksum != header.metadata.checksum)
    {
        println("The metadata checksum is incorrect. The file may be corrupted");
        std::cout << "Expected checksum = " << std::setw(8) << std::setfill('0') << std::hex << checksum << std::endl;
        std::cout << "Actual checksum = " << std::setw(8) << std::setfill('0') << std::hex << header.metadata.checksum << std::endl;
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
    }

    // Checksum on crypto
    checksum = dmod_crypto_checksum(&header.crypto);
    if (checksum != header.crypto.checksum)
    {
        println("The crypto checksum is incorrect. The file may be corrupted");
        std::cout << "Expected checksum = " << std::setw(8) << std::setfill('0') << std::hex << checksum << std::endl;
        std::cout << "Actual checksum = " << std::setw(8) << std::setfill('0') << std::hex << header.crypto.checksum << std::endl;
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
    }
    else
    {
        full_header_valid = true;
    }

    println("Module information:");

    println("  - Module header:");
    println("    - Module Preamble:");
    println("      - Version: " + to_version(header.preamble.version));
    std::cout << "      - Checksum: " << std::setw(8) << std::setfill('0') << std::hex << header.preamble.checksum << std::endl;
    println("      - Valid: " + std::string(preamble_valid ? "Yes" : "No"));
    println("      - Bytes: " + to_hexstring((u8 *)&header.preamble, sizeof(struct dmod_preamble), 15));

    println("    - Module Metadata:");
    println("      - Metadata Items: " + std::to_string(header.metadata.length));
    println("      - Offset: " + std::to_string(header.metadata.offset) + " bytes");
    println("      - Flags:");

    // Check flags
    bool compressed = header.metadata.flags & DMOD_METADATA_COMPRESS_MASK;
    if (compressed)
    {
        println("        - Compressed: Yes");

        switch (header.metadata.flags & DMOD_METADATA_COMPRESS_MASK)
        {
        case DMOD_COMPRESSOR_LZ4:
            println("        - Compression Method: LZ4");
            break;
        case DMOD_COMPRESSOR_ZSTD:
            println("        - Compression Method: ZSTD");
            break;
        case DMOD_COMPRESSOR_LZ4HC:
            println("        - Compression Method: LZ4HC");
            break;
        case DMOD_COMPRESSOR_ZLIB:
            println("        - Compression Method: ZLIB");
            break;
        case DMOD_COMPRESSOR_LZMA:
            println("        - Compression Method: LZMA");
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
    println("      - Bytes: " + to_hexstring((u8 *)&header.metadata, sizeof(struct dmod_metadata), 15));

    println("    - Module Crypto Settings:");
    println("      - Symmetric Algorithm: " + to_symmetric_algorithm(header.crypto.sym_cipher_algo));
    println("      - Digest Algorithm: " + to_digest_algorithm(header.crypto.digest_algo));

    u8 cipher_data_cmp[sizeof(header.crypto.cipher_data)];
    u8 digital_signature_cmp[sizeof(header.crypto.digital_signature)];
    u8 public_key_cmp[sizeof(header.crypto.public_key)];
    memset(cipher_data_cmp, 0, sizeof(cipher_data_cmp));
    memset(digital_signature_cmp, 0, sizeof(digital_signature_cmp));
    memset(public_key_cmp, 0, sizeof(public_key_cmp));

    if (memcmp(header.crypto.cipher_data, cipher_data_cmp, sizeof(cipher_data_cmp)) == 0)
    {
        println("      - Cipher Data: None");
    }
    else
    {
        println("      - Cipher Data: " + to_hexstring(header.crypto.cipher_data, sizeof(header.crypto.cipher_data), 21));
    }

    if (memcmp(header.crypto.digital_signature, digital_signature_cmp, sizeof(digital_signature_cmp)) == 0)
    {
        println("      - Digital Signature: None");
    }
    else
    {
        println("      - Digital Signature: " + to_hexstring(header.crypto.digital_signature, sizeof(header.crypto.digital_signature), 27));
    }

    if (memcmp(header.crypto.public_key, public_key_cmp, sizeof(public_key_cmp)) == 0)
    {
        println("      - Public Key: None");
    }
    else
    {
        println("      - Public Key: " + to_hexstring(header.crypto.public_key, sizeof(header.crypto.public_key), 20));
    }

    if (header.crypto.x509_certificate_offset > 0)
    {
        println("      - X509 Certificate Offset: " + std::to_string(header.crypto.x509_certificate_offset) + " bytes");
    }
    else
    {
        println("      - X509 Certificate Offset: None");
    }

    std::cout << "      - Checksum: " << std::setw(8) << std::setfill('0') << std::hex << header.crypto.checksum << std::endl;
    println("      - Valid: " + std::string(crypto_valid ? "Yes" : "No"));
    println("      - Bytes: " + to_hexstring((u8 *)&header.crypto, sizeof(struct dmod_crypto), 15));

    println("  - Module Entry Table:");
    println("    - Symbol Count: " + std::to_string(header.entry.symbols_count));
    println("    - Symbol Table Offset: " + std::to_string(header.entry.symbols_entry_offset) + " bytes");
    println("    - Entry Offset: " + std::to_string(header.entry.text_entry_offset) + " bytes");

    u8 reserve_cmp[sizeof(header.reserved)];
    memset(reserve_cmp, 0, sizeof(reserve_cmp));

    if (memcmp(header.reserved, reserve_cmp, sizeof(reserve_cmp)) != 0)
    {
        println("  - Warning: Reserved bytes are not zeroed");

        println("    - Bytes: " + to_hexstring(header.reserved, sizeof(header.reserved), 13));
    }

    std::cout << "  - DMOD Header Checksum: " << std::setw(8) << std::setfill('0') << std::hex << header.checksum << std::endl;
    if (full_header_valid)
    {
        println("  - DMOD Header Valid: Yes");
    }
    else
    {
        println("  - DMOD Header Valid: No");
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