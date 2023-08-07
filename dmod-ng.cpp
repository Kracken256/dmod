#include <dmod.h>
#include <string.h>
#include <vector>
#include <string>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <map>
#include <openssl/evp.h>
#include <openssl/rand.h>

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
    Help,
    Version,
};

struct param_block
{
    OpMode mode;
    std::string dmod_file_out;
    std::string dmod_file_in;
    std::string signkey_file;
    std::vector<std::string> files_in;
    std::map<std::string, std::string> data;
    bool list_data;
    bool should_exit;
    bool do_encrypt;
    bool do_sign;
    bool do_compress;
    bool do_verify;
};

void println(std::string msg = "");

void print_help();

std::string to_version(uint16_t num);

bool contains_arg(const std::vector<std::string> &args, const std::string &arg, ssize_t pos = -1);

param_block parse_get_mode(const std::vector<std::string> &args);

int inspect_mode(const std::string &dmod_file);

int list_contents(const std::string &dmod_file);

int pack_mode(std::vector<std::string> files_in, const std::string &dmod_file_out, bool do_encrypt = false, bool do_sign = false, std::string keyfile = "", bool do_compress = false);

int verify_mode(std::string dmod_file);

std::string get_password(std::string prompt);

std::vector<std::string> get_files_recursive(const std::string &path);

int main(int argc, char *argv[])
{
    std::vector<std::string> arguments = std::vector<std::string>(argv + 1, argv + argc);

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
        println("dmod-ng version " + to_version(DMOD_VERSION));
        return 0;
    }

    int res = 0;

    if (mode.mode == OpMode::Inspect)
    {
        res &= inspect_mode(mode.dmod_file_in) << 1;
    }

    if (mode.mode == OpMode::Pack)
    {
        res &= pack_mode(mode.files_in, mode.dmod_file_out, mode.do_encrypt, mode.do_sign, mode.signkey_file, mode.do_compress) << 2;
    }

    if (mode.list_data)
    {
        res &= list_contents(mode.dmod_file_in) << 3;
    }

    if (mode.do_verify)
    {
        res &= verify_mode(mode.dmod_file_in) << 4;
    }

    return res;
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

    if (mblock.front() != '-')
    {

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
            case 'z':
                if (params.mode != OpMode::None && params.mode != OpMode::Pack)
                {
                    println("Multiple modes specified. Can not use 'z' with other modes.");
                    params.should_exit = true;
                    return params;
                }
                params.do_compress = true;
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
                if (params.mode != OpMode::None && params.mode != OpMode::Pack)
                {
                    println("Multiple modes specified. Can not use 'e' with other modes.");
                    params.should_exit = true;
                    return params;
                }
                params.do_encrypt = true;
                break;
            case 's':
                if (params.mode != OpMode::None && params.mode != OpMode::Pack)
                {
                    println("Multiple modes specified. Can not use 's' with other modes.");
                    params.should_exit = true;
                    return params;
                }
                params.do_sign = true;
                break;
            case 'v':
                params.do_verify = true;
                break;
            case 'l':
                params.list_data = true;
                break;
            }
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

    if (params.do_verify)
    {
        if (args.size() < 2)
        {
            println("Missing arguments. Usage: dmod-ng v <dmod file>");
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

    if (params.do_sign)
    {
        if (args.size() < 2 || !contains_arg(args, "--sign-key", 1))
        {
            println("Missing --sign-key. Usage: dmod-ng [OPTIONS] --sign-key <key> ...");
            params.should_exit = true;
            return params;
        }

        if (!std::filesystem::exists(args[2]))
        {
            println("The file '" + args[2] + "' does not exist and can not be used as a signing key");
            params.should_exit = true;
            return params;
        }
        params.signkey_file = args[2];
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
            println("The file '" + args[1] + "' does not exit. Can not verify.");
            params.should_exit = true;
            return params;
        }

        params.dmod_file_in = args[1];

        return params;
    }

    if (params.mode == OpMode::Pack && params.do_sign)
    {
        if (args.size() < 5)
        {
            println("Missing output file. Usage: dmod-ng c <output.dmod> [input files...]");
            params.should_exit = true;
            return params;
        }

        params.dmod_file_out = args[3];

        std::vector<std::string> files;

        for (size_t i = 4; i < args.size(); i++)
        {
            if (!std::filesystem::exists(args[i]))
            {
                println("The file '" + args[i] + "' does not exist");
                params.should_exit = true;
                return params;
            }

            std::vector<std::string> sub_files = get_files_recursive(args[i]);
            for (std::string &f : sub_files)
            {
                files.push_back(f);
            }
        }

        params.files_in = files;

        return params;
    }
    else if (params.mode == OpMode::Pack)
    {
        if (args.size() < 3)
        {
            println("Missing output file. Usage: dmod-ng c <output.dmod> [input files...]");
            params.should_exit = true;
            return params;
        }

        params.dmod_file_out = args[1];

        std::vector<std::string> files;

        for (size_t i = 2; i < args.size(); i++)
        {
            if (!std::filesystem::exists(args[i]))
            {
                println("The file '" + args[i] + "' does not exist");
                params.should_exit = true;
                return params;
            }

            std::vector<std::string> sub_files = get_files_recursive(args[i]);
            for (std::string &f : sub_files)
            {
                files.push_back(f);
            }
        }

        params.files_in = files;

        return params;
    }

    if (params.list_data)
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

    if (params.mode == None && !params.list_data)
    {
        params.mode = OpMode::Help;
        return params;
    }

    return params;
}

bool contains_arg(const std::vector<std::string> &args, const std::string &arg, ssize_t pos)
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
    std::string version = to_version(DMOD_VERSION);
    println("dmod-ng " + version + " - An extensible container format for modules");
    println("Usage: dmod-ng [OPTION...] <output> <input>");
    println();
    println("Options:");
    println("  --help, -h: Print this help message");
    println("  --version, -v: Print the version of dmod-ng");
    println("  i: Inspect mode");
    println("  c: Pack mode");
    println("  z: Compress mode");
    println("  x: Unpack mode");
    println("  e: Apply encryption");
    println("  s: Add digital signature");
    println("  v: Verify the module's signature");
    println("  l: List data");
    println();

    println("  --sign-key [path]: The private key to sign the module with");
    println("  --verify-key [path]: The public key to verify the module with");
    println("  --extract-path [path]: The path to extract the module to");

    println();

    println("  --data [key] [value], -m [key] [value]: Add data to the module");
    println("  --remove-data [key], -r [key]: Remove data from the module");
    println("  --extract-data, -x: Extract data from the module to a CSV file");

    println();

    println("Examples:");
    println("  dmod-ng i module.dmod\t\t\t\t\t\tInspect the module");
    println("  dmod-ng il module.dmod\t\t\t\t\tInspect the module and list the data");
    println("  dmod-ng c module.dmod module/\t\t\t\t\tPack the module");
    println("  dmod-ng ce module.dmod module/\t\t\t\tPack the module and encrypt it");
    println("  dmod-ng cse --sign-key /path/private.pem module.dmod module/\tPack the module, encrypt it, and sign it");
    println("  dmod-ng csze --sign-key /path/private.pem module.dmod module/\tPack the module (compressed), encrypt it, sign it");
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
    case 2:
        result = "v0.2";
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
    bool data_valid = false;
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

    // Data section
    if (header.data.magic != DMOD_DATA_MAGIC)
    {
        println("The data magic number is incorrect. The file may be corrupted");
        std::cout << "Expected magic value = " << std::setw(8) << std::setfill('0') << std::hex << DMOD_DATA_MAGIC << std::endl;
        std::cout << "Actual magic value = " << std::setw(8) << std::setfill('0') << std::hex << header.data.magic << std::endl;
        println();
    }

    // Checksum on data
    checksum = dmod_data_checksum(&header.data);
    if (checksum != header.data.checksum)
    {
        println("The data checksum is incorrect. The file may be corrupted");
        std::cout << "Expected checksum = " << std::setw(8) << std::setfill('0') << std::hex << checksum << std::endl;
        std::cout << "Actual checksum = " << std::setw(8) << std::setfill('0') << std::hex << header.data.checksum << std::endl;
        println();
    }
    else
    {
        data_valid = true;
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

    if (!preamble_valid || !data_valid || !crypto_valid || !full_header_valid)
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

    println("    - Module content:");
    println("      - Item count: " + std::to_string(header.data.count));
    println("      - Offset: " + std::to_string(header.data.offset) + " bytes");
    println("      - Size: " + std::to_string(header.data.length) + " bytes");
    println("      - Flags:");

    // Check flags
    bool compressed = header.data.flags & DMOD_DATA_COMPRESS_MASK;
    if (compressed)
    {
        println("        - Compressed: Yes");

        switch (header.data.flags & DMOD_DATA_COMPRESS_MASK)
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

    bool encrypted = header.data.flags & DMOD_DATA_ENCRYPT;
    if (encrypted)
    {
        println("        - Encrypted: Yes");
    }
    else
    {
        println("        - Encrypted: No");
    }

    std::cout << "      - Checksum: " << std::setw(8) << std::setfill('0') << std::hex << header.data.checksum << std::endl;
    println("      - Valid: " + std::string(data_valid ? "Yes" : "No"));
    println("      - Bytes: " + to_hexstring((uint8_t *)&header.data, sizeof(struct dmod_data), 15));

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
        
        uint8_t authority[32];
        dmod_hash(header.crypto.public_key, sizeof(header.crypto.public_key), authority);

        println("      - Authority: " + to_hexstring(authority, sizeof(authority), 19));
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

int list_contents(const std::string &dmod_file)
{
    struct dmod_header header;
    if (dmod_read_header(&header, dmod_file.c_str()) != 0)
    {
        println("Failed to read DMOD header");
        return 1;
    }

    if (dmod_verify_header(&header) != 0)
    {
        println("Failed to verify DMOD header");
        return 1;
    }

    size_t content_length = header.data.length;
    println("Details:");
    std::cout << "  - Size: " << std::dec << content_length << " bytes" << std::endl;
    std::cout << "  - Item count: " << std::dec << header.data.count << std::endl;

    uint8_t enc_key[32];

    if (header.data.flags & DMOD_DATA_ENCRYPT)
    {
        std::string password = get_password("Enter password: ");
        dmod_derive_key(password.c_str(), password.length(), enc_key);
    }

    struct dmod_data_item *items;

    int err = dmod_read_data(&items, &header, dmod_file.c_str(), enc_key);

    switch (err)
    {
    case 0:
        break;
    case 1:
        println("Failed to read file header");
        return 1;
    case 2:
        println("Error: Password is incorrect");
        return 1;
    case 3:
        println("Error: Decryption failed");
        return 1;
    case 4:
        println("Failed to read digest from file");
        return 1;
    case 5:
        println("Failed to decrypt file digest");
        return 1;
    case 6:
        println("Failed to verify file digest. File has been tampered with");
        return 1;
    case 7:
        println("Failed to decompress file");
        return 1;
    default:
        println("Failed to read DMOD data");
        println("Error: " + std::to_string(err));
        return 1;
    }

    std::map<std::string, std::string> data;

    for (size_t i = 0; i < header.data.count; i++)
    {
        struct dmod_data_item *item = &items[i];

        std::string key((char *)item->key, item->keysize);
        std::string value((char *)item->value, item->valuesize);

        data[key] = value;

        delete[] item->key;
        delete[] item->value;
    }

    delete[] items;

    for (auto &it : data)
    {
        if (it.first.length() > 4096)
        {
            println("Not printing data because it is too large");
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

        if (key_is_binary)
        {
            println("  - (Binary key)");
        }
        else
        {
            println("  - \"" + it.first + "\": Value is " + std::to_string(it.second.length()) + " bytes");
        }
    }

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

    char *pass = getpass(prompt.c_str());
    password = pass;

#endif

    return password;
}

std::vector<std::string> get_files_recursive(const std::string &path)
{
    std::vector<std::string> files;

    if (!std::filesystem::exists(path))
        return files;

    if (std::filesystem::is_regular_file(path))
    {
        files.push_back(path);
        return files;
    }

    try
    {
        for (const auto &entry : std::filesystem::directory_iterator(path))
        {
            if (entry.is_directory() && !entry.is_symlink())
            {
                std::vector<std::string> sub_files = get_files_recursive(entry.path().string());
                files.insert(files.end(), sub_files.begin(), sub_files.end());
            }
            else
            {
                if (!entry.is_regular_file())
                    continue;

                // Check if I have read access to the file
                try
                {
                    std::ifstream file(entry.path().string());
                    if (!file.is_open())
                        continue;
                    file.close();
                }
                catch (std::ifstream::failure &e)
                {
                    continue;
                }

                files.push_back(entry.path().string());
            }
        }
    }
    catch (std::filesystem::filesystem_error &e)
    {
        println("Error: " + std::string(e.what()));
    }

    return files;
}

int pack_mode(std::vector<std::string> files_in, const std::string &dmod_file_out, bool do_encrypt, bool do_sign, std::string keyfile, bool do_compress)
{
    println("Packing files into " + dmod_file_out);

    dmod_lib_init();

    struct dmod_content_ctx *ctx = dmod_ctx_new();

    if (do_compress)
        dmod_set_data_flags(ctx, DMOD_COMPRESSOR_ZLIB);

    if (do_encrypt)
    {
        uint8_t enc_key[32];
        uint8_t enc_iv[16];
        RAND_bytes(enc_iv, 16);

        std::string password = get_password("Enter password: ");
        std::string password_confirm = get_password("Confirm password: ");

        if (password != password_confirm)
        {
            println("Error: Passwords do not match");
            dmod_ctx_free(ctx);
            return 1;
        }

        dmod_derive_key((uint8_t *)password.c_str(), password.length(), enc_key);

        dmod_set_cipher(ctx, DMOD_CIPHER_AES_256_CTR);
        dmod_set_key(ctx, enc_key);
        dmod_set_iv(ctx, enc_iv);
    }

    if (do_sign)
    {
        if (dmod_load_private_key_pem_file(ctx, keyfile.c_str()) != 0)
        {
            println("Error: Could not load private key file " + keyfile);
            dmod_ctx_free(ctx);
            return 1;
        }
    }

    for (const std::string &file_name : files_in)
    {
        if (file_name == dmod_file_out)
        {
            println("Error: Input file cannot be the same as the output file");
            dmod_ctx_free(ctx);
            return 1;
        }

        std::ifstream file(file_name, std::ios::binary | std::ios::ate);

        if (!file.is_open())
        {
            println("Error: Could not open file " + file_name + " for reading. Skipping.");
            continue;
        }

        println("  - Adding file " + file_name);

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        char *contents = new char[size];
        int bytes_read = 0;
        do
        {
            bytes_read = file.readsome(contents + bytes_read, size - bytes_read);
        } while (bytes_read > 0);

        file.close();

        std::string file_name_out = file_name;

        dmod_add_data(ctx, file_name_out.c_str(), file_name_out.length(), contents, size);
    }

    dmod_header_final(ctx->header);

    dmod_write(ctx, dmod_file_out.c_str());

    dmod_ctx_free(ctx);

    println("Done");

    return 0;
}

int verify_mode(std::string dmod_file)
{

    struct dmod_header header;
    if (dmod_read_header(&header, dmod_file.c_str()) != 0)
    {
        println("Error: Unable to read header from file.");
        return 1;
    }

    int err = dmod_verify_signature(dmod_file.c_str());

    switch (err)
    {
    case 0:
        println("Signature is valid");
        break;
    case 1:
        println("Error: Unable to read header from file.");
        break;
    case 2:
        println("Error: Unable to verify header.");
        break;
    case 4:
        println("Error: Unable to load public key from header.");
        break;
    case 5:
        println("Error: Unable to read digest from file.");
        break;
    case 6:
        println("Error: Unable to read content of file.");
        break;
    case 7:
        println("Digests do not match. Signature is invalid.");
        break;
    case 8:
        println("Signature is invalid.");
        break;
    case 9:
        println("Error: Unable to open file.");
        break;
    default:
        println("Error: Unknown error. Signature is invalid.");
        break;
    }

    if (err != 0)
    {
        return 1;
    }

    println("\nPublic key: " + to_hexstring(header.crypto.public_key, 32, 12));

    uint8_t authority[32];
    dmod_hash(header.crypto.public_key, 32, authority);

    println("\nAuthority: " + to_hexstring(authority, 32, 11));
    return 0;
}
