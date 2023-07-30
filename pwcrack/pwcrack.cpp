#include <openssl/evp.h>
#include <openssl/sha.h>
#include <iostream>
#include <vector>
#include <cstring>
#include <time.h>
#include <thread>
#include <atomic>
#include <cmath>
#include <fstream>

using namespace std;

void dmod_hash(const void *in, size_t len, uint8_t *out);
void dmod_compute_pwcheck(const void *password, size_t len, uint8_t *out);
void increment_attempt(char *attempt);
void attempt_str_add(char *attempt, size_t add, int base);
void make_random_attempt(char *attempt);
void thread_crack(const uint8_t *checksum_to_match, char *password_attempt_start, size_t max_iter, int thread_id);

char pwchar[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const size_t password_len = 10;
const int thread_count = 16;

std::fstream shared_stream;
std::atomic<bool> should_exit_thread = false;

void write_msg(std::string msg = "")
{
    shared_stream << msg << std::endl;
    std::cout << msg << std::endl;
    std::cout.flush();
    shared_stream.flush();
}

int main(int argc, char **argv)
{
    vector<string> args = vector<string>(argv + 1, argv + argc);

    if (args.size() != 1)
    {
        cout << "Usage: pwcrack <checksum>" << endl;
        return 1;
    }

    std::string checksum = args[0];

    bool has_found_preimage = false;

    uint8_t tmpsum[SHA256_DIGEST_LENGTH];
    uint8_t checksum_to_match[3];
    size_t iterations = 0;

    // Read checksum into array. ex 00:00:00

    for (int i = 0; i < 3; i++)
    {
        checksum_to_match[i] = (uint8_t)stoi(checksum.substr(i * 3, 2), nullptr, 16);
    }

    shared_stream = std::fstream("pwcrack.log", std::ios::out);

    if (!shared_stream.is_open())
    {
        std::cout << "Failed to open log file" << std::endl;
        return 1;
    }

    // Write start time
    time_t now = time(0);
    char *dt = ctime(&now);
    write_msg("Starting at: " + std::string(dt));

    write_msg("Computing preimage on: " + checksum);

    srand(time(NULL));

    char password_attempt[thread_count][password_len + 1];
    memset(password_attempt, 0, sizeof(password_attempt));
    make_random_attempt(password_attempt[0]);

    const size_t keyspace = pow(strlen(pwchar), password_len);
    const size_t step_size = keyspace / thread_count;

    write_msg("Keyspace: " + std::to_string(keyspace));
    write_msg("Max Iterations: " + std::to_string(keyspace));
    write_msg("Starting Brute Force...\n\n");

    for (int i = 0; i < thread_count; i++)
    {
        char tmp[password_len + 1];
        memcpy(tmp, password_attempt[i], password_len);
        attempt_str_add(tmp, step_size, strlen(pwchar));
        memcpy(password_attempt[i + 1], tmp, password_len);
    }

    thread threads[thread_count];
    int thread_id = 1;
    for (int i = 0; i < thread_count; i++)
    {
        threads[i] = thread(thread_crack, checksum_to_match, password_attempt[i], step_size, thread_id);
        threads[i].detach();
        thread_id++;

        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    write_msg("\n");

    // Do this for 10 minutes
    std::this_thread::sleep_for(std::chrono::hours(4));

    // Write end time
    now = time(0);
    dt = ctime(&now);
    write_msg("Finished at: " + std::string(dt));

    should_exit_thread = true;
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

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

void dmod_compute_pwcheck(const void *password, size_t len, uint8_t *out)
{
    dmod_hash(password, len, out);
    dmod_hash(out, SHA256_DIGEST_LENGTH, out);
}

void increment_attempt(char *attempt)
{
    int i = password_len - 1;
    while (i >= 0)
    {
        if (attempt[i] == pwchar[sizeof(pwchar) - 2])
        {
            attempt[i] = pwchar[0];
            i--;
        }
        else
        {
            attempt[i] = pwchar[strchr(pwchar, attempt[i]) - pwchar + 1];
            break;
        }
    }
}

void make_random_attempt(char *attempt)
{
#pragma omp parallel for
    for (int i = 0; i < password_len; i++)
    {
        attempt[i] = pwchar[rand() % (sizeof(pwchar) - 1)];
    }
}

void thread_crack(const uint8_t *checksum_to_match, char *password_attempt_start, size_t max_iter, int thread_id)
{
    bool has_found_preimage = false;
    size_t iterations = 0;
    char password_attempt[password_len + 1];
    char password_end[password_len + 1];

    memcpy(password_attempt, password_attempt_start, password_len);
    memcpy(password_end, password_attempt_start, password_len);

    password_attempt[password_len] = '\0';
    password_end[password_len] = '\0';

    attempt_str_add(password_end, max_iter, strlen(pwchar));
    uint8_t tmpsum[SHA256_DIGEST_LENGTH];
    std::string print_prefix = "Thread " + std::to_string(thread_id) + ":";

    if (print_prefix.length() < 10)
    {
        print_prefix += std::string(10 - print_prefix.length(), ' ');
    }

    write_msg(print_prefix + " Starting at " + password_attempt + " end " + password_end);

    while (!has_found_preimage && iterations < max_iter && !should_exit_thread)
    {
        dmod_compute_pwcheck(password_attempt, password_len, tmpsum);

        if (memcmp(tmpsum, checksum_to_match, 3) == 0)
        {
            write_msg(print_prefix + " Found preimage: " + password_attempt);
        }

        increment_attempt(password_attempt);
        iterations++;
    }
}

void attempt_str_add(char *attempt, size_t add, int base)
{
    // Add to the string like a basebase number with carry
    // Wrap around modulo base^len

    size_t len = strlen(attempt);

    while (add > 0 && len > 0)
    {
        // Find the index of the current character in the basebase_chars array
        char *ch_pos = strchr(pwchar, attempt[len - 1]);
        if (ch_pos == NULL)
        {
            fprintf(stderr, "Invalid character in the input string: %c\n", attempt[len - 1]);
            exit(1);
        }
        size_t digit = ch_pos - pwchar;

        // Calculate the new value for the current digit
        size_t new_value = digit + add;

        // Determine the carry (if any) and update 'add' with the carry for the next iteration
        add = new_value / base;
        size_t remainder = new_value % base;

        // Update the current digit with the new value (modulo base)
        attempt[len - 1] = pwchar[remainder];

        len--;
    }
}
