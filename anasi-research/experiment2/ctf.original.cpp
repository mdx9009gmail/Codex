#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// ctf input: rotate_the_keys_while_we
static_assert(CHAR_BIT == 8, "This challenge requires 8-bit bytes.");
static_assert(sizeof(unsigned int) == 4, "This challenge requires 32-bit unsigned int.");

namespace {

static const unsigned int kInputBytes = 24;
static const unsigned int kOutputBytes = 24;
static const unsigned int kFeistelRoundsA = 28;
static const unsigned int kFeistelRoundsB = 36;
static const unsigned int kFeistelRoundsC = 32;
static const unsigned int kCoordinateRoundsA = 19;
static const unsigned int kCoordinateRoundsB = 23;
static const unsigned int kByteRoundsA = 9;
static const unsigned int kByteRoundsB = 7;

static const uint32_t kMaster[8] = {
    0xC6A4A793u, 0x9E3779B9u, 0x7F4A7C15u, 0xD1B54A35u,
    0x94D049BBu, 0x369DEA0Fu, 0xA5A5A5A5u, 0x3C6EF372u};

static const uint32_t kInitialWhitening[6] = {
    0x243F6A88u, 0x85A308D3u, 0x13198A2Eu,
    0x03707344u, 0xA4093822u, 0x299F31D0u};

static const uint32_t kFinalWhitening[6] = {
    0x082EFA98u, 0xEC4E6C89u, 0x452821E6u,
    0x38D01377u, 0xBE5466CFu, 0x34E90C6Cu};

static const unsigned char kExpected[kOutputBytes] = {
    0x5e, 0xe2, 0x6d, 0x23, 0x27, 0x78, 0x71, 0xca,
    0x7b, 0x60, 0xe0, 0x40, 0x6d, 0x09, 0xcf, 0x48,
    0x21, 0x9a, 0x52, 0xa7, 0x74, 0x3c, 0x2e, 0x62};

static inline uint32_t rotl32(uint32_t value, unsigned int amount) {
    return (value << amount) | (value >> (32u - amount));
}

static inline unsigned char rotl8(unsigned char value, unsigned int amount) {
    const unsigned int v = value;
    return (unsigned char)((v << amount) | (v >> (8u - amount)));
}

static inline uint32_t load_le32(const unsigned char *bytes) {
    return (uint32_t)bytes[0] |
           ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static inline void store_le32(unsigned char *bytes, uint32_t value) {
    bytes[0] = (unsigned char)value;
    bytes[1] = (unsigned char)(value >> 8);
    bytes[2] = (unsigned char)(value >> 16);
    bytes[3] = (unsigned char)(value >> 24);
}

static inline unsigned char add8(unsigned char left,
                                 unsigned char right) {
    return (unsigned char)(left + right);
}

static unsigned char gf_multiply(unsigned char left,
                                 unsigned char right) {
    unsigned char product = 0;
    unsigned char multiplicand = left;
    unsigned char multiplier = right;

    for (unsigned int bit = 0; bit < 8; ++bit) {
        if (multiplier & 1u)
            product ^= multiplicand;

        const unsigned char high = (unsigned char)(multiplicand & 0x80u);
        multiplicand = (unsigned char)(multiplicand << 1);
        if (high)
            multiplicand ^= 0x1Bu;
        multiplier = (unsigned char)(multiplier >> 1);
    }

    return product;
}

static unsigned char gf_power(unsigned char value, unsigned int exponent) {
    unsigned char result = 1;
    unsigned char factor = value;
    unsigned int remaining = exponent;

    while (remaining != 0) {
        if (remaining & 1u)
            result = gf_multiply(result, factor);
        factor = gf_multiply(factor, factor);
        remaining >>= 1;
    }

    return result;
}

static unsigned char gf_inverse(unsigned char value) {
    if (value == 0)
        return 0;
    return gf_power(value, 254u);
}

static unsigned char substitute_byte(unsigned char value) {
    const unsigned char inverse = gf_inverse(value);
    unsigned char result = inverse;
    result ^= rotl8(inverse, 1);
    result ^= rotl8(inverse, 2);
    result ^= rotl8(inverse, 3);
    result ^= rotl8(inverse, 4);
    result ^= 0x63u;
    return result;
}

static uint32_t nonlinear_word(uint32_t a,
                               uint32_t b,
                               uint32_t c,
                               uint32_t d,
                               uint32_t e,
                               const uint32_t key[6],
                               uint32_t domain,
                               unsigned int round) {
    uint32_t value = a + key[0] + domain;
    value ^= rotl32(c ^ key[1], (round % 23u) + 5u);
    value += (e ^ key[2]) * 0xD6E8FEB9u;
    value = rotl32(value, (round % 13u) + 7u);
    value ^= b + key[3] + (domain ^ 0xA5A5A5A5u);
    value *= 0x9E3779B1u;
    value += rotl32(d ^ key[4], (round % 19u) + 3u);
    value ^= rotl32(a + e + key[5], 11u);
    value += (c ^ d ^ (round * 0x7F4A7C15u));
    return value;
}

static uint32_t avalanche_word(uint32_t value, uint32_t salt) {
    value ^= salt;
    value ^= value >> 16;
    value *= 0x7FEB352Du;
    value ^= value >> 15;
    value *= 0x846CA68Bu;
    value ^= value >> 16;
    return value;
}

static void derive_round_keys(uint32_t keys[64][6], uint32_t domain) {
    uint32_t state[8];
    for (unsigned int i = 0; i < 8; ++i) {
        const uint32_t lane = 0x01010101u * (i + 1u);
        state[i] = kMaster[i] ^ rotl32(domain + lane, (i * 3u) + 5u);
    }

    for (unsigned int round = 0; round < 64; ++round) {
        const uint32_t counter = 0x9E3779B9u * (round + 1u);
        state[0] += counter ^ state[5];
        state[1] ^= rotl32(state[0] + state[7], 7u);
        state[2] += rotl32(state[1] ^ domain, 13u);
        state[3] = rotl32(state[3] + state[2] + counter, 17u);
        state[4] ^= state[3] + 0xA5A5A5A5u + round;
        state[5] += rotl32(state[4] ^ state[0], 19u);
        state[6] = avalanche_word(state[6] + state[5], domain ^ counter);
        state[7] ^= rotl32(state[6] + state[1], 23u);

        const unsigned int base = (round * 5u) & 7u;
        for (unsigned int lane = 0; lane < 6; ++lane) {
            const unsigned int first = (base + lane) & 7u;
            const unsigned int second = (first + 3u) & 7u;
            const unsigned int third = (first + 6u) & 7u;
            const uint32_t salt = domain + counter + (lane * 0x6A09E667u);
            keys[round][lane] = avalanche_word(
                state[first] ^ rotl32(state[second], lane + 5u) ^
                    (state[third] + salt),
                salt ^ state[(first + 1u) & 7u]);
        }
    }
}

static void words_from_bytes(const unsigned char bytes[24],
                             uint32_t words[6]) {
    for (unsigned int lane = 0; lane < 6; ++lane)
        words[lane] = load_le32(bytes + lane * 4u);
}

static void bytes_from_words(const uint32_t words[6],
                             unsigned char bytes[24]) {
    for (unsigned int lane = 0; lane < 6; ++lane)
        store_le32(bytes + lane * 4u, words[lane]);
}

static void feistel_round(uint32_t words[6],
                          const uint32_t round_key[6],
                          uint32_t domain,
                          unsigned int round) {
    const uint32_t feedback = nonlinear_word(
        words[1], words[2], words[3], words[4], words[5],
        round_key, domain, round);
    const uint32_t first = words[0];

    words[0] = words[1];
    words[1] = words[2];
    words[2] = words[3];
    words[3] = words[4];
    words[4] = words[5];
    words[5] = first ^ feedback;
}

static void feistel_forward(unsigned char bytes[24],
                            unsigned int rounds,
                            uint32_t domain) {
    uint32_t words[6];
    uint32_t keys[64][6];
    words_from_bytes(bytes, words);
    derive_round_keys(keys, domain);

    for (unsigned int round = 0; round < rounds; ++round)
        feistel_round(words, keys[round], domain, round);

    bytes_from_words(words, bytes);
}

static void coordinate_round(uint32_t words[6],
                             const uint32_t round_key[6],
                             uint32_t domain,
                             unsigned int round) {
    const unsigned int lane = (round * 5u + domain) % 6u;
    const unsigned int a = (lane + 1u) % 6u;
    const unsigned int b = (lane + 2u) % 6u;
    const unsigned int c = (lane + 3u) % 6u;
    const unsigned int d = (lane + 4u) % 6u;
    const unsigned int e = (lane + 5u) % 6u;
    const uint32_t mixed = nonlinear_word(
        words[a], words[b], words[c], words[d], words[e],
        round_key, domain ^ (round * 0x6A09E667u), round);
    words[lane] ^= mixed;
}

static void coordinate_forward(unsigned char bytes[24],
                               unsigned int rounds,
                               uint32_t domain) {
    uint32_t words[6];
    uint32_t keys[64][6];
    words_from_bytes(bytes, words);
    derive_round_keys(keys, domain ^ 0x51A7E123u);

    for (unsigned int round = 0; round < rounds; ++round)
        coordinate_round(words, keys[round], domain, round);

    bytes_from_words(words, bytes);
}

static uint32_t derive_byte_seed(uint32_t domain) {
    uint32_t seed = 0xB7E15162u ^ domain;
    for (unsigned int i = 0; i < 8; ++i) {
        seed += kMaster[i] ^ (0x9E3779B9u * (i + 1u));
        seed = rotl32(seed, (i * 3u) + 5u);
        seed ^= avalanche_word(kMaster[(i + 3u) & 7u], domain + i);
    }
    return avalanche_word(seed, domain ^ 0x3C6EF372u);
}

static void derive_byte_keys(unsigned char keys[16][24], uint32_t domain) {
    uint32_t state[4];
    uint32_t seed = derive_byte_seed(domain);

    for (unsigned int lane = 0; lane < 4; ++lane) {
        const unsigned int master_index = (lane * 2u + 1u) & 7u;
        state[lane] = kMaster[master_index] ^
                      rotl32(seed + domain + lane, lane * 5u + 3u);
    }

    for (unsigned int round = 0; round < 16; ++round) {
        const uint32_t counter = 0x6A09E667u * (round + 1u);
        state[0] += counter ^ state[3];
        state[1] ^= rotl32(state[0] + domain, 9u);
        state[2] = rotl32(state[2] + state[1] + counter, 15u);
        state[3] += avalanche_word(state[2] ^ state[0], domain + round);

        for (unsigned int index = 0; index < 24; ++index) {
            const unsigned int lane = (index + round) & 3u;
            const unsigned int other = (lane + 1u) & 3u;
            const uint32_t item = state[lane] ^
                rotl32(state[other] + index * 0x3C6EF372u, (index % 23u) + 5u);
            const uint32_t keyed = avalanche_word(
                item + counter + domain + index,
                state[(lane + 2u) & 3u] ^ state[(lane + 3u) & 3u]);
            keys[round][index] = (unsigned char)(keyed >> ((index & 3u) * 8u));
            state[lane] ^= rotl32(keyed + state[other], (index % 19u) + 3u);
        }
    }
}

static unsigned int permutation_destination(unsigned int index,
                                            unsigned int round,
                                            uint32_t domain) {
    const unsigned int shift = (round * 7u + (domain & 0xFFu)) % 24u;
    return (index * 5u + shift) % 24u;
}

static void permute_bytes(unsigned char state[24],
                          unsigned int round,
                          uint32_t domain) {
    unsigned char temporary[24];

    for (unsigned int index = 0; index < 24; ++index) {
        const unsigned int destination =
            permutation_destination(index, round, domain);
        temporary[destination] = state[index];
    }

    for (unsigned int index = 0; index < 24; ++index)
        state[index] = temporary[index];
}

static unsigned char byte_add_mix(unsigned char left,
                                  unsigned char middle,
                                  unsigned char right,
                                  unsigned char key,
                                  unsigned int round,
                                  unsigned int index) {
    unsigned char value = add8(left, key);
    value ^= rotl8((unsigned char)(middle ^ (key + index)),
                   (round % 7u) + 1u);
    value = add8(value,
                 (unsigned char)((right ^ rotl8(key, 3u)) * 0x3Du));
    value ^= rotl8(value, 3u);
    value = add8(value, (unsigned char)(round * 0x1Du + index * 0x27u));
    return value;
}

static void diffuse_add_forward(unsigned char state[24],
                                const unsigned char round_key[24],
                                unsigned int round) {
    for (unsigned int index = 0; index < 24; ++index) {
        const unsigned char left = index > 0
            ? state[index - 1u] : (unsigned char)(round * 0x35u + 0xA7u);
        const unsigned char middle = index > 1
            ? state[index - 2u] : (unsigned char)(round * 0x71u + 0x3Du);
        const unsigned char right = index > 2
            ? state[index - 3u] : (unsigned char)(round * 0x19u + 0xE3u);
        state[index] = add8(state[index], byte_add_mix(
            left, middle, right, round_key[index], round, index));
    }
}

static unsigned char byte_xor_mix(unsigned char left,
                                  unsigned char right,
                                  unsigned char key,
                                  unsigned int round,
                                  unsigned int index) {
    unsigned char value = (unsigned char)(left ^ rotl8(key, (index % 5u) + 1u));
    value = add8(value, (unsigned char)(right * 0xB7u));
    value ^= rotl8((unsigned char)(right + key + round), (round % 5u) + 1u);
    value = add8(value, (unsigned char)(index * 0x39u + round * 0x53u));
    return rotl8(value, (index + round) % 7u + 1u);
}

static void diffuse_xor_forward(unsigned char state[24],
                                const unsigned char round_key[24],
                                unsigned int round) {
    for (unsigned int remaining = 24; remaining > 0; --remaining) {
        const unsigned int index = remaining - 1u;
        const unsigned char left = index + 1u < 24u
            ? state[index + 1u] : (unsigned char)(round * 0x2Bu + 0x51u);
        const unsigned char right = index + 2u < 24u
            ? state[index + 2u] : (unsigned char)(round * 0x47u + 0xC9u);
        state[index] ^= byte_xor_mix(
            left, right, round_key[index], round, index);
    }
}

static void substitute_forward(unsigned char state[24],
                               const unsigned char round_key[24],
                               unsigned int round) {
    for (unsigned int index = 0; index < 24; ++index) {
        const unsigned char first = (unsigned char)(state[index] ^ round_key[index]);
        const unsigned char nonlinear = substitute_byte(first);
        const unsigned int rotation = (round + index) % 7u + 1u;
        const unsigned char second_key = (unsigned char)(
            round_key[(index * 7u + round) % 24u] + index * 0x13u);
        state[index] = (unsigned char)(rotl8(nonlinear, rotation) ^ second_key);
    }
}

static void mix_columns(unsigned char state[24]) {
    for (unsigned int column = 0; column < 6; ++column) {
        const unsigned char a = state[column];
        const unsigned char b = state[column + 6u];
        const unsigned char c = state[column + 12u];
        const unsigned char d = state[column + 18u];
        state[column] = (unsigned char)(
            gf_multiply(a, 2u) ^ gf_multiply(b, 3u) ^ c ^ d);
        state[column + 6u] = (unsigned char)(
            a ^ gf_multiply(b, 2u) ^ gf_multiply(c, 3u) ^ d);
        state[column + 12u] = (unsigned char)(
            a ^ b ^ gf_multiply(c, 2u) ^ gf_multiply(d, 3u));
        state[column + 18u] = (unsigned char)(
            gf_multiply(a, 3u) ^ b ^ c ^ gf_multiply(d, 2u));
    }
}

static void byte_round_forward(unsigned char state[24],
                               const unsigned char round_key[24],
                               unsigned int round,
                               uint32_t domain) {
    substitute_forward(state, round_key, round);
    diffuse_add_forward(state, round_key, round);
    diffuse_xor_forward(state, round_key, round);
    permute_bytes(state, round, domain);
    mix_columns(state);
}

static void byte_layer_forward(unsigned char state[24],
                               unsigned int rounds,
                               uint32_t domain) {
    unsigned char round_keys[16][24];
    derive_byte_keys(round_keys, domain);

    for (unsigned int round = 0; round < rounds; ++round)
        byte_round_forward(state, round_keys[round], round, domain);
}

static unsigned char input_mask_byte(unsigned int index,
                                     uint32_t seed,
                                     unsigned int lane) {
    const uint32_t word = avalanche_word(
        seed + index * 0x9E3779B9u + lane * 0x7F4A7C15u,
        kMaster[(index + lane) & 7u] ^ (index << 16));
    return (unsigned char)(word >> ((index & 3u) * 8u));
}

static void initial_whitening(unsigned char state[24]) {
    uint32_t seed = 0x510E527Fu;

    for (unsigned int lane = 0; lane < 6; ++lane) {
        seed = avalanche_word(seed + kInitialWhitening[lane],
                              kMaster[(lane + 2u) & 7u]);
        for (unsigned int byte = 0; byte < 4; ++byte) {
            const unsigned int index = lane * 4u + byte;
            const unsigned char mask = input_mask_byte(index, seed, lane);
            const unsigned int rotation = (index + lane) % 7u + 1u;
            const unsigned char adjusted = add8(state[index], mask);
            state[index] = (unsigned char)(rotl8(adjusted, rotation) ^
                                            (unsigned char)(seed >> (byte * 8u)));
        }
    }
}

static void final_whitening(unsigned char state[24]) {
    uint32_t seed = 0x1F83D9ABu;

    for (unsigned int lane = 0; lane < 6; ++lane) {
        seed ^= rotl32(kFinalWhitening[lane] + seed, (lane * 3u) + 5u);
        seed = avalanche_word(seed, kMaster[(lane + 5u) & 7u]);
        for (unsigned int byte = 0; byte < 4; ++byte) {
            const unsigned int index = lane * 4u + byte;
            const unsigned char mask = input_mask_byte(index, seed, lane + 7u);
            const unsigned int rotation = (index * 3u + lane) % 7u + 1u;
            const unsigned char keyed = (unsigned char)(
                state[index] ^ (unsigned char)(seed >> (byte * 8u)));
            state[index] = add8(rotl8(keyed, rotation), mask);
        }
    }
}

static void transform_password(const unsigned char input[kInputBytes],
                               unsigned char output[kOutputBytes]) {
    unsigned char state[24];
    memcpy(state, input, sizeof(state));
    initial_whitening(state);
    feistel_forward(state, kFeistelRoundsA, 0x13579BDFu);
    coordinate_forward(state, kCoordinateRoundsA, 0x42B19E37u);
    byte_layer_forward(state, kByteRoundsA, 0x2468ACE0u);
    feistel_forward(state, kFeistelRoundsB, 0xC001D00Du);
    coordinate_forward(state, kCoordinateRoundsB, 0xDEADBEEFu);
    byte_layer_forward(state, kByteRoundsB, 0x5A17C3E9u);
    feistel_forward(state, kFeistelRoundsC, 0x7E4A91B3u);
    final_whitening(state);
    memcpy(output, state, sizeof(state));
}

static int compare_output(const unsigned char left[kOutputBytes],
                          const unsigned char right[kOutputBytes]) {
    unsigned int difference = 0;
    for (unsigned int index = 0; index < kOutputBytes; ++index)
        difference |= (unsigned int)(left[index] ^ right[index]);
    return difference == 0;
}

} // namespace

extern "C" int verify_password(const unsigned char *input, int length) {
    if (input == NULL || length != (int)kInputBytes)
        return 0;

    unsigned char transformed[kOutputBytes];
    transform_password(input, transformed);
    return compare_output(transformed, kExpected);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return 1;
    }

    const size_t length = strlen(argv[1]);
    if (length == kInputBytes &&
        verify_password((const unsigned char *)argv[1], (int)length)) {
        printf("Access granted!\n");
        return 0;
    }

    printf("Access denied.\n");
    return 1;
}
