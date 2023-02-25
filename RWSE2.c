#include "RWSE2.h"

// Constants

/**
 * The substitution box (a.k.a. S-box) of the encryption scheme. \n
 * It is constructed by the following formula: \n
 * SB[i] = (A * (0xa4 pow i)) xor 0xe3. \n
 * pow represents power operation on Galois Field GF(2^8) with
 * the primitive polynomial be 0435 (0b100011101).\n
 * A is a circulant matrix generated from value 0xd3(1 1 0 1 0 0 1 1)
 * which is the product of 'R' and 'W' under the field above.\n
 * 0xa4 represents the sum of hex value of string "RichadoWonosas",
 * which is exactly 0x5a4.
 */
const u8 S_box[256] = {
    0x28, 0x50, 0xa7, 0x91, 0x08, 0x8f, 0x2c, 0x61, 0xd6, 0xa3, 0xa0, 0x79, 0xbd, 0x84, 0x97, 0x47,
    0x46, 0xe1, 0x9d, 0x5b, 0x1c, 0xb7, 0x98, 0xcd, 0x11, 0x43, 0x77, 0x90, 0xaf, 0xf3, 0xea, 0x26,
    0x7d, 0x8c, 0xf5, 0xa5, 0xef, 0xb0, 0x70, 0x78, 0x1a, 0xf8, 0x51, 0x00, 0xed, 0xce, 0xc8, 0x87,
    0x4e, 0x83, 0x7f, 0xf2, 0x4d, 0x5a, 0xbb, 0xcb, 0x5e, 0x8a, 0xba, 0x6c, 0x22, 0x4c, 0xfd, 0xc7,
    0x0d, 0x19, 0x21, 0x95, 0x39, 0xfe, 0x1e, 0xc9, 0x20, 0x32, 0x45, 0x38, 0x59, 0x62, 0x0f, 0x67,
    0x99, 0x6a, 0x6d, 0x85, 0x30, 0x3b, 0x80, 0xa6, 0x36, 0x74, 0x49, 0x6b, 0xca, 0xf9, 0xf6, 0x7c,
    0x2b, 0x89, 0x63, 0xa8, 0x1b, 0x5f, 0x2d, 0xc6, 0xaa, 0x65, 0xe7, 0xd2, 0x92, 0xd1, 0x4b, 0x15,
    0x72, 0x06, 0xa2, 0x07, 0x05, 0x7b, 0xc3, 0x3c, 0x68, 0x13, 0x3d, 0xcf, 0x6f, 0xfb, 0x88, 0xc4,
    0xd4, 0xdd, 0x18, 0x86, 0xe9, 0xff, 0xb9, 0xb5, 0xe6, 0x75, 0xee, 0x17, 0x0c, 0xbe, 0x5d, 0x53,
    0x7e, 0x55, 0x31, 0x9c, 0xfc, 0x60, 0x71, 0xdf, 0x66, 0x3e, 0x16, 0xab, 0xc2, 0x9b, 0x14, 0xd5,
    0x7a, 0x64, 0x40, 0xae, 0x54, 0x96, 0xe0, 0x3a, 0x27, 0xda, 0xf0, 0x33, 0xe2, 0x44, 0x9f, 0x25,
    0xa4, 0x48, 0xcc, 0xb6, 0x3f, 0xb1, 0xd7, 0x04, 0xdc, 0xbf, 0xfa, 0x2f, 0xb8, 0x12, 0x9a, 0xb3,
    0xa9, 0xbc, 0x23, 0xeb, 0x81, 0x01, 0x4a, 0xb2, 0x0e, 0xc0, 0xe5, 0xac, 0x2a, 0x2e, 0x1f, 0x6e,
    0x5c, 0xf4, 0x02, 0x93, 0x76, 0x37, 0xd3, 0x35, 0xad, 0x8d, 0x52, 0xd9, 0x29, 0xf7, 0xdb, 0x57,
    0x4f, 0x24, 0x03, 0x34, 0x0a, 0xf1, 0x94, 0x9e, 0x82, 0xd8, 0x8e, 0x8b, 0x1d, 0x10, 0xe4, 0x0b,
    0x56, 0xe8, 0x58, 0xc5, 0x73, 0xa1, 0xde, 0xc1, 0x42, 0xd0, 0xec, 0x69, 0xb4, 0x41, 0x09, 0xe3};

/**
 * The inverted S-box for decryption.
 */
const u8 S_inv[256] = {
    0x2b, 0xc5, 0xd2, 0xe2, 0xb7, 0x74, 0x71, 0x73, 0x04, 0xfe, 0xe4, 0xef, 0x8c, 0x40, 0xc8, 0x4e,
    0xed, 0x18, 0xbd, 0x79, 0x9e, 0x6f, 0x9a, 0x8b, 0x82, 0x41, 0x28, 0x64, 0x14, 0xec, 0x46, 0xce,
    0x48, 0x42, 0x3c, 0xc2, 0xe1, 0xaf, 0x1f, 0xa8, 0x00, 0xdc, 0xcc, 0x60, 0x06, 0x66, 0xcd, 0xbb,
    0x54, 0x92, 0x49, 0xab, 0xe3, 0xd7, 0x58, 0xd5, 0x4b, 0x44, 0xa7, 0x55, 0x77, 0x7a, 0x99, 0xb4,
    0xa2, 0xfd, 0xf8, 0x19, 0xad, 0x4a, 0x10, 0x0f, 0xb1, 0x5a, 0xc6, 0x6e, 0x3d, 0x34, 0x30, 0xe0,
    0x01, 0x2a, 0xda, 0x8f, 0xa4, 0x91, 0xf0, 0xdf, 0xf2, 0x4c, 0x35, 0x13, 0xd0, 0x8e, 0x38, 0x65,
    0x95, 0x07, 0x4d, 0x62, 0xa1, 0x69, 0x98, 0x4f, 0x78, 0xfb, 0x51, 0x5b, 0x3b, 0x52, 0xcf, 0x7c,
    0x26, 0x96, 0x70, 0xf4, 0x59, 0x89, 0xd4, 0x1a, 0x27, 0x0b, 0xa0, 0x75, 0x5f, 0x20, 0x90, 0x32,
    0x56, 0xc4, 0xe8, 0x31, 0x0d, 0x53, 0x83, 0x2f, 0x7e, 0x61, 0x39, 0xeb, 0x21, 0xd9, 0xea, 0x05,
    0x1b, 0x03, 0x6c, 0xd3, 0xe6, 0x43, 0xa5, 0x0e, 0x16, 0x50, 0xbe, 0x9d, 0x93, 0x12, 0xe7, 0xae,
    0x0a, 0xf5, 0x72, 0x09, 0xb0, 0x23, 0x57, 0x02, 0x63, 0xc0, 0x68, 0x9b, 0xcb, 0xd8, 0xa3, 0x1c,
    0x25, 0xb5, 0xc7, 0xbf, 0xfc, 0x87, 0xb3, 0x15, 0xbc, 0x86, 0x3a, 0x36, 0xc1, 0x0c, 0x8d, 0xb9,
    0xc9, 0xf7, 0x9c, 0x76, 0x7f, 0xf3, 0x67, 0x3f, 0x2e, 0x47, 0x5c, 0x37, 0xb2, 0x17, 0x2d, 0x7b,
    0xf9, 0x6d, 0x6b, 0xd6, 0x80, 0x9f, 0x08, 0xb6, 0xe9, 0xdb, 0xa9, 0xde, 0xb8, 0x81, 0xf6, 0x97,
    0xa6, 0x11, 0xac, 0xff, 0xee, 0xca, 0x88, 0x6a, 0xf1, 0x84, 0x1e, 0xc3, 0xfa, 0x2c, 0x8a, 0x24,
    0xaa, 0xe5, 0x33, 0x1d, 0xd1, 0x22, 0x5e, 0xdd, 0x29, 0x5d, 0xba, 0x7d, 0x94, 0x3e, 0x45, 0x85};

/**
 * Round Constants for key expansion.\n
 * (In byte) rcon[u8] = 0x02 pow u8 in GF(2^8)
 * with little-endian.
 */
const u64 rcon[] = {
    0x8040201008040201ull,
    0x261387cde8743a1dull,
    0xc9ea75b45a2d984cull,
    0xc06030180c06038full,
    0x35944a259c4e279dull,
    0x239fc1ee77b5d46aull,
    0xa05028140a058c46ull,
    0xa1de6fb9d269ba5dull,
    0xbc5e2f99c261be5full,
    0xf0783c1e0f89ca65ull,
    0x7fb1d66bbbd3e7fdull,
    0xe271b65ba3dfe1feull,
    0x884422118643afd9ull,
    0xce67bdd068341a0dull,
    0x93c7edf87c3e1f81ull,
    0xcc663397c5ec763bull};

/**
 * Upper mask for SHUFFLE operation.
 */
const u64 SHUF_UPPER_MASK = 0x9292929292929292ull;

/**
 * Lower mask for SHUFFLE operation.
 */
const u64 SHUF_LOWER_MASK = 0x6d6d6d6d6d6d6d6dull;

// Macro Function Declaration

/**
 * Swap two values.
 *
 * @param a First value
 * @param b Second value
 */
#define swap(a, b) \
    (a) ^= (b);    \
    (b) ^= (a);    \
    (a) ^= (b)

/**
 * Circular left shift operation for qwords.
 */
#define cshl(qword, digit) (((qword) << (digit)) | \
                            ((qword) >> (64 - (digit))))

/**
 * Circular right shift operation for qwords.
 */
#define cshr(qword, digit) (((qword) >> (digit)) | \
                            ((qword) << (64 - (digit))))

/**
 * Single shuffle operation using masks and circular shifts.
 */
#define shuf(qword, digit, type)               \
    cshr(                                      \
        (                                      \
            cshl(                              \
                ((qword) & (SHUF_UPPER_MASK)), \
                (((type)&7) << 3)) |           \
            ((qword) & (SHUF_LOWER_MASK))),    \
        (digit))

/**
 * Inverse operation of shuffle, thus re-shuf.
 */
#define reshuf(qword, digit, type)                        \
    (                                                     \
        (cshl((qword), (digit)) & (SHUF_LOWER_MASK)) |    \
        cshr(                                             \
            (cshl((qword), (digit)) & (SHUF_UPPER_MASK)), \
            (((type)&7) << 3)))

/**
 * A simple permutation for a single qword (of 64 bits long),
 * using S-box.
 *
 * @param word The input qword
 */
#define SubQword(qword) (((u64)(S_box[((qword) >> 56) & 0xff]) << 56) ^ \
                         (((u64)S_box[((qword) >> 48) & 0xff]) << 48) ^ \
                         (((u64)S_box[((qword) >> 40) & 0xff]) << 40) ^ \
                         (((u64)S_box[((qword) >> 32) & 0xff]) << 32) ^ \
                         (((u64)S_box[((qword) >> 24) & 0xff]) << 24) ^ \
                         (((u64)S_box[((qword) >> 16) & 0xff]) << 16) ^ \
                         (((u64)S_box[((qword) >> 8) & 0xff]) << 8) ^   \
                         ((u64)S_box[(qword)&0xffull]))

// Function Declaration

/**
 * Add the round key to the message. Provides confusion needed.
 */
void AddRoundKey(u64 *message, const u64 *round_key);

/**
 * A byte-scale substitution operation. The nonlinear S-box used
 * can prevent differential or linear attacks to the scheme.
 *
 * @param message Message to substitute
 * @param operation Encrypt/Decrypt flag
 */
void Subu8s(u8 *message, int operation);

/**
 * An involutory operation which combines "shuffle" operation that
 * only affects rows with "mix column" operation that mix different
 * columns together, providing diffusion effect needed.
 *
 * @param message Message to shuffle
 */
void RWshuffle(u64 *message);

/**
 * An involutory operation that mixes different columns together using
 * matrix multiplication. \n
 * The matrix of this function is the "Case 27" of the search result
 * of small-index involutory matrix: \n
 * 3 1 2 1 \n
 * 1 3 1 2 \n
 * 2 1 3 1 \n
 * 1 2 1 3 \n
 *
 * @param message Message to mix
 */
void MixColumn(u64 *message);

// Realisation

inline int RWSE2_Single(u8 *dst, const u8 *src, const u8 *key, int operation, int option)
{
    exk_t exkey = RWSE2_Key_Expand(key, operation, option);
    RWSE2_Direct(dst, src, &exkey);
    free(exkey.msg.byte);
    return 32;
}

inline exk_t RWSE2_Key_Expand(const u8 *key, int operation, int option)
{
    int nk, i;
    exk_t result;

    // Complete params
    result.operation = operation;
    switch (option)
    {
    default:
    case OPT_256:
        nk = 4;
        result.round = 12;
        break;
    case OPT_384:
        nk = 6;
        result.round = 15;
        break;
    case OPT_512:
        nk = 8;
        result.round = 18;
        break;
    }
    result.msg.byte = (u8 *)calloc((result.round + 1) << 2, sizeof(u64));

    // Initial keys
    memcpy(result.msg.byte, key, sizeof(u64) * nk);

    // Generate remaining round key
    for (i = nk; i < ((result.round + 1) << 2); i++)
    {
        if (i % nk == 0)
            result.msg.qword[i] =
                result.msg.qword[i - nk] ^ SubQword(shuf(result.msg.qword[i - 1], 25, 4)) ^ rcon[i / nk - 1];
        else if (i % nk == (nk >> 1))
            result.msg.qword[i] = result.msg.qword[i - nk] ^ SubQword(result.msg.qword[i - 1]);
        else
            result.msg.qword[i] = result.msg.qword[i - nk] ^ result.msg.qword[i - 1];
    }

    // Process decryption key
    if (operation == OPER_DECRYPT)
    {
        // Shuffle round key
        for (i = 4; i < (result.round << 2); i += 4)
            RWshuffle(result.msg.qword + i);

        // Reorder round key
        for (i = 0; i < ((result.round + 1) >> 1); i++)
        {
            swap(result.msg.qword[(i << 2)], result.msg.qword[((result.round - i) << 2)]);
            swap(result.msg.qword[(i << 2) + 1], result.msg.qword[((result.round - i) << 2) + 1]);
            swap(result.msg.qword[(i << 2) + 2], result.msg.qword[((result.round - i) << 2) + 2]);
            swap(result.msg.qword[(i << 2) + 3], result.msg.qword[((result.round - i) << 2) + 3]);
        }
    }

    return result;
}

inline int RWSE2_Direct(u8 *dst, const u8 *src, const exk_t *exkey)
{
    int i;
    u64 *dst64 = (u64 *)dst;

    // Copy contents to destination position
    memcpy(dst, src, sizeof(u8) * 32);

    // First round
    AddRoundKey(dst64, exkey->msg.qword);
    RWshuffle(dst64);
    // Rounds
    for (i = 1; i <= exkey->round; i++)
    {
        Subu8s(dst, exkey->operation);
        RWshuffle(dst64);
        AddRoundKey(dst64, exkey->msg.qword + (i << 2));
    }

    return 32;
}

inline void AddRoundKey(u64 *message, const u64 *round_key)
{
    message[0] ^= round_key[0];
    message[1] ^= round_key[1];
    message[2] ^= round_key[2];
    message[3] ^= round_key[3];
}

inline void Subu8s(u8 *message, int operation)
{
    int i;
    for (i = 0; i < 32; i++)
        message[i] = (operation == OPER_ENCRYPT) ? S_box[message[i]] : S_inv[message[i]];
}

inline void RWshuffle(u64 *message)
{
    message[0] = shuf(message[0], 3, 1);
    message[1] = shuf(message[1], 23, 3);
    message[2] = shuf(message[2], 41, 5);
    message[3] = shuf(message[3], 61, 7);
    MixColumn(message);
    message[0] = reshuf(message[0], 3, 1);
    message[1] = reshuf(message[1], 23, 3);
    message[2] = reshuf(message[2], 41, 5);
    message[3] = reshuf(message[3], 61, 7);
}

inline void MixColumn(u64 *message)
{
    u64 temp[4], reg[2];

    reg[0] = (message[0] ^ message[2]) & 0x8080808080808080ull;
    reg[0] = (reg[0] >> 7) ^ (reg[0] >> 5) ^ (reg[0] >> 4) ^ (reg[0] >> 3) ^ (reg[0] << 1);
    reg[1] = (message[1] ^ message[3]) & 0x8080808080808080ull;
    reg[1] = (reg[1] >> 7) ^ (reg[1] >> 5) ^ (reg[1] >> 4) ^ (reg[1] >> 3) ^ (reg[1] << 1);

    temp[0] = message[0] ^ message[1] ^ message[3] ^ ((message[0] ^ message[2]) << 1) ^ reg[0];
    temp[1] = message[1] ^ message[2] ^ message[0] ^ ((message[1] ^ message[3]) << 1) ^ reg[1];
    temp[2] = message[2] ^ message[3] ^ message[1] ^ ((message[2] ^ message[0]) << 1) ^ reg[0];
    temp[3] = message[3] ^ message[0] ^ message[2] ^ ((message[3] ^ message[1]) << 1) ^ reg[1];

    message[0] = temp[0];
    message[1] = temp[1];
    message[2] = temp[2];
    message[3] = temp[3];
}
