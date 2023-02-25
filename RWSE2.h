#pragma once
#ifndef RWSE_2
#define RWSE_2

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint64_t u64;

/**
 * Encryption/Decryption flags
 */
enum RWSE2_OPER
{
    OPER_ENCRYPT = 0,
    OPER_DECRYPT
};

/**
 * Key length flags (256bit/384bit/512bit flags)
 */
enum RWSE2_OPT
{
    OPT_256 = 0,
    OPT_384,
    OPT_512
};

/**
 * The union of different pointers used in the implementation
 */
typedef union RWSE2_MSG
{
    u8 *byte;
    u64 *qword;
} msg_t;

/**
 * The round keys structure
 */
typedef struct RWSE2_EXK
{
    int operation;
    int round;
    msg_t msg;
} exk_t;

/**
 * A single block encryption/decryption in RWSE2.
 *
 * @param dst Destination of block
 * @param src Original message/ciphertext
 * @param key Original key
 * @param operation Encryption/Decrytion flag
 * @param option 256bit/384bit/512bit flag
 *
 * @return Encrypted/Decrypted byte amount
 */
int RWSE2_Single(u8 *dst, const u8 *src, const u8 *key, int operation, int option);

/**
 * Key expansion operation that generates round keys.
 *
 * @param key Original key
 * @param operation Encryption/Decryption flag
 * @param option 256bit/384bit/512bit key flag
 *
 * @return Extended key for encryption/decryption
 */
exk_t RWSE2_Key_Expand(const u8 *key, int operation, int option);

/**
 * A direct encryption/decryption in RWSE2 using generated round keys.
 * @param dst Destination of block
 * @param src Original message/ciphertext
 * @param exkey Round keys generated with sealed params
 *
 * @return Encrypted/Decrypted byte amount
 */
int RWSE2_Direct(u8 *dst, const u8 *src, const exk_t *exkey);

#endif // RWSE_2