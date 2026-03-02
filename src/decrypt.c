/*
 * src/decrypt.c
 * Core decryption logic that reverses the obfuscation done at compile time.
 */

#include "internal.h"

/*
 * Decrypts a chunk of bytes.
 *
 * For each byte, we:
 * 1. Calculate the keystream byte (4-seed bilinear VKF, mirrors OBF_KS in cipher.h).
 * 2. Figure out the seed-dependent rotation amount (mirrors OBF_ROT in cipher.h).
 * 3. Reverse the S-box substitution, undo the XOR, and rotate it back to get the original byte.
 *
 * We use `register volatile` here to stop the compiler from getting too smart
 * and optimizing away our decryption steps, which could leave clues in the binary.
 */
static OBFAPI_NOINLINE OBFAPI_OPTNONE
void obf_decrypt_bytes(const unsigned char *enc, size_t n,
                       unsigned char s0, unsigned char s1,
                       unsigned char s2, unsigned char s3,
                       unsigned char *out)
{
    OBF_OPAQUE_PRED();
    const unsigned char *sbox_inv = g_obf_ctx.sbox_inv;

    for (size_t i = 0u; i < n; i++) {
        /* 6-cross-product + i² keystream — must mirror OBF_KS(i) in cipher.h */
        register volatile unsigned char ki = (unsigned char)((
            (unsigned int)s0 * ((unsigned int)i * 89u  + 1u)  +
            (unsigned int)s1 * ((unsigned int)i * 97u  + 3u)  +
            (unsigned int)s2 * ((unsigned int)i * 113u + 7u)  +
            (unsigned int)s3 * ((unsigned int)i * 127u + 11u) +
            (unsigned int)s0 * (unsigned int)s1 * ((unsigned int)i * 5u  + 2u) +
            (unsigned int)s0 * (unsigned int)s2 * ((unsigned int)i * 13u + 5u) +
            (unsigned int)s0 * (unsigned int)s3 * ((unsigned int)i * 17u + 9u) +
            (unsigned int)s1 * (unsigned int)s2 * ((unsigned int)i * 19u + 4u) +
            (unsigned int)s1 * (unsigned int)s3 * ((unsigned int)i * 23u + 6u) +
            (unsigned int)s2 * (unsigned int)s3 * ((unsigned int)i * 29u + 8u) +
            (unsigned int)i  * (unsigned int)i  * 37u +
            (unsigned int)i  * 167u + 251u
        ) & 0xFFu);

        /* 4-seed rotation — must mirror OBF_ROT(i) in cipher.h */
        register volatile unsigned char r = (unsigned char)((
            (unsigned int)i * 37u +
            (unsigned int)s0 +
            (unsigned int)s1 * 3u +
            (unsigned int)s2 * 5u +
            (unsigned int)s3 * 7u
        ) % 7u + 1u);

        register volatile unsigned char c = enc[i];

        unsigned char p_xr  = sbox_inv[(unsigned int)c];
        unsigned char p_rot = (unsigned char)((unsigned int)p_xr ^ (unsigned int)ki);
        out[i] = (unsigned char)(
            ((unsigned int)p_rot >> (unsigned int)r) |
            ((unsigned int)p_rot << (8u - (unsigned int)r)));
    }
}

/*
 * Main function to decrypt a blob of data.
 * The first four bytes of the blob are the "seeds", hidden via the S-box.
 * We uncover them first, then use them to decrypt the rest of the string.
 */
OBFAPI OBFAPI_NOINLINE OBFAPI_OPTNONE
const char *obf_decrypt(const unsigned char *blob, size_t len,
                        unsigned char *out_buf)
{
    OBF_OPAQUE_PRED();
    if (!blob || !out_buf) { return (const char *)out_buf; }
    if (!atomic_load_explicit(&g_obf_ctx.initialized, memory_order_acquire)) { obf_init(); }
    if (len < 5u) { out_buf[0] = 0u; return (const char *)out_buf; }

    /* Unhide the seeds */
    register volatile unsigned char s0 = g_obf_ctx.sbox_inv[(unsigned int)blob[0]];
    register volatile unsigned char s1 = g_obf_ctx.sbox_inv[(unsigned int)blob[1]];
    register volatile unsigned char s2 = g_obf_ctx.sbox_inv[(unsigned int)blob[2]];
    register volatile unsigned char s3 = g_obf_ctx.sbox_inv[(unsigned int)blob[3]];

    size_t n = len - 4u;
    if (n > (size_t)OBF_MAX_LEN) { n = (size_t)OBF_MAX_LEN; }

    obf_decrypt_bytes(blob + 4, n,
                      (unsigned char)s0, (unsigned char)s1,
                      (unsigned char)s2, (unsigned char)s3,
                      out_buf);
    return (const char *)out_buf;
}
