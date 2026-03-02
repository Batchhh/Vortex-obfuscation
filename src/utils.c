/*
 * src/utils.c
 * Utility functions for wiping memory securely and decoding numbers.
 */

/* Apple platforms need this to unlock memset_s.
 * We have to declare it before including any system headers. */
#if defined(__APPLE__) && !defined(__STDC_WANT_LIB_EXT1__)
#   define __STDC_WANT_LIB_EXT1__ 1
#endif

#if defined(_WIN32) || defined(_WIN64)
#   include <winbase.h>   /* SecureZeroMemory */
#endif

#include "internal.h"
#include <string.h>   /* memset_s (Apple/C11 Annex K) / explicit_bzero (BSDs) */

/* 
 * Safely fills a buffer with zeros so that sensitive data (like decrypted strings)
 * isn't left in memory.
 *
 * Compilers love to delete memory-clearing loops if they think the memory
 * won't be used again (this is a common security issue). We try to use
 * the most reliable, un-optimizable function the platform offers:
 * 1. memset_s (Apple)
 * 2. explicit_bzero (BSDs)
 * 3. A volatile loop as a fallback (which works nicely on GCC, Clang, and MSVC).
 */
OBFAPI OBFAPI_NOINLINE
void obf_zero(unsigned char *buf, size_t len)
{
#if defined(__APPLE__) && defined(__STDC_LIB_EXT1__)
    memset_s(buf, len, 0, len);
#elif defined(__OpenBSD__) || defined(__FreeBSD__) || \
      defined(__NetBSD__)  || defined(__DragonFly__)
    explicit_bzero(buf, len);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(buf, len, 0, len);
#elif defined(_WIN32) || defined(_WIN64)
    SecureZeroMemory(buf, len);   /* guaranteed not optimised away */
#else
    volatile unsigned char *p = buf;
    while (len--) { *p++ = 0u; }
#endif
}

/* Make sure floats are 32 bits and doubles are 64 bits.
 * Our decoding logic relies on this to work correctly. */
_Static_assert(sizeof(float)  == sizeof(unsigned int),
               "OBF_FLOAT requires sizeof(float) == sizeof(unsigned int)");
_Static_assert(sizeof(double) == sizeof(unsigned long long),
               "OBF_DOUBLE requires sizeof(double) == sizeof(unsigned long long)");

/* 
 * Decodes an integer that was obfuscated by OBF_INT.
 * 
 * At compile time, the integer was XORed and then rotated.
 * We undo that here by rotating back and XORing again.
 *
 * We do the calculation using volatile variables so the compiler
 * can't trace the math back to the caller and figure out the original number.
 */
OBFAPI OBFAPI_NOINLINE OBFAPI_OPTNONE
int obf_decode_int(unsigned int enc, unsigned int key)
{
    OBF_OPAQUE_PRED();
    volatile unsigned int rot    = ((key >> 24u) | 1u) & 0x1Fu;
    volatile unsigned int rotl   = (enc << (unsigned int)rot) |
                                   (enc >> (32u - (unsigned int)rot));
    volatile unsigned int result = (unsigned int)rotl ^ key;
    return (int)result;
}

/* 
 * Decodes a 32-bit float that was hidden by OBF_FLOAT.
 * Once we decode the bits, we use memcpy to copy them into a float variable.
 * This is the safest way in C to change types without upsetting the compiler.
 */
OBFAPI OBFAPI_NOINLINE OBFAPI_OPTNONE
float obf_decode_float(unsigned int enc, unsigned int key)
{
    OBF_OPAQUE_PRED();
    volatile unsigned int rot    = ((key >> 24u) | 1u) & 0x1Fu;
    volatile unsigned int rotl   = (enc << (unsigned int)rot) |
                                   (enc >> (32u - (unsigned int)rot));
    volatile unsigned int bits   = (unsigned int)rotl ^ key;
    unsigned int bits_val        = (unsigned int)bits;
    float result;
    memcpy(&result, &bits_val, sizeof(float));
    return result;
}

/* 
 * Decodes a 64-bit double that was hidden by OBF_DOUBLE.
 * Works just like the float version, but with 64-bit math and a bigger key.
 */
OBFAPI OBFAPI_NOINLINE OBFAPI_OPTNONE
double obf_decode_double(unsigned long long enc, unsigned long long key)
{
    OBF_OPAQUE_PRED();
    volatile unsigned int       rot  = ((unsigned int)(key >> 56u) | 1u) & 0x3Fu;
    volatile unsigned long long rotl = (enc << (unsigned int)rot) |
                                       (enc >> (64u - (unsigned int)rot));
    volatile unsigned long long bits = (unsigned long long)rotl ^ key;
    unsigned long long bits_val      = (unsigned long long)bits;
    double result;
    memcpy(&result, &bits_val, sizeof(double));
    return result;
}

/* 
 * Decodes a size_t offset that was hidden by OBF_OFFSET.
 * Uses 64-bit math to safely cover both 32-bit and 64-bit size_t.
 */
OBFAPI OBFAPI_NOINLINE OBFAPI_OPTNONE
size_t obf_decode_offset(unsigned long long enc, unsigned long long key)
{
    OBF_OPAQUE_PRED();
    volatile unsigned int       rot  = ((unsigned int)(key >> 56u) | 1u) & 0x3Fu;
    volatile unsigned long long rotl = (enc << (unsigned int)rot) |
                                       (enc >> (64u - (unsigned int)rot));
    volatile unsigned long long result = (unsigned long long)rotl ^ key;
    return (size_t)result;
}
