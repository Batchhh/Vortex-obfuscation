/*
 * vortex/cipher.h
 * The compile-time half of the VORTEX cipher.
 *
 * This file contains the macros that actually encrypt your strings and numbers
 * while your code is compiling. The math here exactly matches the decryption
 * logic in `src/decrypt.c`.
 *
 * If OBF_DISABLE is defined, we skip all of this and just use the transparent
 * macros defined in `config.h`.
 *
 * HOW IT WORKS
 * ------------
 * 1. Keystream (VKF): We generate a stream of bytes based on two seeds (SEED0 and SEED1)
 *    and the position of the character we're encrypting. We use a formula involving
 *    primes and Fibonacci numbers to make it non-linear.
 *
 * 2. Per-byte Encryption: For each byte in a string:
 *    - We rotate its bits (the rotation amount depends on its position).
 *    - We pass it through an S-box (a substitution table to scramble it further).
 *    - We XOR it with the keystream byte.
 *
 * 3. Blob Format: The final encrypted string in your binary looks like this:
 *    [S[SEED0]] [S[SEED1]] [S[SEED2]] [S[SEED3]] [Encrypted Char 0] [Encrypted Char 1] ...
 *
 * You shouldn't need to include this file directly; just use `#include "obfuscate.h"`.
 */

#ifndef VORTEX_CIPHER_H
#define VORTEX_CIPHER_H

#ifndef OBF_DISABLE  /* ═══ entire cipher engine is compile-time only ═══ */

/* ── Per-string keystream seeds ─────────────────────────────────────────
 * Evaluated at each OBF_STR expansion; __LINE__ uniquifies every call.  */
#define OBF_SEED0  ((unsigned char)( (OBF_KEY)         & 0xFFu))
#define OBF_SEED1  ((unsigned char)(((OBF_KEY) >>  8u) & 0xFFu))
#define OBF_SEED2  ((unsigned char)(((OBF_KEY) >> 16u) & 0xFFu))
#define OBF_SEED3  ((unsigned char)(((OBF_KEY) >> 24u) & 0xFFu))

/* ── Fibonacci key schedule (reference / verification) ──────────────────
 * OBF_KFIB(a,b,c) = (a·SEED0 + b·SEED1 + c) mod 256
 * Coefficients below were derived by symbolically unrolling the recurrence
 * for n = 0..31.  Spot-check: SEED0=1,SEED1=0 → K[5]=169·1+129·0+82=251;
 * loop gives 251 ✓.  (SEED0=0,SEED1=1) → K[4]=0+13+95=108; loop=108 ✓.
 * These macros are NOT called from OBF_ENC_ALL; OBF_KS is used instead.  */
#define OBF_KFIB(a,b,c) \
    ((unsigned char)(((unsigned int)(a)*(unsigned int)(OBF_SEED0) \
                    + (unsigned int)(b)*(unsigned int)(OBF_SEED1) \
                    + (unsigned int)(c)) & 0xFFu))

#define OBF_K0   OBF_KFIB(  1,   0,   0)
#define OBF_K1   OBF_KFIB(  0,   1,   0)
#define OBF_K2   OBF_KFIB( 13,   7,  65)
#define OBF_K3   OBF_KFIB( 91,  62,  25)
#define OBF_K4   OBF_KFIB( 38,  13,  95)
#define OBF_K5   OBF_KFIB(169, 129,  82)
#define OBF_K6   OBF_KFIB(141,  48, 150)
#define OBF_K7   OBF_KFIB(112, 221, 218)
#define OBF_K8   OBF_KFIB( 57, 123,  59)
#define OBF_K9   OBF_KFIB( 63, 150, 103)
#define OBF_K10  OBF_KFIB(158,  89, 153)
#define OBF_K11  OBF_KFIB(133,  13,  68)
#define OBF_K12  OBF_KFIB(169, 224, 140)
#define OBF_K13  OBF_KFIB( 96, 201,  68)
#define OBF_K14  OBF_KFIB( 53, 223,   5)
#define OBF_K15  OBF_KFIB( 83,  78, 181)
#define OBF_K16  OBF_KFIB(246,  89,  99)
#define OBF_K17  OBF_KFIB(241, 101,  38)
#define OBF_K18  OBF_KFIB( 21,  72,  98)
#define OBF_K19  OBF_KFIB(208,  25, 254)
#define OBF_K20  OBF_KFIB(193,  87,  95)
#define OBF_K21  OBF_KFIB(215, 166,   3)
#define OBF_K22  OBF_KFIB(174, 245, 125)
#define OBF_K23  OBF_KFIB(173,  33,  56)
#define OBF_K24  OBF_KFIB(145,  88, 152)
#define OBF_K25  OBF_KFIB(192,  21, 200)
#define OBF_K26  OBF_KFIB(157,  11,   9)
#define OBF_K27  OBF_KFIB( 11,  94,  81)
#define OBF_K28  OBF_KFIB( 70,  33, 167)
#define OBF_K29  OBF_KFIB(121, 173, 186)
#define OBF_K30  OBF_KFIB(221, 224, 174)
#define OBF_K31  OBF_KFIB( 48,  89,  98)

/* ── VORTEX Keystream Function (VKF) ─────────────────────────────────
 * Direct O(1) formula — no table lookup, no ternary chains.
 * Evaluates to a compile-time constant when i is a literal integer.
 *
 * Security — three layers of hardening vs. the previous design:
 *
 *   1. All 6 pairwise seed cross-products (S0S1, S0S2, S0S3, S1S2,
 *      S1S3, S2S3) make the keystream fully quadratic in all four seeds.
 *      A known-plaintext attack now requires solving a system of 6
 *      coupled quadratic equations over Z/256Z — infeasible without
 *      a brute-force over 2^32 seed combinations.
 *
 *   2. The i² term introduces super-linear position dependence so
 *      keystream bytes at different indices cannot be related by a
 *      simple arithmetic progression, defeating linear extrapolation.
 *
 *   3. Each linear coefficient (89, 97, 113, 127) and each bilinear
 *      coefficient (5, 13, 17, 19, 23, 29) are distinct primes that
 *      maximise the algebraic independence of the six cross-product
 *      contributions modulo 256.                                        */
#define OBF_KS(i) \
    ((unsigned char)(( \
        (unsigned int)(OBF_SEED0) * ((unsigned int)(i)*89u  + 1u)  \
      + (unsigned int)(OBF_SEED1) * ((unsigned int)(i)*97u  + 3u)  \
      + (unsigned int)(OBF_SEED2) * ((unsigned int)(i)*113u + 7u)  \
      + (unsigned int)(OBF_SEED3) * ((unsigned int)(i)*127u + 11u) \
      + (unsigned int)(OBF_SEED0) * (unsigned int)(OBF_SEED1) * ((unsigned int)(i)*5u  + 2u)  \
      + (unsigned int)(OBF_SEED0) * (unsigned int)(OBF_SEED2) * ((unsigned int)(i)*13u + 5u)  \
      + (unsigned int)(OBF_SEED0) * (unsigned int)(OBF_SEED3) * ((unsigned int)(i)*17u + 9u)  \
      + (unsigned int)(OBF_SEED1) * (unsigned int)(OBF_SEED2) * ((unsigned int)(i)*19u + 4u)  \
      + (unsigned int)(OBF_SEED1) * (unsigned int)(OBF_SEED3) * ((unsigned int)(i)*23u + 6u)  \
      + (unsigned int)(OBF_SEED2) * (unsigned int)(OBF_SEED3) * ((unsigned int)(i)*29u + 8u)  \
      + (unsigned int)(i) * (unsigned int)(i) * 37u                                            \
      + (unsigned int)(i)*167u + 251u                                                          \
    ) & 0xFFu))

/* ── Compile-time affine S-box  S[x] = (A·x + B) mod 256 ─────────── */
#define OBF_SBOX(x) \
    ((unsigned char)(((unsigned int)(OBF_SBOX_A) * (unsigned int)(x) \
                    + (unsigned int)(OBF_SBOX_B)) & 0xFFu))

/* ── Per-byte primitives ─────────────────────────────────────────────
 * OBF_ROT: rotation in [1,7] — both shifts stay within [1,7] (no UB).
 *   All four seeds contribute to the rotation base so recovering the
 *   rotation pattern no longer singles out SEED0 alone; an attacker
 *   must solve (S0 + 3·S1 + 5·S2 + 7·S3) mod 7 for four unknowns.
 * OBF_ROTL8_CT: compile-time 8-bit left rotation.
 * OBF_EC: full per-character compile-time encryption.                  */
#define OBF_ROT(i)  ((unsigned int)(( \
      (unsigned int)(i)*37u             \
    + (unsigned int)(OBF_SEED0)         \
    + (unsigned int)(OBF_SEED1)*3u      \
    + (unsigned int)(OBF_SEED2)*5u      \
    + (unsigned int)(OBF_SEED3)*7u      \
    ) % 7u) + 1u)

#define OBF_ROTL8_CT(b,r) \
    ((unsigned char)(((unsigned int)(b) << (r)) | ((unsigned int)(b) >> (8u - (r)))))

/* Encrypt character s[i]; pad with encrypted-null beyond sizeof(s).   */
#define OBF_EC(s,i) \
    ((unsigned char)(                                                        \
        (size_t)(i) < sizeof(s)                                              \
        ? OBF_SBOX(OBF_ROTL8_CT((unsigned char)((s)[(i)]), OBF_ROT(i))      \
                   ^ OBF_KS(i))                                              \
        : OBF_SBOX(OBF_ROTL8_CT(0u, OBF_ROT(i)) ^ OBF_KS(i))               \
    ))

/* ── Blob expansion macros ───────────────────────────────────────────
 * Built in doublings to limit preprocessor argument-copy overhead.
 * Each OBF_EC is a flat O(1) expression; AST growth is linear in depth. */
#define OBF_ENC4(s,B) \
    OBF_EC(s,(B)+0),OBF_EC(s,(B)+1),OBF_EC(s,(B)+2),OBF_EC(s,(B)+3)
#define OBF_ENC8(s,B)   OBF_ENC4(s,(B)),   OBF_ENC4(s,(B)+4)
#define OBF_ENC16(s,B)  OBF_ENC8(s,(B)),   OBF_ENC8(s,(B)+8)
#define OBF_ENC32(s,B)  OBF_ENC16(s,(B)),  OBF_ENC16(s,(B)+16)
#define OBF_ENC64(s,B)  OBF_ENC32(s,(B)),  OBF_ENC32(s,(B)+32)
#define OBF_ENC128(s,B) OBF_ENC64(s,(B)),  OBF_ENC64(s,(B)+64)
#define OBF_ENC256(s)   OBF_ENC128(s,0),   OBF_ENC128(s,128)

/* Select expansion depth based on OBF_MAX_LEN */
#if   OBF_MAX_LEN <= 32
#   define OBF_ENC_ALL(s)  OBF_ENC32(s,0)
#elif OBF_MAX_LEN <= 64
#   define OBF_ENC_ALL(s)  OBF_ENC64(s,0)
#elif OBF_MAX_LEN <= 128
#   define OBF_ENC_ALL(s)  OBF_ENC128(s,0)
#else
#   define OBF_ENC_ALL(s)  OBF_ENC256(s)
#endif

/* ── OBF_WITH ────────────────────────────────────────────────────────
 * Decrypt string literal s exactly when needed; zero automatically on exit.
 *
 * Usage:
 *   OBF_WITH(var, "secret") {
 *       do_something(var);   // var is const char* pointing to plaintext
 *   }
 *   // var is no longer in scope; stack buffer is zeroed
 *
 * Three nested for-loops implement the RAII pattern without heap, VLA, or
 * GCC statement-expressions:
 *
 *   Loop 1  — sets up a one-shot flag (var##__once_).
 *   Loop 2  — allocates the stack buffer; its UPDATE expression calls
 *             obf_zero() and clears the flag — runs on every exit path,
 *             including break, goto, and early return from the body.
 *   Loop 3  — performs the actual decryption into the buffer and binds
 *             var; its UPDATE clears the flag so loops 1 and 2 also exit.
 *
 * The encrypted blob is an inline compound literal in read-only storage.
 * The plaintext buffer lives only while the body executes.
 *
 * Lifetime note: do NOT use var outside the braces.                    */
#define OBF_WITH(var, s)                                                             \
    for (int var##__once_ = 1; var##__once_; var##__once_ = 0)                      \
    for (unsigned char var##__buf_[OBF_MAX_LEN] = {0};                               \
         var##__once_;                                                                \
         obf_zero(var##__buf_, (size_t)OBF_MAX_LEN), var##__once_ = 0)              \
    for (const char *var = (                                                          \
             (void)sizeof(struct {                                                    \
                 _Static_assert(sizeof(s) <= (size_t)(OBF_MAX_LEN),                  \
                                "OBF_WITH: string length exceeds OBF_MAX_LEN");       \
                 char obf_sa_;                                                        \
             }),                                                                      \
             obf_decrypt(                                                             \
                 (const unsigned char[]){                                             \
                     OBF_SBOX(OBF_SEED0), OBF_SBOX(OBF_SEED1),                      \
                     OBF_SBOX(OBF_SEED2), OBF_SBOX(OBF_SEED3),                      \
                     OBF_ENC_ALL(s)                                                  \
                 },                                                                   \
                 (size_t)(sizeof(s) + 4u), var##__buf_)                              \
         );                                                                           \
         var##__once_; var##__once_ = 0)

/* ── OBF_INT ─────────────────────────────────────────────────────────
 * Stores ROTR32(n XOR OBF_INT_KEY, OBF_INT_ROT) in the binary.
 *
 * OBF_INT_ROT = ((key >> 24) | 1) & 0x1F
 *   Forcing bit 0 keeps rot in {1,3,5,…,31} — never 0 or 32, so both
 *   shifts in ROTR32 are within [1,31] and well-defined on unsigned int.
 *
 * obf_decode_int() derives rot from key internally and applies ROTL32
 * before XOR-ing, so the compiler cannot fold the round-trip to identity.
 * An attacker must now derive the rotation from the key constant, rotate,
 * then XOR — compared to the previous single-XOR.                       */
#define OBF_INT_KEY \
    ((unsigned int)(((OBF_KEY) ^ ((OBF_KEY) >> 16u)) & 0x7FFFFFFFu))

#define OBF_INT_ROT \
    ((unsigned int)(((OBF_INT_KEY) >> 24u) | 1u) & 0x1Fu)

#define OBF_ROTR32(v,r) \
    (((unsigned int)(v) >> (r)) | ((unsigned int)(v) << (32u - (r))))

#define OBF_INT(n) \
    (obf_decode_int(                                                       \
        OBF_ROTR32((unsigned int)(n) ^ OBF_INT_KEY, OBF_INT_ROT),         \
        OBF_INT_KEY                                                        \
    ))

/* ── OBF_FLOAT ───────────────────────────────────────────────────────
 * Obfuscate a float constant.  The binary stores the IEEE 754 bit pattern
 * after ROTR32(bits XOR key, rot); the plaintext float never appears.
 *
 * OBF_FLOAT_BITS(f) extracts the 32-bit bit pattern of float f using a
 * union compound literal — C explicitly permits union type-punning
 * (C11 §6.5.2.3 footnote 95).  The compiler constant-folds the expression
 * at -O1+, so only the encoded integer is embedded in the binary.
 *
 * Requires -O1 or higher to be effective (the Makefile default is -O2).
 * In OBF_DISABLE mode OBF_FLOAT(f) expands to (float)(f) with no overhead.*/
#define OBF_FLOAT_BITS(f) \
    (((union { float obf_f_; unsigned int obf_u_; }) \
      {.obf_f_ = (float)(f)}).obf_u_)

#define OBF_FLOAT(f) \
    (obf_decode_float(                                                     \
        OBF_ROTR32(OBF_FLOAT_BITS(f) ^ OBF_INT_KEY, OBF_INT_ROT),        \
        OBF_INT_KEY                                                        \
    ))

/* ── OBF_DOUBLE ──────────────────────────────────────────────────────
 * Same scheme as OBF_FLOAT but for 64-bit double constants.
 *
 * OBF_DOUBLE_KEY — 64-bit key built by combining two 32-bit halves:
 *   low  32 bits = OBF_INT_KEY
 *   high 32 bits = OBF_INT_KEY XOR OBF_GSEED  (independent contribution)
 *
 * OBF_DOUBLE_ROT — odd value in [1,63]; derived from bits 63-56 of the
 *   key so both shifts in ROTR64 stay within [1,63] (no shift-UB).
 *
 * Requires -O1 or higher (Makefile default is -O2).                    */
#define OBF_DOUBLE_BITS(d) \
    (((union { double obf_d_; unsigned long long obf_u_; }) \
      {.obf_d_ = (double)(d)}).obf_u_)

#define OBF_DOUBLE_KEY \
    ((unsigned long long)(OBF_INT_KEY) | \
     ((unsigned long long)((unsigned int)(OBF_INT_KEY) ^ \
                           (unsigned int)(OBF_GSEED))    \
      << 32u))

#define OBF_DOUBLE_ROT \
    ((unsigned int)(((unsigned int)((OBF_DOUBLE_KEY) >> 56u) | 1u) & 0x3Fu))

#define OBF_ROTR64(v,r) \
    (((unsigned long long)(v) >> (r)) | \
     ((unsigned long long)(v) << (64u - (r))))

#define OBF_DOUBLE(d) \
    (obf_decode_double(                                                    \
        OBF_ROTR64(OBF_DOUBLE_BITS(d) ^ OBF_DOUBLE_KEY, OBF_DOUBLE_ROT), \
        OBF_DOUBLE_KEY                                                     \
    ))

/* ── OBF_OFFSET ──────────────────────────────────────────────────────
 * Obfuscate a memory offset (size_t). Uses 64-bit math so it safely
 * covers both 32-bit and 64-bit architectures without UB.
 * In OBF_DISABLE mode, OBF_OFFSET(n) expands to (size_t)(n).           */
#define OBF_OFFSET(n) \
    (obf_decode_offset(                                                    \
        OBF_ROTR64((unsigned long long)(n) ^ OBF_DOUBLE_KEY, OBF_DOUBLE_ROT), \
        OBF_DOUBLE_KEY                                                     \
    ))

/* ── OBF_STRING ──────────────────────────────────────────────────────
 * Single-line string decryption: decrypts at the declaration point and
 * auto-zeroes the plaintext buffer when var goes out of scope.
 *
 * Usage:
 *   OBF_STRING(pwd, "my-password");
 *   login(server, pwd);
 *   // pwd is zeroed automatically here — no block, no manual cleanup
 *
 * On GCC/Clang the buffer carries __attribute__((cleanup(...))) so
 * obf_zero() fires exactly when var goes out of scope, on every exit
 * path including early return and goto.
 *
 * On MSVC / unknown compilers the cleanup attribute is unavailable;
 * the macro still works but the buffer is NOT auto-zeroed.  Use
 * OBF_WITH(var, s) { ... } for guaranteed cleanup there.             */

/* obf_buf_cleanup_ is declared as a static inline in api.h (after obf_zero).
 * It is referenced here by name only — the reference is resolved at the
 * call sites where OBF_STRING is expanded, after api.h is included.    */
#if defined(__GNUC__) || defined(__clang__)

#define OBF_STRING(var, s)                                                   \
    (void)sizeof(struct {                                                     \
        _Static_assert(sizeof(s) <= (size_t)(OBF_MAX_LEN),                   \
                       "OBF_STRING: string length exceeds OBF_MAX_LEN");      \
        char obf_sa_;                                                         \
    });                                                                       \
    unsigned char var##__buf_[OBF_MAX_LEN] = {0};                            \
    unsigned char *var##__gc_                                                 \
        __attribute__((cleanup(obf_buf_cleanup_))) = var##__buf_;            \
    const char *var = obf_decrypt(                                            \
        (const unsigned char[]){OBF_SBOX(OBF_SEED0), OBF_SBOX(OBF_SEED1),   \
                                 OBF_SBOX(OBF_SEED2), OBF_SBOX(OBF_SEED3),   \
                                 OBF_ENC_ALL(s)},                             \
        (size_t)(sizeof(s) + 4u), var##__buf_);                               \
    (void)var##__gc_

#else /* MSVC / unknown: no auto-zero; use OBF_WITH for safe cleanup */

#define OBF_STRING(var, s)                                                   \
    (void)sizeof(struct {                                                     \
        _Static_assert(sizeof(s) <= (size_t)(OBF_MAX_LEN),                   \
                       "OBF_STRING: string length exceeds OBF_MAX_LEN");      \
        char obf_sa_;                                                         \
    });                                                                       \
    unsigned char var##__buf_[OBF_MAX_LEN] = {0};                            \
    const char *var = obf_decrypt(                                            \
        (const unsigned char[]){OBF_SBOX(OBF_SEED0), OBF_SBOX(OBF_SEED1),   \
                                 OBF_SBOX(OBF_SEED2), OBF_SBOX(OBF_SEED3),   \
                                 OBF_ENC_ALL(s)},                             \
        (size_t)(sizeof(s) + 4u), var##__buf_)

#endif /* __GNUC__ || __clang__ */

#endif /* !OBF_DISABLE */
#endif /* VORTEX_CIPHER_H */
