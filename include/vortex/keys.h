/*
 * vortex/keys.h
 * How we generate encryption keys at compile time.
 *
 * All of the math in this file is evaluated by the compiler while it's
 * building your code. None of it happens at runtime, and no memory is allocated.
 *
 * HOW WE MAKE KEYS
 * ----------------
 * 1. Global Seed (OBF_GSEED): This is based solely on the current date (__DATE__).
 *    We use the date so that all files compiled on the same day use the same base
 *    S-box settings. If we used the exact time, files compiled a second apart
 *    would have mismatched settings and break.
 *
 * 2. Per-line Key (OBF_KEY): This is the magic that makes every string unique.
 *    We mix the Global Seed with the current file name (__FILE__), the exact
 *    time (__TIME__), and the current line number (__LINE__). Because the line
 *    number is included, "hello" on line 10 will encrypt completely differently
 *    than "hello" on line 20.
 *
 * 3. The S-Box: The Global Seed is used to pick the parameters (A and B) for
 *    the S-box. We use a bit of math (Newton iterations) to ensure we can
 *    always reverse the S-box at runtime.
 *
 * You shouldn't need to include this file directly; just use `#include "obfuscate.h"`.
 */

#ifndef VORTEX_KEYS_H
#define VORTEX_KEYS_H

/* Safely reads a character from a string at compile time.
 * If the string is too short, it just returns 0 so the compiler doesn't crash. */
#define OBF_FC(s,i) \
    ((unsigned char)(sizeof(s) > (size_t)(i) ? (unsigned char)(s)[(i)] : 0u))

/* ── Project Salt ────────────────────────────────────────────────────────
 * Set -DOBF_PROJECT_SALT=0xNNNNNNNNu in your Makefile to produce a unique
 * S-box per project, defeating cross-project precomputed tables.
 * Defaults to 0 (backward-compatible). */
#ifndef OBF_PROJECT_SALT
#   define OBF_PROJECT_SALT  0u
#endif

/* ── The Global Build Seed ────────────────────────────────────────────────
 * We use the date the file was compiled to generate a unique seed.
 * We look at specific characters in the date string (like "Jan 01 2024").
 * We use prime numbers to multiply the characters so they combine randomly. */
#define OBF_GSEED \
    ((( (unsigned int)OBF_FC(__DATE__, 0)*127u  \
      + (unsigned int)OBF_FC(__DATE__, 1)*131u  \
      + (unsigned int)OBF_FC(__DATE__, 2)*137u  \
      + (unsigned int)OBF_FC(__DATE__, 4)*139u  \
      + (unsigned int)OBF_FC(__DATE__, 5)*149u  \
      + (unsigned int)OBF_FC(__DATE__, 7)*151u  \
      + (unsigned int)OBF_FC(__DATE__, 8)*157u  \
      + (unsigned int)OBF_FC(__DATE__, 9)*163u  \
      + (unsigned int)OBF_FC(__DATE__,10)*167u) \
     ^ ((unsigned int)(OBF_PROJECT_SALT) * 241u) \
    ) & 0xFFFFFFFFu)

/* ── The Per-Line Key ───────────────────────────────────────────────────
 * We mix the Global Seed with the specific time, file name, and line number.
 * By using prime multipliers for each character, we prevent parts of the
 * filename from "canceling each other out" when we XOR them.
 *
 * Covers all 8 digits of __TIME__ ("HH:MM:SS") and 16 bytes of __FILE__
 * so that files sharing a long common path prefix still diverge. */
#define OBF_KEY \
    (( (unsigned int)(OBF_GSEED)               \
     ^ (unsigned int)OBF_FC(__TIME__,0)*163u   \
     ^ (unsigned int)OBF_FC(__TIME__,1)*167u   \
     ^ (unsigned int)OBF_FC(__TIME__,3)*173u   \
     ^ (unsigned int)OBF_FC(__TIME__,4)*179u   \
     ^ (unsigned int)OBF_FC(__TIME__,6)*181u   \
     ^ (unsigned int)OBF_FC(__TIME__,7)*191u   \
     ^ (unsigned int)OBF_FC(__FILE__, 0)*193u  \
     ^ (unsigned int)OBF_FC(__FILE__, 1)*197u  \
     ^ (unsigned int)OBF_FC(__FILE__, 2)*199u  \
     ^ (unsigned int)OBF_FC(__FILE__, 3)*211u  \
     ^ (unsigned int)OBF_FC(__FILE__, 4)*223u  \
     ^ (unsigned int)OBF_FC(__FILE__, 5)*227u  \
     ^ (unsigned int)OBF_FC(__FILE__, 6)*229u  \
     ^ (unsigned int)OBF_FC(__FILE__, 7)*233u  \
     ^ (unsigned int)OBF_FC(__FILE__, 8)*239u  \
     ^ (unsigned int)OBF_FC(__FILE__, 9)*241u  \
     ^ (unsigned int)OBF_FC(__FILE__,10)*251u  \
     ^ (unsigned int)OBF_FC(__FILE__,11)*257u  \
     ^ (unsigned int)OBF_FC(__FILE__,12)*263u  \
     ^ (unsigned int)OBF_FC(__FILE__,13)*269u  \
     ^ (unsigned int)OBF_FC(__FILE__,14)*271u  \
     ^ (unsigned int)OBF_FC(__FILE__,15)*277u  \
     ^ ((unsigned int)(__LINE__) * 281u)        \
    ) & 0xFFFFFFFFu)

/* ── S-box parameters ───────────────────────────────────────────────── */
#define OBF_GSEED_BYTE0  ((unsigned char)( (OBF_GSEED)        & 0xFFu))
#define OBF_GSEED_BYTE1  ((unsigned char)(((OBF_GSEED) >> 8u) & 0xFFu))
#define OBF_SBOX_A       ((unsigned char)(((unsigned int)(OBF_GSEED_BYTE0) | 1u) & 0xFFu))
#define OBF_SBOX_B       ((unsigned char)( (unsigned int)(OBF_GSEED_BYTE1)       & 0xFFu))

/* ── S-box key splitting ─────────────────────────────────────────────
 * Instead of embedding OBF_SBOX_A, _B, and A_inv as plain immediates,
 * we XOR each with a mask derived from an independent GSEED slice.
 * init.c reconstructs the originals at runtime via the same XOR —
 * turning one obvious constant into two unrelated-looking ones.
 *
 * OBF_SBOX_MASK : derived from bits [23:16] of GSEED (independent of A/B).
 * OBF_SBOX_A_ENC: A ^ mask          (stored literal in init.c)
 * OBF_SBOX_B_ENC: B ^ (mask ^ 0x5A) (different scramble per component)
 * OBF_SBOX_I_ENC: A_inv ^ (mask ^ 0xA5)                                  */
#define OBF_SBOX_MASK  ((unsigned char)(((OBF_GSEED) >> 16u) & 0xFFu))
#define OBF_SBOX_A_ENC ((unsigned char)((unsigned int)(OBF_SBOX_A)            ^ (unsigned int)(OBF_SBOX_MASK)))
#define OBF_SBOX_B_ENC ((unsigned char)((unsigned int)(OBF_SBOX_B)            ^ ((unsigned int)(OBF_SBOX_MASK) ^ 0x5Au)))
#define OBF_SBOX_I_ENC ((unsigned char)((unsigned int)(OBF_MODINV256(OBF_SBOX_A)) ^ ((unsigned int)(OBF_SBOX_MASK) ^ 0xA5u)))

/* ── Reverse Math Helpers ───────────────────────────────────────────────
 * These macros do the heavy math (Newton iterations) needed to reverse the
 * S-box at runtime. They are evaluated entirely at compile time. */
#define OBF_MSTEP(a,x) \
    ((unsigned char)((unsigned char)(x) * (2u - (unsigned char)(a) * (unsigned char)(x))))

/* Does the reverse math three times to make sure it's accurate */
#define OBF_MODINV256(a) \
    OBF_MSTEP((unsigned char)(a), \
      OBF_MSTEP((unsigned char)(a), \
        OBF_MSTEP((unsigned char)(a), (unsigned char)(a))))

#endif /* VORTEX_KEYS_H */
