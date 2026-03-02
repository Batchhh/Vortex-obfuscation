/*
 * vortex/api.h
 * The public C API for VORTEX.
 *
 * This file declares the `ObfContext` type and all the functions you can call.
 * It's safe to include this from C++ (it wraps everything in `extern "C"`),
 * and it's also used by the FFI bindings in `obf_ffi.h` for Rust, Python, etc.
 *
 * You shouldn't need to include this file directly; just use `#include "obfuscate.h"`.
 */

#ifndef VORTEX_API_H
#define VORTEX_API_H

#include "platform.h"   
#include "config.h"    
#include <stddef.h>    
#include <stdatomic.h> 


/* ── Internal context ────────────────────────────────────────────────
 * Holds the runtime S-box and its inverse.  One instance per link target,
 * zero-initialised at program start.  Populated by obf_init().          */
typedef struct {
    unsigned char sbox[256];      /* S[p]     = (A·p + B) mod 256             */
    unsigned char sbox_inv[256];  /* S_inv[c] = (A_inv·(c-B)) mod 256         */
    _Atomic int   initialized;    /* nonzero after obf_init() completes;
                                   * _Atomic ensures acquire/release ordering
                                   * when multiple threads call obf_decrypt()  */
} ObfContext;

/* ── Public API ──────────────────────────────────────────────────────── */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * obf_init — generate sbox[] and sbox_inv[] from compile-time key material.
 *   Must be called once before any obf_decrypt().
 *   Subsequent calls are no-ops (double-checked via the atomic flag).
 *   Thread-safe: the _Atomic initialized flag uses acquire/release ordering
 *   so a thread that observes initialized=1 also sees the fully written
 *   sbox[] and sbox_inv[] arrays.  Concurrent first-calls produce identical
 *   deterministic results (same A, B) with at most redundant work.
 */
OBFAPI void        obf_init(void);

/*
 * obf_decrypt — decrypt a compile-time-obfuscated blob.
 *   blob    : [S[SEED0]][S[SEED1]][S[SEED2]][S[SEED3]][enc_byte_0 .. enc_byte_{len-5}]
 *             Produced by OBF_STR / OBF_ENC_ALL macros.
 *             blob[0..3] are S-box-blinded seeds; obf_decrypt undoes the
 *             blinding via sbox_inv before running the keystream.
 *   len     : sizeof(original_string) + 4
 *   out_buf : caller-supplied buffer of at least OBF_MAX_LEN bytes.
 *             Filled with the null-terminated decrypted string.
 *   Returns : out_buf cast to const char*.
 *             Call OBF_CLEAR() or obf_zero() when done.
 */
OBFAPI const char* obf_decrypt(const unsigned char *blob, size_t len,
                                unsigned char *out_buf);

/*
 * obf_zero — securely zero a buffer using volatile writes.
 *   The volatile pointer prevents the compiler from eliding the stores
 *   as "dead writes" when the buffer is not read afterwards.
 *   Call after every obf_decrypt() once the plaintext is no longer needed.
 */
OBFAPI void        obf_zero(unsigned char *buf, size_t len);

/*
 * obf_buf_cleanup_ — auto-zero callback for OBF_STRING (GCC/Clang).
 *   Called by __attribute__((cleanup)) when the var declared by
 *   OBF_STRING goes out of scope.  Defined here so obf_zero is visible.
 *   static inline prevents duplicate-symbol errors across translation units.
 */
#if defined(__GNUC__) || defined(__clang__)
static inline void obf_buf_cleanup_(unsigned char **pp)
{
    obf_zero(*pp, (size_t)OBF_MAX_LEN);
}
#endif

/*
 * obf_version — return the library version string "VORTEX/1.0.0".
 *   The string is encrypted at compile time; no ASCII bytes for it appear
 *   in the .rodata section of the library binary.
 *   Returned pointer addresses a static internal buffer — do not free it.
 *   Not thread-safe on the very first call (no pthreads dependency).
 */
OBFAPI const char* obf_version(void);

/*
 * obf_decode_int — decode an OBF_INT()-obfuscated integer.
 *   Applies ROTL32(enc, rot) XOR key, where rot is derived from key
 *   internally.  noinline + optnone prevent compile-time folding.
 */
OBFAPI int         obf_decode_int(unsigned int enc, unsigned int key);

/*
 * obf_decode_float — decode an OBF_FLOAT()-obfuscated float.
 *   Reverses ROTR32(bits XOR key, rot); reinterprets the decoded bit
 *   pattern as IEEE 754 float via memcpy (UB-free type punning).
 */
OBFAPI float       obf_decode_float(unsigned int enc, unsigned int key);

/*
 * obf_decode_double — decode an OBF_DOUBLE()-obfuscated double.
 *   Same scheme as obf_decode_float but operates on 64-bit values;
 *   uses a 64-bit key derived from OBF_DOUBLE_KEY.
 */
OBFAPI double      obf_decode_double(unsigned long long enc,
                                     unsigned long long key);

/*
 * obf_decode_offset — decode an OBF_OFFSET()-obfuscated memory offset.
 *   Same scheme as obf_decode_double but returns size_t directly.
 */
OBFAPI size_t      obf_decode_offset(unsigned long long enc,
                                     unsigned long long key);

#ifdef __cplusplus
}
#endif

#endif /* VORTEX_API_H */
