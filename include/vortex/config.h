/*
 * vortex/config.h — user-tunable configuration and OBF_DISABLE passthrough
 *
 * Defines:
 *   OBF_MAX_LEN       — maximum string length (including null terminator).
 *                       OBF_ENC_ALL always emits exactly this many encrypted
 *                       bytes.  Increase freely; each extra byte costs one
 *                       O(1) expression at compile time.  Default: 256.
 *
 *   OBF_DISABLE       — if defined before including obfuscate.h, all cipher
 *                       machinery is skipped and macros become transparent
 *                       pass-throughs.  Useful for debug / sanitiser builds.
 *
 * User-facing macros (both modes):
 *   OBF_WITH(var, s)  — the string macro: decrypts s on entry, exposes it
 *                       as const char* var inside the braces, and zeroes the
 *                       plaintext automatically on every exit path.
 *   OBF_INT(n)        — integer macro: obfuscates the constant n.
 *
 * Included by: include/obfuscate.h (via the umbrella)
 * Do not include this file directly; use #include "obfuscate.h" instead.
 */

#ifndef VORTEX_CONFIG_H
#define VORTEX_CONFIG_H

/* ── Maximum string length ─────────────────────────────────────────── */
#ifndef OBF_MAX_LEN
#   define OBF_MAX_LEN 256
#endif

/* ── OBF_DISABLE passthrough ────────────────────────────────────────── */
#ifdef OBF_DISABLE

/*
 * OBF_INT — return n as-is; no obfuscation in transparent mode.
 * OBF_INT_KEY is 0 so obf_decode_int(n ^ 0, 0) == n.
 */
#   define OBF_INT(n)     ((int)(n))
#   define OBF_INT_KEY    (0u)

/*
 * OBF_WITH — single-iteration for-loop binding var to the string literal s.
 * No zeroing is needed: s is a string literal in read-only storage.
 * Setting var = (void*)0 on the update step terminates the loop cleanly.
 */
#   define OBF_WITH(var, s) \
        for (const char *var = (s); var; var = (void *)0)

/* OBF_FLOAT / OBF_DOUBLE — transparent pass-throughs; no obfuscation. */
#   define OBF_FLOAT(f)   ((float)(f))
#   define OBF_DOUBLE(d)  ((double)(d))

/* OBF_OFFSET — transparent pass-through; no obfuscation. */
#   define OBF_OFFSET(n)  ((size_t)(n))

/* OBF_STRING — plain const char* declaration; no crypto, no auto-zero. */
#   define OBF_STRING(var, s)  const char *var = (s)

#endif /* OBF_DISABLE */

#endif /* VORTEX_CONFIG_H */
