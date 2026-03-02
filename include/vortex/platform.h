/*
 * vortex/platform.h — compiler and platform detection
 *
 * Defines three portability macros used on every exported symbol:
 *
 *   OBFAPI          — visibility / export attribute
 *   OBFAPI_NOINLINE — prevents inlining of decrypt functions (anti-analysis)
 *   OBFAPI_OPTNONE  — suppresses optimisation on decrypt functions so the
 *                     compiler cannot fold compile-time constants back in
 *
 * Included by: include/obfuscate.h (via the umbrella)
 * Do not include this file directly; use #include "obfuscate.h" instead.
 */

#ifndef VORTEX_PLATFORM_H
#define VORTEX_PLATFORM_H

#if defined(_WIN32) || defined(_WIN64)
/* ── Windows (MSVC / MinGW) ────────────────────────────────────────── */
#   define OBFAPI          __declspec(dllexport)
#   define OBFAPI_NOINLINE __declspec(noinline)
#   if defined(__clang__)
#       define OBFAPI_OPTNONE __attribute__((optnone))
#   else
#       define OBFAPI_OPTNONE   /* MSVC: compile translation unit with /Od */
#   endif

#elif defined(__clang__)
/* ── Clang (macOS / Linux / iOS) ───────────────────────────────────── */
#   define OBFAPI          __attribute__((visibility("default")))
#   define OBFAPI_NOINLINE __attribute__((noinline))
#   define OBFAPI_OPTNONE  __attribute__((optnone))

#elif defined(__GNUC__)
/* ── GCC (Linux / ARM / MinGW) ─────────────────────────────────────── */
#   define OBFAPI          __attribute__((visibility("default")))
#   define OBFAPI_NOINLINE __attribute__((noinline))
#   define OBFAPI_OPTNONE  __attribute__((optimize("O0")))

#else
/* ── Unknown / portable fallback ───────────────────────────────────── */
#   define OBFAPI
#   define OBFAPI_NOINLINE
#   define OBFAPI_OPTNONE
#endif

#endif /* VORTEX_PLATFORM_H */
