/*
 * src/version.c
 * Provides an obfuscated way to get the library's version string.
 *
 * Instead of storing "VORTEX/1.0.0" as plain text where anyone can see it,
 * we encrypt it at compile time. The encryption key is tied to the exact line
 * number in this file, so it's stable as long as you don't move the code around.
 *
 * If you compile with OBF_DISABLE, we just use a normal string.
 */

#include "internal.h"

OBFAPI OBFAPI_NOINLINE OBFAPI_OPTNONE
const char *obf_version(void)
{
    OBF_OPAQUE_PRED();
    static unsigned char ver_buf[OBF_MAX_LEN];
    static _Atomic int ver_initialized_ = 0;

    if (!atomic_load_explicit(&ver_initialized_, memory_order_acquire)) {
#ifndef OBF_DISABLE
        /* OBF_WITH is a single macro call — all sub-macros see the same __LINE__,
         * so seeds and encrypted data share a consistent OBF_KEY. */
        OBF_WITH(ver, "VORTEX/1.0.0") {
            size_t i;
            for (i = 0u; ver[i] && i < (size_t)(OBF_MAX_LEN - 1u); i++) {
                ver_buf[i] = (unsigned char)ver[i];
            }
            ver_buf[i] = 0u;
        }
#else
        /* OBF_DISABLE is on, just do a normal string copy. */
        static const char src[] = "VORTEX/1.0.0";
        size_t i;
        for (i = 0u; src[i] && i < (size_t)(OBF_MAX_LEN - 1u); i++) {
            ver_buf[i] = (unsigned char)src[i];
        }
        ver_buf[i] = 0u;
#endif
        atomic_store_explicit(&ver_initialized_, 1, memory_order_release);
    }

    return (const char *)ver_buf;
}
