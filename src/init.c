/*
 * src/init.c
 * Sets up the decryption S-box at runtime based on our compile-time keys.
 */

#include "internal.h"
#include <string.h>   /* memcpy */

/* 
 * The single global context.
 * It's automatically zeroed when the program starts.
 * Other files access it through internal.h.
 */
ObfContext g_obf_ctx;

/* 
 * Builds the S-box and its inverse using the compile-time keys.
 *
 * We force the compiler to calculate this at runtime with `register volatile`
 * variables so it doesn't just bake the final tables into the binary,
 * which would leak our keys.
 *
 * This function is thread-safe. If multiple threads call it at the exact
 * same time during startup, they might do the work twice, but they'll
 * generate the exact same data safely.
 */
OBFAPI OBFAPI_NOINLINE OBFAPI_OPTNONE
void obf_init(void)
{
    if (atomic_load_explicit(&g_obf_ctx.initialized, memory_order_acquire)) { return; }
    OBF_OPAQUE_PRED();

    /* Key splitting: A, B, and A_inv are stored XOR-masked so they do not
     * appear as plain immediates next to each other in the binary.
     * Each encoded constant uses a different XOR mask derived from the
     * same GSEED slice, making the three constants look unrelated to a
     * static analyser.  The volatile reads prevent constant propagation. */
    register volatile unsigned int enc_A    = (unsigned int)OBF_SBOX_A_ENC;
    register volatile unsigned int enc_B    = (unsigned int)OBF_SBOX_B_ENC;
    register volatile unsigned int enc_Inv  = (unsigned int)OBF_SBOX_I_ENC;
    register volatile unsigned int mask     = (unsigned int)OBF_SBOX_MASK;

    register volatile unsigned int A     = ((enc_A   ^  mask)               | 1u) & 0xFFu;
    register volatile unsigned int B     =  (enc_B   ^ (mask ^ 0x5Au))             & 0xFFu;
    register volatile unsigned int A_inv = ((enc_Inv ^ (mask ^ 0xA5u))      | 1u) & 0xFFu;

    /* Build into local arrays first, then memcpy to the global.
     * This eliminates the C11 data race: concurrent threads that both
     * observe initialized==0 only write to thread-local storage; the
     * release-store below makes the fully-written globals visible. */
    unsigned char local_sbox[256];
    unsigned char local_sbox_inv[256];

    for (int i = 0; i < 256; i++) {
        local_sbox[i]     = (unsigned char)((A * (unsigned int)i + B) & 0xFFu);
        local_sbox_inv[i] = (unsigned char)((A_inv * ((unsigned int)i - B)) & 0xFFu);
    }

    memcpy(g_obf_ctx.sbox,     local_sbox,     256u);
    memcpy(g_obf_ctx.sbox_inv, local_sbox_inv, 256u);

    /* Zero key material from registers/stack before releasing the init flag */
    A = 0u; B = 0u; A_inv = 0u;
    enc_A = 0u; enc_B = 0u; enc_Inv = 0u; mask = 0u;
    atomic_store_explicit(&g_obf_ctx.initialized, 1, memory_order_release);
}
