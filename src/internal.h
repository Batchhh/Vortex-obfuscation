/*
 * src/internal.h
 * Shared state and internal utilities.
 *
 * This is an internal header, not meant for users to include directly.
 * It's only used by the C files inside the src/ folder.
 */

#ifndef VORTEX_INTERNAL_H
#define VORTEX_INTERNAL_H

#include "../include/obfuscate.h"   /* relative path — works with or without -Iinclude */
#include <stdint.h>                 /* uintptr_t for OBF_OPAQUE_PRED */

/* 
 * The single global instance of our runtime context.
 * It's created once in `src/init.c` and shared across all files.
 */
extern ObfContext g_obf_ctx;

/* 
 * A trick to confuse static analysis tools.
 * We add a chunk of code that will never actually run, but it looks
 * real enough to make decompilers and analysis tools waste time on it.
 *
 * If OBF_DISABLE is on, we skip this so we don't get compiler warnings.
 */
#ifndef OBF_DISABLE
/* OBF_OPAQUE_PRED — injects a dead branch that decompilers must analyse.
 *
 * The predicate uses the low bit of a stack address: always 0 on any
 * ABI that aligns the stack to ≥ 2 bytes, but the compiler cannot prove
 * this when the address is stored through a volatile pointer and then
 * loaded back, so it emits a real comparison instruction.
 *
 * The dead body mixes a fake function-pointer dispatch with a byte-scan
 * loop, giving decompilers (IDA, Ghidra) a plausible-but-unreachable
 * control-flow path that pollutes their call-graph and register analysis. */
#   define OBF_OPAQUE_PRED()                                                   \
        do {                                                                   \
            volatile unsigned char _obf_stk_ = 0u;                            \
            volatile unsigned char *_obf_sp_ = &_obf_stk_;                    \
            /* low bit of a stack address is always 0 on aligned ABIs */       \
            volatile int _obf_dead_ = (int)((uintptr_t)_obf_sp_ & 1u);        \
            if (_obf_dead_) {                                                  \
                /* fake indirect call — decompiler must track the pointer */   \
                static void (* volatile _obf_fake_fp_)(void) = (void(*)(void))0;\
                if (_obf_fake_fp_) { _obf_fake_fp_(); }                        \
                /* fake byte scan — pollutes register liveness analysis */     \
                volatile unsigned char _obf_buf_[4] = {0x56u,0x4Fu,0x52u,0u}; \
                volatile const unsigned char *_obf_p_ = _obf_buf_;             \
                while (*_obf_p_) { _obf_p_++; }                               \
            }                                                                  \
        } while (0)
#else
#   define OBF_OPAQUE_PRED() do {} while (0)
#endif

#endif /* VORTEX_INTERNAL_H */
