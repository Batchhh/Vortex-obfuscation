/*
 * example_usage.c
 * A demonstration of how to use the VORTEX Obfuscation Framework.
 *
 * To build and run normally:
 *   make
 *   ./example
 *
 * To build and run in debug mode (no encryption):
 *   make debug
 *   ./example_debug
 *
 * To prove that it works, try searching the compiled binary for secrets:
 *   strings example | grep -Ei "hello|vortex|secret|bearer|password"
 *   (It won't find anything!)
 */

#include "obfuscate.h"

#include <stdio.h>    /* printf, puts */

/* ════════════════════════════════════════════════════════════════════════
 * Example 1a: OBF_STRING (The easiest way to hide strings)
 *
 * This works perfectly on GCC and Clang. It decrypts the string when you
 * declare it, and then magically wipes it from memory as soon as the
 * function finishes (or the variable goes out of scope).
 * ════════════════════════════════════════════════════════════════════════ */
static void demo_string_single(void)
{
    OBF_STRING(greeting, "Hello from VORTEX!");
    printf("[OBF_STRING] greeting: %s\n", greeting);

    OBF_STRING(password, "p4$$w0rd-do-not-leak");
    printf("[OBF_STRING] password: %s\n", password);

    OBF_STRING(token, "Bearer sk-9f3a-demo");
    printf("[OBF_STRING] token   : %s\n", token);
    /* greeting, password, token all auto-zeroed here */
}

/* ════════════════════════════════════════════════════════════════════════
 * Example 1b: OBF_WITH (The safest way to hide strings)
 *
 * If you're on Windows using MSVC, or just want absolute certainty that
 * your string gets wiped from memory IMMEDIATELY after you use it, use this.
 * The string only exists as plain text inside the curly braces.
 * ════════════════════════════════════════════════════════════════════════ */
static void demo_string_scoped(void)
{
    /* Nested: inner zeroed when its block exits; outer stays live. */
    OBF_WITH(outer, "outer-secret") {
        OBF_WITH(inner, "inner-secret") {
            printf("[OBF_WITH] outer    : %s\n", outer);
            printf("[OBF_WITH] inner    : %s\n", inner);
        }
        printf("[OBF_WITH] outer ok : %s\n", outer);
    }
}

/* ════════════════════════════════════════════════════════════════════════
 * Example 2: Hiding Numbers (Ints, Floats, Doubles, Hex)
 *
 * It's just as easy to hide numeric constants in your compiled app.
 * Note: OBF_FLOAT and OBF_DOUBLE only work if you compile with optimizations
 * enabled (-O1 or higher), because they rely on the compiler folding the math.
 * ════════════════════════════════════════════════════════════════════════ */
static void demo_numbers(void)
{
    /* Integers and hex offsets */
    int answer   = OBF_INT(42);
    int port     = OBF_INT(8443);
    int checksum = OBF_INT(0x1BADC0DE);
    size_t offset = OBF_OFFSET(0xfa);      /* hide a memory offset */
    printf("[OBF_INT] answer    : %d\n",      answer);
    printf("[OBF_INT] port      : %d\n",      port);
    printf("[OBF_INT] checksum  : 0x%X\n",    (unsigned int)checksum);
    printf("[OBF_OFFSET] offset : 0x%zX\n",   offset);

    /* Floats */
    float  pi      = OBF_FLOAT(3.14159265f);
    float  scale   = OBF_FLOAT(0.001f);
    printf("[OBF_FLOAT] pi      : %f\n",      (double)pi);
    printf("[OBF_FLOAT] scale   : %f\n",      (double)scale);

    /* Doubles */
    double gravity = OBF_DOUBLE(9.80665);
    double euler   = OBF_DOUBLE(2.718281828459045);
    printf("[OBF_DOUBLE] gravity: %f\n",      gravity);
    printf("[OBF_DOUBLE] euler  : %.15f\n",   euler);
}

/* ════════════════════════════════════════════════════════════════════════
 * Example 3: Getting the library version securely.
 *
 * This version string is encrypted inside the library itself.
 * ════════════════════════════════════════════════════════════════════════ */
static void demo_version(void)
{
    printf("[obf_version]       : %s\n", obf_version());
}

/* ════════════════════════════════════════════════════════════════════════
 * Example 4: Secure Memory Erasing (obf_zero)
 *
 * If you ever have a sensitive array that you want to securely wipe from
 * memory, use this. Normal `memset` calls are sometimes "optimized away"
 * by the compiler if it thinks the memory won't be used again. This function
 * guarantees the memory is wiped clean.
 * ════════════════════════════════════════════════════════════════════════ */
static void demo_zero(void)
{
    unsigned char sensitive[16];
    for (size_t i = 0u; i < sizeof(sensitive); i++) {
        sensitive[i] = (unsigned char)(i + 0xA0u);
    }
    printf("[obf_zero] before   :");
    for (int i = 0; i < 16; i++) { printf(" %02X", (unsigned int)sensitive[i]); }
    puts("");

    obf_zero(sensitive, sizeof(sensitive));

    printf("[obf_zero] after    :");
    for (int i = 0; i < 16; i++) { printf(" %02X", (unsigned int)sensitive[i]); }
    puts("");
}

/* ════════════════════════════════════════════════════════════════════════
 * main
 * ════════════════════════════════════════════════════════════════════════ */
int main(void)
{
    obf_init();

    puts("== VORTEX Obfuscation Framework - demonstration ==\n");

    demo_string_single(); puts("");
    demo_string_scoped(); puts("");
    demo_numbers();   puts("");
    demo_version();   puts("");
    demo_zero();

    puts("\n== done ==");
    return 0;
}
