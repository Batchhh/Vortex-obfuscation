# VORTEX API Reference

---

## Setup

Include the umbrella header — do not include sub-headers directly:

```c
#include "obfuscate.h"
```

Add `-Iinclude` to your compiler flags so the header can be found. Call `obf_init()` once at program startup, before any decryption takes place:

```c
int main(void) {
    obf_init();
    /* ... rest of program ... */
}
```

---

## Quick Reference


| Macro / Function              | What it does                                                | Returns                          |
| ----------------------------- | ----------------------------------------------------------- | -------------------------------- |
| `OBF_STRING(var, s)`          | Decrypt string literal; auto-zero on scope exit (GCC/Clang) | `const char *var` (local)        |
| `OBF_WITH(var, s) { }`        | Decrypt string; zero on every exit path incl. MSVC          | `const char *var` (block-scoped) |
| `OBF_INT(n)`                  | Obfuscate integer constant                                  | `int`                            |
| `OBF_FLOAT(f)`                | Obfuscate float constant (requires -O1+)                    | `float`                          |
| `OBF_DOUBLE(d)`               | Obfuscate double constant (requires -O1+)                   | `double`                         |
| `OBF_OFFSET(n)`               | Obfuscate memory offset                                     | `size_t`                         |
| `OBF_MAX_LEN`                 | Max string length (default 256)                             | compile-time constant            |
| `OBF_DISABLE`                 | Disable all encryption (debug/sanitiser mode)               | —                                |
| `obf_init()`                  | Build runtime S-box; call once at startup                   | `void`                           |
| `obf_decrypt(blob, len, buf)` | Decrypt a compile-time blob                                 | `const char *`                   |
| `obf_zero(buf, len)`          | Securely zero a buffer                                      | `void`                           |
| `obf_version()`               | Return `"VORTEX/1.0.0"` (encrypted in binary)               | `const char *`                   |
| `obf_decode_int(enc, key)`    | Decode OBF_INT value (called by macro)                      | `int`                            |
| `obf_decode_float(enc, key)`  | Decode OBF_FLOAT value (called by macro)                    | `float`                          |
| `obf_decode_double(enc, key)` | Decode OBF_DOUBLE value (called by macro)                   | `double`                         |
| `obf_decode_offset(enc, key)` | Decode OBF_OFFSET value (called by macro)                   | `size_t`                         |


---

## OBF_STRING vs OBF_WITH


|               | `OBF_STRING(var, s)`                                            | `OBF_WITH(var, s) { }`                                                   |
| ------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------ |
| **Syntax**    | Single statement; `var` lives until end of enclosing block      | Scoped block; `var` lives only inside `{ }`                              |
| **Auto-zero** | Yes on GCC/Clang (`__attribute__((cleanup))`). **Not** on MSVC. | Yes on all compilers, all exit paths                                     |
| **Nesting**   | Natural — declare multiple vars in one block                    | Explicit nesting required                                                |
| **MSVC**      | Decrypts but does **not** auto-zero                             | Full auto-zero                                                           |
| **Use when**  | GCC/Clang build, single-line convenience                        | MSVC targets, or when you need guaranteed cleanup regardless of compiler |


---

## Macros

### OBF_STRING(var, s)

Declares `const char *var` pointing to a decrypted plaintext buffer on the stack. On GCC/Clang the buffer carries `__attribute__((cleanup(obf_buf_cleanup_)))`, which fires `obf_zero()` automatically when `var` goes out of scope — on every exit path including early return and `goto`. On MSVC and unknown compilers the macro still
decrypts, but the buffer is **not** auto-zeroed; use `OBF_WITH` for guaranteed cleanup on those toolchains.

Constraints:

- `s` must be a string literal.
- The stack buffer is `OBF_MAX_LEN` bytes. `sizeof(s) <= OBF_MAX_LEN` is
enforced as a `_Static_assert` at compile time.
- Do **not** return `var` from the function — it points into a stack buffer
that is zeroed on scope exit (dangling pointer).

```c
/* Correct: var used within the same function scope */
void send_request(void) {
    OBF_STRING(host,  "api.internal.example.com");
    OBF_STRING(token, "Bearer sk-9f3a-demo");
    http_post(host, token);
    /* host and token buffers are zeroed automatically here */
}
```

```c
/* Incorrect: returning var is a dangling pointer */
const char *bad(void) {
    OBF_STRING(pw, "secret");
    return pw;   /* pw's buffer is zeroed before the caller reads it */
}
```

### OBF_WITH(var, s)

Decrypts `s` on entry to the block and zeroes the plaintext buffer on every exit path — including `break`, `goto`, and early `return` from the enclosing function. `var` is a `const char *` valid only inside the `{ }` body.

The implementation uses three nested `for`-loops to achieve RAII behaviour without heap allocation, VLAs, or GCC statement-expressions:

- Loop 1 sets up a one-shot control flag.
- Loop 2 allocates the stack buffer; its update expression calls `obf_zero()` and clears the flag — but only runs after Loop 3 has exited.
- Loop 3 performs the decryption and binds `var`; its update clears the flag on every exit path (normal completion, `break`, `goto`, early `return`), which causes Loop 2 to evaluate its update (the zero + flag clear) before Loop 1 and Loop 2 themselves exit. Together the three loops guarantee the buffer is zeroed on every path.

`OBF_WITH` is portable across all compilers including MSVC.

```c
/* Nested usage — inner is zeroed first, outer second */
void login_msvc(void) {
    OBF_WITH(host, "auth.internal.example.com") {
        OBF_WITH(secret, "xK9#mP2$qR7!wL4@") {
            tls_connect(host, OBF_INT(8443), secret);
        }   /* secret zeroed here */
    }       /* host zeroed here */
}
```

### OBF_INT(n)

Obfuscates an integer constant. The binary stores `ROTR32(n XOR OBF_INT_KEY, OBF_INT_ROT)` rather than the plaintext value. The value is recovered at runtime via `obf_decode_int()`, which is marked `noinline` and `optnone` to prevent the compiler from folding the round-trip back to the original constant.

`OBF_INT(n)` is valid anywhere an `int` expression is valid.

```c
int port     = OBF_INT(8443);
int checksum = OBF_INT(0x1BADC0DE);

/* Inline in a function call */
connect(host, OBF_INT(443));
```

### OBF_FLOAT(f)

Obfuscates a `float` constant. The macro extracts the IEEE 754 bit pattern via a union compound literal (C11 §6.5.2.3), applies `ROTR32(bits XOR OBF_INT_KEY, OBF_INT_ROT)`, and embeds only the encoded integer in the binary. The plaintext float value never appears. Decoding happens at runtime via `obf_decode_float()`.

Requires `-O1` or higher to be effective — the compiler must constant-fold the bit-manipulation expression so only the encoded value is emitted. The Makefile default is `-O2`.

In `OBF_DISABLE` mode `OBF_FLOAT(f)` expands to `(float)(f)` with no overhead.

```c
float pi    = OBF_FLOAT(3.14159265f);
float scale = OBF_FLOAT(0.001f);
```

### OBF_DOUBLE(d)

Same scheme as `OBF_FLOAT` but for 64-bit `double` constants. A 64-bit key (`OBF_DOUBLE_KEY`) is constructed by combining two 32-bit halves: the low half is `OBF_INT_KEY` and the high half is `OBF_INT_KEY XOR OBF_GSEED`,  
providing an independent contribution from the global build seed. `OBF_DOUBLE_ROT` is an odd value in `[1, 63]` so both shifts in `ROTR64` stay within the defined range.

Requires `-O1` or higher. In `OBF_DISABLE` mode expands to `(double)(d)`.

```c
double gravity = OBF_DOUBLE(9.80665);
double euler   = OBF_DOUBLE(2.718281828459045);
```

### OBF_OFFSET(n)

Obfuscates a `size_t` memory offset. Uses 64-bit arithmetic (`OBF_DOUBLE_KEY` and `OBF_DOUBLE_ROT`) so the result is safe on both 32-bit and 64-bit architectures without undefined behaviour from integer overflow.

In `OBF_DISABLE` mode expands to `(size_t)(n)`.

```c
/* Hide a field offset used in pointer arithmetic */
size_t off    = OBF_OFFSET(0xfa);
char  *field  = (char *)base + off;
```

### OBF_MAX_LEN

Compile-time constant controlling the maximum supported string length (including the null terminator). Default: `256`, which supports strings up to 255 characters long.

Override it **before** including the header:

```c
#define OBF_MAX_LEN 128
#include "obfuscate.h"
```

`OBF_ENC_ALL` always emits exactly `OBF_MAX_LEN` encrypted bytes. Each extra byte adds one O(1) expression at compile time; the cost is negligible in practice.

A `_Static_assert` in both `OBF_STRING` and `OBF_WITH` catches strings that exceed the configured limit at compile time.

### OBF_DISABLE

Define before including the header to disable all encryption machinery:

```c
#define OBF_DISABLE
#include "obfuscate.h"
```

Or pass it on the command line:

```sh
gcc -std=c11 -Iinclude -DOBF_DISABLE myapp.c -o myapp
```

The convenience target in the Makefile:

```sh
make debug   # builds with OBF_DISABLE; output binary is example_debug
```

All macros become transparent pass-throughs:


| Macro                | OBF_DISABLE expansion                          |
| -------------------- | ---------------------------------------------- |
| `OBF_STRING(var, s)` | `const char *var = (s)`                        |
| `OBF_WITH(var, s)`   | single-iteration for-loop binding `var` to `s` |
| `OBF_INT(n)`         | `(int)(n)`                                     |
| `OBF_FLOAT(f)`       | `(float)(f)`                                   |
| `OBF_DOUBLE(d)`      | `(double)(d)`                                  |
| `OBF_OFFSET(n)`      | `(size_t)(n)`                                  |


Use `OBF_DISABLE` when running sanitisers (`AddressSanitizer`,
`UndefinedBehaviorSanitizer`) or stepping through code in a debugger, so
strings appear as-is and tool reports remain readable.

---

## Functions

### `void obf_init(void)`

Generates the runtime S-box (`sbox[]`) and its inverse (`sbox_inv[]`) from compile-time key material (`OBF_SBOX_A`, `OBF_SBOX_B`). Must be called once before any `obf_decrypt()` call.

Subsequent calls are no-ops — the function checks an `_Atomic int` flag with acquire/release ordering before doing any work. The design is thread-safe: a thread that observes `initialized = 1` is guaranteed to see the fully written S-box arrays. Concurrent first-calls produce identical, deterministic results with at most redundant work (no data race, no lock required).

```c
int main(void) {
    obf_init();
    /* safe to call obf_decrypt() from any thread from this point */
}
```

### `const char *obf_decrypt(const unsigned char *blob, size_t len, unsigned char *out_buf)`

Decrypts a compile-time-obfuscated blob produced by `OBF_ENC_ALL`.

**Blob format:**

```
[ S[SEED0] ][ S[SEED1] ][ enc_byte_0 ][ enc_byte_1 ] ... [ enc_byte_{n-1} ]
```

`blob[0]` and `blob[1]` are S-box-blinded seeds; `obf_decrypt` recovers the original seeds via `sbox_inv` before running the keystream. The remaining `len - 2` bytes are the encrypted string bytes.

Parameters:

- `blob` — pointer to the encrypted blob (typically a compound literal in
read-only storage produced by the `OBF_STRING` or `OBF_WITH` macros).
- `len` — `sizeof(original_string) + 2` (accounts for the two seed bytes).
- `out_buf` — caller-supplied buffer of at least `OBF_MAX_LEN` bytes.
Filled with the null-terminated decrypted string.

Returns `out_buf` cast to `const char *`. The buffer must be zeroed by the caller when the plaintext is no longer needed (done automatically by `OBF_STRING` on GCC/Clang and by `OBF_WITH` on all compilers).

The static blob pattern for use at global scope:

```c
static const unsigned char LICENSE_KEY[] = {
    OBF_SBOX(OBF_SEED0), OBF_SBOX(OBF_SEED1), OBF_ENC_ALL("LICENSE-XXXX-YYYY-ZZZZ")
};
```

### `void obf_zero(unsigned char *buf, size_t len)`

Securely erases `len` bytes starting at `buf`. Uses the best available platform primitive: `memset_s` on Apple/C11 Annex K targets, `explicit_bzero` on BSDs, and volatile pointer writes as a fallback. All three variants prevent  
the compiler from eliding the stores as dead writes — a common optimisation that defeats ordinary `memset` calls on sensitive data.

```c
unsigned char sensitive[32];
/* ... fill and use sensitive ... */
obf_zero(sensitive, sizeof(sensitive));
```

### `const char *obf_version(void)`

Returns the library version string `"VORTEX/1.0.0"`. The string is encrypted at compile time so no ASCII bytes for it appear in the `.rodata` section of the library binary.

The returned pointer addresses a static internal buffer — do **not** free it. The function is not thread-safe on the very first call (it decrypts into a static buffer on first invocation). If multiple threads may call `obf_version()` simultaneously, serialise that access externally.

```c
printf("library: %s\n", obf_version());
```

### `int obf_decode_int(unsigned int enc, unsigned int key)`

Decodes an `OBF_INT()`-obfuscated value. Applies `ROTL32(enc, rot) XOR key`, where `rot` is derived from `key` internally (`((key >> 24) | 1) & 0x1F`).

Marked `noinline` and `optnone` (via `OBFAPI_OPTNONE`) so the compiler cannot fold the decode-encode pair back to the original constant at the call site.

This function is called automatically by the `OBF_INT` macro. Direct use is rarely needed.

```c
/* Called automatically — shown for reference */
int val = obf_decode_int(enc_value, key_value);
```

### `float obf_decode_float(unsigned int enc, unsigned int key)`

Decodes an `OBF_FLOAT()`-obfuscated value. Reverses `ROTR32(bits XOR key, rot)` to recover the original IEEE 754 bit pattern, then reinterprets it as a `float` via `memcpy` (UB-free type punning).

Called automatically by the `OBF_FLOAT` macro.

```c
float val = obf_decode_float(enc_value, key_value);
```

### `double obf_decode_double(unsigned long long enc, unsigned long long key)`

Decodes an `OBF_DOUBLE()`-obfuscated value. Same scheme as `obf_decode_float` but operates on 64-bit values with a 64-bit key (`OBF_DOUBLE_KEY`).

Called automatically by the `OBF_DOUBLE` macro.

```c
double val = obf_decode_double(enc_value, key_value);
```

### `size_t obf_decode_offset(unsigned long long enc, unsigned long long key)`

Decodes an `OBF_OFFSET()`-obfuscated memory offset. Same scheme as
`obf_decode_double` but returns `size_t` directly.

Called automatically by the `OBF_OFFSET` macro.

```c
size_t off = obf_decode_offset(enc_value, key_value);
```

---

## Common Patterns

### Pattern 1 — OBF_STRING (GCC/Clang preferred)

Multiple strings declared in a single block; auto-zeroed on scope exit with
no extra syntax.

```c
void login(void) {
    OBF_STRING(host,   "auth.internal.example.com");
    OBF_STRING(secret, "xK9#mP2$qR7!wL4@");
    int port = OBF_INT(8443);
    tls_connect(host, port, secret);
    /* host and secret auto-zeroed here */
}
```

### Pattern 2 — OBF_WITH (all compilers, MSVC-safe)

Explicit scoping guarantees cleanup regardless of toolchain.

```c
void login_msvc(void) {
    OBF_WITH(host, "auth.internal.example.com") {
        OBF_WITH(secret, "xK9#mP2$qR7!wL4@") {
            tls_connect(host, OBF_INT(8443), secret);
        }   /* secret zeroed */
    }       /* host zeroed */
}
```

### Pattern 3 — Static blob (global scope)

When a string must live at file scope, store the encrypted blob as a static array and call `obf_decrypt()` manually. Remember to call `obf_zero()` when the plaintext is no longer needed.

```c
static const unsigned char LICENSE_KEY[] = {
    OBF_SBOX(OBF_SEED0), OBF_SBOX(OBF_SEED1), OBF_ENC_ALL("LICENSE-XXXX-YYYY-ZZZZ")
};

bool check_license(void) {
    unsigned char buf[OBF_MAX_LEN] = {0};
    const char *key = obf_decrypt(LICENSE_KEY,
                                   sizeof("LICENSE-XXXX-YYYY-ZZZZ") + 2, buf);
    bool ok = validate(key);
    obf_zero(buf, sizeof(buf));
    return ok;
}
```

### Pattern 4 — Debug build with sanitisers

`OBF_DISABLE` makes all macros transparent, so AddressSanitizer and UndefinedBehaviorSanitizer can instrument the code without interference from the cipher machinery.

```sh
gcc -std=c11 -Iinclude -DOBF_DISABLE \
    -fsanitize=address,undefined \
    src/init.c src/decrypt.c src/utils.c src/version.c \
    myapp.c -o myapp_asan
```

