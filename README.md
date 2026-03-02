# Vortex - Obfuscation framework

[![CI](https://github.com/Batchhh/Vortex-obfuscation/actions/workflows/ci.yml/badge.svg)](https://github.com/Batchhh/Vortex-obfuscation/actions/workflows/ci.yml)
[![Release](https://github.com/Batchhh/Vortex-obfuscation/actions/workflows/release.yml/badge.svg)](https://github.com/Batchhh/Vortex-obfuscation/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/Batchhh/Vortex-obfuscation)](https://github.com/Batchhh/Vortex-obfuscation/releases/latest)

A C11 library that encrypts strings and numeric constants **at compile time**, making them invisible to binary analysis tools like `strings`, IDA Pro, and Ghidra.

No external dependencies. Stack-only allocation. Drop-in macros.

## The problem

Sensitive values embedded in a binary — API keys, passwords, version strings, magic constants — are trivially extracted:

```sh
strings my_binary | grep -i "bearer"
# Bearer sk-9f3a...   ← plaintext, readable by anyone
```

VORTEX encrypts those values before compilation so nothing sensitive ever appears in the binary.

## How it works

Each macro call site gets a unique encryption key derived from `__FILE__`, `__LINE__`, `__DATE__`, and `__TIME__`. A global S-box is built from `__DATE__` alone. At compile time the preprocessor emits already-encrypted byte arrays; at runtime `obf_init()` / `obf_decrypt()` reverse the cipher and hand you a normal C string or number, then wipe it from memory when it goes out of scope.

See [docs/cipher.md](docs/cipher.md) for the full algorithm specification.

## Quick start

```c
#include "obfuscate.h"
#include <stdio.h>

int main(void) {
    obf_init();   /* call once before any decryption */

    /* encrypted at compile time; auto-zeroed when the variable goes out of scope */
    OBF_STRING(key, "secret-api-key");
    printf("%s\n", key);

    /* guaranteed cleanup on every exit path, including MSVC */
    OBF_WITH(token, "Bearer sk-9f3a") {
        printf("%s\n", token);
    }   /* zeroed here */

    int    port  = OBF_INT(8443);
    float  scale = OBF_FLOAT(0.001f);   /* requires -O1 or higher */
    size_t off   = OBF_OFFSET(0xfa);

    return 0;
}
```

## Build

Requires a C11 compiler (`gcc` or `clang`) and `make`.

```sh
make            # build libvortex.a + example binary
make lib        # static library only
make debug      # transparent mode (OBF_DISABLE), no encryption — useful with sanitizers
make clean
```

## Verify no plaintext leaks

```sh
make && strings example | grep -Ei "hello|secret|bearer"
# Expected: no output
```

## API at a glance

| Macro / function | Purpose |
|---|---|
| `obf_init()` | Initialize S-box (call once at startup) |
| `OBF_STRING(var, "str")` | Declare + decrypt a string; auto-zeroes on scope exit (GCC/Clang) |
| `OBF_WITH(var, "str") { }` | Scoped decrypt with guaranteed cleanup (all compilers) |
| `OBF_INT(n)` | Obfuscate an integer constant |
| `OBF_FLOAT(f)` | Obfuscate a float constant (requires `-O1+`) |
| `OBF_DOUBLE(d)` | Obfuscate a double constant (requires `-O1+`) |
| `OBF_OFFSET(n)` | Obfuscate a `size_t` memory offset |
| `obf_zero(ptr, len)` | Secure memory wipe (compiler-safe, not optimised away) |
| `obf_version()` | Return the library version string (itself encrypted) |

Full reference: [docs/api.md](docs/api.md)
Cross-language bindings (C++, Rust, Python, Swift): [docs/ffi.md](docs/ffi.md)

## License

Apache 2.0 — see [LICENSE](LICENSE).
