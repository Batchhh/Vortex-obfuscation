# VORTEX Obfuscation Framework — Documentation

| File | Contents |
|------|----------|
| [getting-started.md](getting-started.md) | Prerequisites, build instructions, compiler matrix |
| [api.md](api.md) | Macro and API reference, OBF_STRING vs OBF_WITH guide |
| [cipher.md](cipher.md) | VORTEX algorithm specification |
| [ffi.md](ffi.md) | C++, Rust, Python, Swift integration |

---

## Project Structure

```
obfuscation/
├── include/
│   ├── obfuscate.h          ← include this in user code
│   ├── obf_ffi.h            ← standalone FFI declarations
│   └── vortex/              ← implementation detail (do not include directly)
│       ├── platform.h       ←   compiler/platform macros
│       ├── config.h         ←   OBF_MAX_LEN, OBF_DISABLE pass-throughs
│       ├── keys.h           ←   key derivation (GSEED, KEY, S-box params)
│       ├── cipher.h         ←   cipher engine macros (OBF_STRING, OBF_WITH, OBF_INT, …)
│       └── api.h            ←   ObfContext type + function declarations
├── src/
│   ├── internal.h           ←   shared state (not installed)
│   ├── init.c               ←   obf_init()
│   ├── decrypt.c            ←   obf_decrypt()
│   ├── utils.c              ←   obf_zero(), obf_decode_int/float/double/offset()
│   └── version.c            ←   obf_version()
├── docs/                    ← you are here
├── example_usage.c          ← runnable demonstration
├── Makefile
└── compile_commands.json    ← clangd/IDE integration
```

---

## 30-Second Example

```c
#include "obfuscate.h"
#include <stdio.h>

int main(void) {
    obf_init();   /* must be called once before any obf_decrypt */

    /* "secret-key" is encrypted at compile time — not visible in the binary */
    OBF_STRING(key, "secret-key");   /* auto-zeroes on scope exit (GCC/Clang) */
    printf("%s\n", key);

    /* Use OBF_WITH for guaranteed cleanup on any compiler (including MSVC) */
    OBF_WITH(token, "Bearer sk-9f3a") {
        send_request(token);   /* illustrative — replace with your HTTP call */
    }   /* token is zeroed here on every exit path */

    /* integers, floats, offsets are XOR/rotate-obfuscated */
    int    port    = OBF_INT(8443);
    float  scale   = OBF_FLOAT(0.001f);   /* requires -O1+ */
    size_t off     = OBF_OFFSET(0xfa);
    printf("%d %f %zu\n", port, (double)scale, off);

    return 0;
}
```

---

## Build

```sh
make && ./example
```

---

## Verify No Plaintext Leaks

```sh
strings example | grep -Ei "hello|vortex|secret|bearer"
# Expected: no output
```
