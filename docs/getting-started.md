# Getting Started

## Prerequisites

| Tool | Minimum version | Notes |
|------|----------------|-------|
| C compiler | GCC 5 / Clang 6 / MSVC 2019 | Any C11-capable compiler |
| GNU Make | 3.82 | Optional — see manual builds below |
| `ar` | any | Bundled with GCC/Clang/Xcode |

No external libraries. No package manager. No build-time code generation.

---

## Quick Start

```sh
git clone <repo>
cd obfuscation

make          # builds build/libvortex.a + ./example
./example
```

Expected output (encrypted bytes in the hex line will vary by build time):

```
== VORTEX Obfuscation Framework - demonstration ==

[OBF_STRING] greeting: Hello from VORTEX!
[OBF_STRING] password: p4$$w0rd-do-not-leak
[OBF_STRING] token   : Bearer sk-9f3a-demo

[OBF_WITH] outer    : outer-secret
[OBF_WITH] inner    : inner-secret
[OBF_WITH] outer ok : outer-secret

[OBF_INT] answer    : 42
[OBF_INT] port      : 8443
[OBF_INT] checksum  : 0x1BADC0DE
[OBF_OFFSET] offset : 0xFA

[OBF_FLOAT] pi      : 3.141593
[OBF_FLOAT] scale   : 0.001000
[OBF_DOUBLE] gravity: 9.806650
[OBF_DOUBLE] euler  : 2.718281828459045

[obf_version]       : VORTEX/1.0.0
...
```

---

## Build Targets

| Target | Effect |
|--------|--------|
| `make` | Build `build/libvortex.a` and the `./example` binary (default) |
| `make lib` | Build `build/libvortex.a` only |
| `make example` | Build the `./example` binary only (requires lib) |
| `make debug` | Build with `OBF_DISABLE` — no encryption, useful for sanitisers; produces `example_debug` |
| `make clean` | Remove `build/`, `example`, and `example_debug` |
| `make compdb` | Regenerate `compile_commands.json` for clangd / IDE integration |

---

## Using the Library in Your Own Project

### Step 1 — Copy the headers

Copy the `include/` directory into your project (or add it to your include path):

```sh
cp -r include/ /your/project/include/
```

### Step 2 — Build the library

```sh
# From the obfuscation repo root:
make lib

# Then link against build/libvortex.a in your build system.
```

Or compile the four source files directly without Make:

```sh
gcc -std=c11 -Iinclude \
    src/init.c src/decrypt.c src/utils.c src/version.c \
    my_app.c -o my_app
```

### Step 3 — Add the include path and link

CMake:

```cmake
target_include_directories(myapp PRIVATE path/to/obfuscation/include)
target_link_libraries(myapp PRIVATE vortex)
```

Plain Makefile:

```make
CFLAGS  += -Ipath/to/obfuscation/include
LDFLAGS += -Lpath/to/obfuscation/build -lvortex
```

---

## Verify No Plaintext Leaks

After building, confirm the `strings` tool sees no sensitive ASCII in the binary:

```sh
strings example | grep -Ei "hello|vortex|secret|bearer"
# Expected: no output
```

---

## Compiler Compatibility Matrix

| Compiler | Platform | Status |
|----------|----------|--------|
| GCC 5+ | Linux x86_64 / ARM | Tested |
| Clang 6+ | macOS / Linux | Tested |
| Xcode Clang | macOS / iOS | Tested |
| MSVC 2019+ | Windows x64 | Supported (`/std:c11`) |
| MinGW-w64 | Windows | Supported |
