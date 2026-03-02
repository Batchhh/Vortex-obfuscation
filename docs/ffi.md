# Cross-Language FFI Guide

`include/obf_ffi.h` exposes the six runtime functions over a stable C ABI.
Include it from any language that can call C code.

Build the shared library first:

```sh
# Linux
gcc -std=c11 -Iinclude -shared -fPIC -fvisibility=hidden \
    src/init.c src/decrypt.c src/utils.c src/version.c \
    -o libvortex.so

# macOS
gcc -std=c11 -Iinclude -dynamiclib -fvisibility=hidden \
    src/init.c src/decrypt.c src/utils.c src/version.c \
    -o libvortex.dylib

# Windows (MSVC)
cl /std:c11 /I include /LD src\init.c src\decrypt.c src\utils.c src\version.c
# produces vortex.dll + vortex.lib
```

---

## C++

Include the FFI header inside your C++ translation unit. The `extern "C"`
block is already present — no changes needed.

```cpp
#include "obf_ffi.h"
#include <iostream>
#include <vector>
#include <cstring>

int main() {
    obf_init();

    // obf_decrypt with a caller-supplied buffer
    unsigned char buf[256] = {};
    // blob must be built with OBF_SEED0, OBF_SEED1, OBF_ENC_ALL in a .c file
    extern const unsigned char MY_BLOB[];
    extern const size_t        MY_BLOB_LEN;

    const char *s = obf_decrypt(MY_BLOB, MY_BLOB_LEN, buf);
    std::cout << s << '\n';
    obf_zero(buf, sizeof(buf));
}
```

To produce the blob from C, add a companion `.c` file (compiled with
`-Iinclude`) that is linked into your C++ project:

```c
/* secrets.c — must be compiled as C, not C++ */
#include "obfuscate.h"

const unsigned char MY_BLOB[] = {
    OBF_SEED0, OBF_SEED1, OBF_ENC_ALL("my secret string")
};
const size_t MY_BLOB_LEN = sizeof("my secret string") + 2;
```

---

## Rust

### With bindgen

```toml
# Cargo.toml
[build-dependencies]
bindgen = "0.69"
```

```rust
// build.rs
fn main() {
    bindgen::Builder::default()
        .header("include/obf_ffi.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("bindgen failed")
        .write_to_file(std::path::PathBuf::from(
            std::env::var("OUT_DIR").unwrap()).join("vortex.rs"))
        .unwrap();

    println!("cargo:rustc-link-lib=vortex");
    println!("cargo:rustc-link-search=native=path/to/build");
}
```

### Manual extern block

```rust
// src/vortex.rs
use std::os::raw::{c_char, c_int, c_uint, c_uchar};

#[link(name = "vortex")]
extern "C" {
    pub fn obf_init();
    pub fn obf_decrypt(blob: *const c_uchar,
                       len:  usize,
                       out:  *mut c_uchar) -> *const c_char;
    pub fn obf_zero(buf: *mut c_uchar, len: usize);
    pub fn obf_version() -> *const c_char;
    pub fn obf_decode_int(enc: c_uint, key: c_uint) -> c_int;
    pub fn obf_decode_offset(enc: u64, key: u64) -> usize;
}
```

```rust
// Usage
unsafe {
    vortex::obf_init();
    let mut buf = [0u8; 256];
    let ptr = vortex::obf_decrypt(BLOB.as_ptr(), BLOB.len(), buf.as_mut_ptr());
    let s = std::ffi::CStr::from_ptr(ptr).to_str().unwrap();
    println!("{}", s);
    vortex::obf_zero(buf.as_mut_ptr(), 256);
}
```

---

## Python (ctypes)

```python
import ctypes
import os

lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), "libvortex.so"))

# Declare signatures
lib.obf_init.restype  = None
lib.obf_init.argtypes = []

lib.obf_decrypt.restype  = ctypes.c_char_p
lib.obf_decrypt.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),   # blob
    ctypes.c_size_t,                  # len
    ctypes.POINTER(ctypes.c_uint8),   # out_buf
]

lib.obf_zero.restype  = None
lib.obf_zero.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]

lib.obf_version.restype  = ctypes.c_char_p
lib.obf_version.argtypes = []

lib.obf_decode_int.restype  = ctypes.c_int
lib.obf_decode_int.argtypes = [ctypes.c_uint, ctypes.c_uint]

lib.obf_decode_offset.restype  = ctypes.c_size_t
lib.obf_decode_offset.argtypes = [ctypes.c_uint64, ctypes.c_uint64]

# Use
lib.obf_init()

print(lib.obf_version().decode())  # b'VORTEX/1.0.0'

# Decrypt a blob produced in C (load from shared data / ctypes array)
BLOB = (ctypes.c_uint8 * len(blob_bytes))(*blob_bytes)
buf  = (ctypes.c_uint8 * 256)()
result = lib.obf_decrypt(BLOB, len(blob_bytes), buf)
print(result.decode())
lib.obf_zero(buf, 256)
```

---

## Swift

Add a bridging header to your Xcode project or Swift Package:

```c
// VortexBridgingHeader.h
#include "obf_ffi.h"
```

```swift
import Foundation

// In your module map or bridging header, include VortexBridgingHeader.h

func decryptBlob(_ blob: [UInt8], length: Int) -> String? {
    obf_init()
    var buf = [UInt8](repeating: 0, count: 256)
    let result = blob.withUnsafeBufferPointer { blobPtr in
        buf.withUnsafeMutableBufferPointer { bufPtr in
            obf_decrypt(blobPtr.baseAddress, length, bufPtr.baseAddress)
        }
    }
    guard let ptr = result else { return nil }
    let s = String(cString: ptr)
    buf.withUnsafeMutableBufferPointer { ptr in
        obf_zero(ptr.baseAddress, 256)
    }
    return s
}
```

---

## Function Reference

All six functions are available over the C ABI:

| C signature | Description |
|-------------|-------------|
| `void obf_init(void)` | Initialise S-box. Call once before any decrypt. |
| `const char *obf_decrypt(const unsigned char *blob, size_t len, unsigned char *out)` | Decrypt a compile-time blob. |
| `void obf_zero(unsigned char *buf, size_t len)` | Securely zero a buffer. |
| `const char *obf_version(void)` | Return `"VORTEX/1.0.0"` (obfuscated in binary). |
| `int obf_decode_int(unsigned int enc, unsigned int key)` | Decode an `OBF_INT` value. |
| `size_t obf_decode_offset(unsigned long long enc, unsigned long long key)` | Decode an `OBF_OFFSET` value. |

Blob layout expected by `obf_decrypt`:

```
[S[SEED0] (1 byte)][S[SEED1] (1 byte)][encrypted bytes (len-2 bytes)]
```

`blob[0]` is `OBF_SBOX(OBF_SEED0)` and `blob[1]` is `OBF_SBOX(OBF_SEED1)` — the raw seed bytes are passed through the compile-time S-box before storage. `obf_decrypt` recovers the original seeds via `sbox_inv` before running the keystream.
