/*
 * obf_ffi.h
 * Cross-language bindings for the Obfuscation Framework.
 *
 * This file lets you use the pre-built library from other languages like C++,
 * Rust, Python, or Swift without needing the main obfuscate.h header.
 *
 * Usage examples:
 *
 * C++:
 *   #include "obf_ffi.h"
 *   obf_init();
 *   unsigned char buf[256];
 *   const char *s = obf_decrypt(blob, blob_len, buf);
 *
 * Rust (via extern "C"):
 *   extern "C" {
 *       fn obf_init();
 *       fn obf_decrypt(blob: *const u8, len: usize, out: *mut u8) -> *const i8;
 *       fn obf_zero(buf: *mut u8, len: usize);
 *       fn obf_version() -> *const i8;
 *       fn obf_decode_int(enc: u32, key: u32) -> i32;
 *       fn obf_decode_offset(enc: u64, key: u64) -> usize;
 *   }
 *
 * Python (via ctypes):
 *   import ctypes
 *   lib = ctypes.CDLL("./build/libvortex.so")
 *   lib.obf_init()
 *   lib.obf_decrypt.restype  = ctypes.c_char_p
 *   lib.obf_decrypt.argtypes = [ctypes.POINTER(ctypes.c_uint8),
 *                                ctypes.c_size_t,
 *                                ctypes.POINTER(ctypes.c_uint8)]
 *
 * Swift (via bridging header):
 *   #include "obf_ffi.h"
 *   // Call obf_init(), obf_decrypt(), etc. directly.
 */

#ifndef OBF_FFI_H
#define OBF_FFI_H

#include <stddef.h>   /* size_t */

/* 
 * Standalone OBFAPI definition so you don't need obfuscate.h.
 * Windows needs dllimport when using the pre-built DLL.
 */
#ifndef OBFAPI
#   if defined(_WIN32) || defined(_WIN64)
#       define OBFAPI __declspec(dllimport)
#   elif defined(__clang__) || defined(__GNUC__)
#       define OBFAPI __attribute__((visibility("default")))
#   else
#       define OBFAPI
#   endif
#endif

/* 
 * Functions you can call from other languages 
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Sets up the decryption tables.
 * Call this once when your program starts.
 */
OBFAPI void        obf_init(void);

/*
 * Decrypts a chunk of encrypted data.
 *   blob    : [S[SEED0]][S[SEED1]][S[SEED2]][S[SEED3]][enc_byte_0 .. enc_byte_{len-5}]
 *   len     : The length of the original string + 4
 *   out_buf : A buffer you provide to hold the decrypted string (must be at least 256 bytes)
 *   Returns : A pointer to your out_buf so you can use it right away.
 *   Note    : Remember to clean up out_buf using obf_zero() when you're done!
 */
OBFAPI const char* obf_decrypt(const unsigned char *blob, size_t len,
                                unsigned char *out_buf);

/*
 * Wipes a chunk of memory with zeros securely so it can't be recovered.
 */
OBFAPI void        obf_zero(unsigned char *buf, size_t len);

/*
 * Returns the version of the obfuscation library (e.g. "VORTEX/1.0.0").
 * The string returned points to an internal buffer, so don't try to free it.
 */
OBFAPI const char* obf_version(void);

/*
 * Decodes an integer that was obfuscated with the OBF_INT macro.
 */
OBFAPI int         obf_decode_int(unsigned int enc, unsigned int key);

/*
 * Decodes an offset that was obfuscated with the OBF_OFFSET macro.
 */
OBFAPI size_t      obf_decode_offset(unsigned long long enc, unsigned long long key);

#ifdef __cplusplus
}
#endif

#endif /* OBF_FFI_H */
