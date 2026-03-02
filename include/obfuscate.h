/*
 * obfuscate.h — The main header for the VORTEX Obfuscation Framework.
 *
 * This is the only file you need to include in your project.
 * It pulls in all the necessary macros and functions to encrypt your
 * strings and numbers at compile time and decrypt them at runtime.
 *
 * HOW TO USE IT
 * -------------
 * 1. Include this header:
 *    #include "obfuscate.h"
 *
 * 2. Call obf_init() once when your program starts:
 *    obf_init();
 *
 * 3. Use the macros to hide your data!
 *
 *    // For strings, you can use OBF_STRING. On GCC/Clang, it will automatically
 *    // wipe the memory when the string goes out of scope.
 *    OBF_STRING(my_password, "super_secret");
 *    login(my_password);
 *
 *    // If you want guaranteed cleanup on any compiler (like MSVC), use OBF_WITH:
 *    OBF_WITH(token, "Bearer xyz") {
 *        send_request(token);
 *    }
 *
 *    // You can also hide numbers!
 *    int    port    = OBF_INT(8080);
 *    float  speed   = OBF_FLOAT(1.5f);
 *    double gravity = OBF_DOUBLE(9.81);
 *
 * DEBUGGING
 * ---------
 * If you need to debug your code and don't want the obfuscation getting in the way,
 * just define OBF_DISABLE before compiling (e.g., compile with -DOBF_DISABLE).
 * This will make all the macros pass through your original values without encrypting them.
 *
 * HOW IT WORKS (Briefly)
 * ----------------------
 * - It generates a unique key for your build based on the current date.
 * - Every time you use a macro, it creates a unique key for that specific line of code.
 * - It encrypts the data at compile time using a custom cipher (VKF) and an S-box.
 * - At runtime, obf_init() rebuilds the S-box, and the macros call functions to decrypt the data.
 */

#ifndef OBFUSCATE_H
#define OBFUSCATE_H

#include "vortex/platform.h"   /* OBFAPI, OBFAPI_NOINLINE, OBFAPI_OPTNONE    */
#include "vortex/config.h"     /* OBF_MAX_LEN, OBF_DISABLE pass-through       */
#include "vortex/keys.h"       /* OBF_GSEED, OBF_KEY, S-box params, MODINV256 */
#include "vortex/cipher.h"     /* Cipher engine macros, OBF_WITH, OBF_INT     */
#include "vortex/api.h"        /* ObfContext, function declarations            */

#endif /* OBFUSCATE_H */
