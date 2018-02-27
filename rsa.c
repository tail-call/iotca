#include <mbedtls/rsa.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "rsa.h"

static int
generate (void *param, unsigned char *buf, size_t length)
// XXX: should be different
{
    for (int i = 0; i < length; i++)
    {
        buf[i] = random();
    }
    return 0;
}

int
generate_rsa_key (mbedtls_rsa_context *ctx,
                  int bits /* recommended: 512 */,
                  int exponent /* recommended: 65537 */)
{
    srand(time(NULL));
    mbedtls_rsa_init(
        ctx,
        MBEDTLS_RSA_PKCS_V21, // Padding mode, dunno what to set to
        MBEDTLS_RSA_PKCS_V21 // Hash identifier, dunno what to set to
        );

    return mbedtls_rsa_gen_key(
        ctx, // context
        generate, // RNG function
        NULL, // RNG parameter
        512, // number of bits of N, minimum is 128, see
             // <https://github.com/ARMmbed/mbedtls/blob/development/library/rsa.c>
        65537 // exponent
        );
}
