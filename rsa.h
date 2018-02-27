#ifndef _RSA_H_
#define _RSA_H_

#include <mbedtls/rsa.h>

int generate_rsa_key(mbedtls_rsa_context *ctx, int bits, int exponent);

#endif // _RSA_H_
