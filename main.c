#include <mbedtls/rsa.h>
#include <mbedtls/md.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "base64url.h"
#include "config.h"
#include "directory.h"
#include "rsa.h"

struct writer_t
{
    char *buffer;
    int bytes_written;
    int buffer_size;
};

void
emit (struct writer_t *writer, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);

    int written =
        vsnprintf(writer->buffer + writer->bytes_written,
                  writer->buffer_size - writer->bytes_written,
                  format, ap);

    va_end(ap);
    writer->bytes_written += written;
}

void
emit_b64u (struct writer_t *writer, const char *binary, size_t length)
{
    int written = base64url_buf(writer->buffer + writer->bytes_written,
                                binary, length);
    writer->bytes_written += written;
}

char *
next_nonzero_char (char *ptr)
{
    while (*ptr == '\0') ptr++;
    return ptr;
}

void
emit_header (struct writer_t *writer,
             mbedtls_rsa_context *rsa,
             const char *nonce)
// If NONCE == NULL, it's a "header", otherwise it's "protected"
{
    const size_t number_length = rsa->len;
    char bignum_binary[number_length];
    char *first_nonzero;

    emit(writer, ("{"
                  "\"alg\":\"RS256\"," // RSA/SHA-256
                  "\"jwk\":"
                  "{\"e\":\""));

    // emit exponent
    mbedtls_mpi_write_binary(&(rsa->E), bignum_binary, number_length);
    first_nonzero = next_nonzero_char(bignum_binary);
    emit_b64u(writer, first_nonzero,
              number_length + (bignum_binary - first_nonzero));

    emit(writer, ("\",\"kty\":\"RSA\",\"n\":\""));

    // emit modulus
    mbedtls_mpi_write_binary(&(rsa->N), bignum_binary, number_length);
    first_nonzero = next_nonzero_char(bignum_binary);
    emit_b64u(writer, first_nonzero,
              number_length + (bignum_binary - first_nonzero));

    emit(writer, ("\"}"));

    if (nonce != NULL)
    {
        emit(writer, (","
                      "\"nonce\":\"%s\""),
             nonce);
    }

    emit(writer, ("}"));

    /* sprintf(buf, "{" */
    /*         "\"alg\":\"RS256\"," // RSA/SHA-256 */
    /*         "\"jwk\":" */
    /*         "{\"e\":\"%s\",\"kty\":\"RSA\",\"n\":\"%s\"}" */
    /*         "}", exp, mod); */
}

// See RFC 7515, section 3.3
void
emit_jws (struct writer_t *writer, mbedtls_rsa_context *rsa,
          const char *payload, const char *nonce)
{
    // INPUT: NONCE, PAYLOAD
    // 1. PAYLOAD <- B64U(PAYLOAD)
    // 2. HEADER <- MAKE_HEADER(NONCE, PKEY)
    // 3. PROTECTED <- B64U(MAKE_PROTECTED(?...))
    // 4. SIGNATURE <- RS256(PROTECTED + "." + PAYLOAD)
    // 5. RETURN JSON_FMT(HEADER, PROTECTED, PAYLOAD, SIGNATURE)

    // We have to use flattened serialization, see
    // <https://github.com/letsencrypt/boulder/blob/release/docs/acme-divergences.md>

    emit(writer, ("{"
                  "\"header\":"));

    emit_header(writer, rsa, NULL);

    emit(writer, (","
                  "\"protected\":"));

    int protected_pos = writer->bytes_written;
    emit_header(writer, rsa, nonce);
    int protected_length = writer->bytes_written - protected_pos;

    emit(writer, (","
                  "\"payload\":\""));

    int payload_pos = writer->bytes_written;
    // Zero byte doesn't count
    emit_b64u(writer, payload, strlen(payload));
    int payload_length = writer->bytes_written - payload_pos;
    emit(writer, ("\","
                  "\"signature\":\""));

    // Generate a signature
    {
        // First we calculate a hash

        // Initialize hasher object
        mbedtls_md_context_t md;
        mbedtls_md_init(&md);
        mbedtls_md_setup(&md, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                         0 /* no HMAC */);
        mbedtls_md_starts(&md);

        // Allocate a buffer for hash output. Using SHA-256, so
        // allocating 256 / 8 bytes is sufficient.
        char hash[32];

        // Calculate SHA256 hash of PROTECTED: ++ "." ++ PAYLOAD:
        mbedtls_md_update(&md, writer->buffer + protected_pos, protected_length);
        mbedtls_md_update(&md, ".", 1);
        mbedtls_md_update(&md, writer->buffer + payload_pos, protected_length);

        mbedtls_md_finish(&md, hash);
        mbedtls_md_free(&md);

        /* puts("---- THIS ARE THE HASH OCTETS ----"); */
        /* for (int i = 0; i < 32; i++) */
        /* { */
        /*     printf("%d ", hash[i]); */
        /* } */
        /* puts("\n---- HASH END ----"); */

        // Allocate a buffer for the signature
        char signature[rsa->len];

        // Use calculated hash to make a signature
        mbedtls_rsa_rsassa_pkcs1_v15_sign(
            rsa,
            // f_rng, if MBEDTLS_RSA_PRIVATE
            NULL,
            // parameter for f_rng
            NULL,
            // mode
            MBEDTLS_RSA_PUBLIC,
            // RS256
            MBEDTLS_MD_SHA256,
            // Hash length, not used but
            // I still pass it for
            // clarity I guess
            32,
            // Pointer to a hash
            hash,
            // Pointer to a signature buffer
            signature
            );

        // Emit signature
        emit_b64u(writer, signature, rsa->len);
    }

    emit(writer, ("\"}"));
}

#if 0 // Directory test
int
main (void)
{
    struct httpcfg *cfg;
    cfg = http_init();

    int r = refresh_directory_and_nonce(CA_ORIGIN, cfg);
    if (r == 0) puts("FAILURE");

    http_uninit(cfg);
}
#endif

#if 0 // Writer test
char buffer[256];
char binary[] = { 7,1,2,3,4,5,7,98,65,12,3,0 };

int
main (void)
{
    struct writer_t writer = {
        .buffer = buffer,
        .bytes_written = 0,
        .buffer_size = 256,
    };

    emit(&writer, "%d, %d\n", 2 + 2, 3 + 3);
    emit_b64u(&writer, binary, sizeof(binary));
    printf("%s\n", buffer);
}
#endif

#if 1

#define BITS 512

char buffer[2048];

const char payload[] = ("{"
                       "resource: \"new-reg\","
                       "contact: [\"mailto:mail@example.com\"],"
                       "agreement: \"http://example.com/agreement\""
                       "}");

int
main (void)
{
    struct writer_t writer = {
        .buffer = buffer,
        .bytes_written = 0,
        .buffer_size = 2048,
    };

    mbedtls_rsa_context rsa;
    generate_rsa_key(&rsa, BITS, 65537);
    const char *nonce = "hello-this-is-the-nonce";

    emit_jws(&writer, &rsa, payload, nonce);

    puts(buffer);
}
#endif
