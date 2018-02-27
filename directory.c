#include <string.h>
#include <stdio.h> // for ssize_t (XXX: ???)

#include "http.h"
#include "jsmn.h"

#include "directory.h"
#include "config.h"

// Global variables
struct directory_t Directory;
char Nonce[MAX_NONCE_LENGTH];

static void
with_json (const char *json,
           size_t token_limit,
           void (*callback)(jsmntok_t*, size_t))
{
    jsmn_parser parser;
    jsmn_init(&parser);

    jsmntok_t tokens[token_limit];
    int number_of_tokens = jsmn_parse(&parser, json, strlen(json),
                                      tokens, token_limit);

    (*callback)(tokens, number_of_tokens);
}

static void
json_directory_fill (const char *json)
// Read `/directory' object and fill Directory fields
{
#define _MATCH(str) (0 == memcmp((str), json + tokens[i].start, \
                                 tokens[i].end - tokens[i].start))
#define _STORE(place) (strncpy(place, json + tokens[i].start, \
                               tokens[i].end - tokens[i].start))
    void callback (jsmntok_t *tokens, size_t size)
    {
        // Assuming /directory resource: root token is JSMN_OBJECT, so
        // skip it and start with i = 0
        for (int i = 1; i < size; i++)
        {
            if (JSMN_STRING == tokens[i].type)
            {
                if (_MATCH("key-change"))
                {
                    i++;
                    _STORE((char*)(Directory.key_change));
                }
                else if (_MATCH("new-authz"))
                {
                    i++;
                    _STORE((char*)(Directory.new_authz));
                }
                else if (_MATCH("new-cert"))
                {
                    i++;
                    _STORE((char*)(Directory.new_cert));
                }
                else if (_MATCH("new-reg"))
                {
                    i++;
                    _STORE((char*)(Directory.new_reg));
                }
                else if (_MATCH("revoke-cert"))
                {
                    i++;
                    _STORE((char*)(Directory.revoke_cert));
                }
                else if (_MATCH("terms-of-service"))
                {
                    i++;
                    _STORE((char*)(Directory.terms_of_service));
                }
            }
        }
    }
#undef _MATCH
#undef _STORE

    with_json(json, DIRECTORY_TOKEN_LIMIT, callback);
}

// A set of characters to validate nonces against
const char *BASE64URL_CHARACTERS =
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "-_";

// From the spec, page 14:
// `The value of the Replay-Nonce field MUST be an octet string encoded
//  according to the base64url encoding described in Section 2 of
//  [RFC7515]. Clients MUST ignore invalid Replay-Nonce values.'
static int
is_nonce_valid (const char *nonce)
{
    for (const char *c = nonce; *c != '\0'; c++)
    {
        if (strchr(BASE64URL_CHARACTERS, *c) == NULL)
        {
            return 0;
        }
    }
    return 1;
}

int
refresh_directory_and_nonce (const char *url, struct httpcfg *cfg)
// Gets a /directory object from URL and parses it into the global
// Directory structure. Also extracts Nonce from Replay-Nonce header.
{
    struct httpget *get;

    // Deinitialize Nonce and Directory
    memset((void*)Nonce, 0, sizeof(Nonce));
    memset((void*)&Directory, 0, sizeof(Directory));

    // If POST is non-null, doing POST request
    get = http_get(cfg, CA_ORIGIN, "443", "/directory", NULL, 0);

    if (get == NULL)
    {
        return 0;
    }
    else
    {
        strncpy((char*)Nonce,
                http_head_get("Replay-Nonce", get->head, get->headsz)->val,
                MAX_NONCE_LENGTH - 1);

        json_directory_fill(get->bodypart);

        http_get_free(get);
        return 1;
    }
    ssize_t x;
}
