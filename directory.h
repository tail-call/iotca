#ifndef _DIRECTORY_H_
#define _DIRECTORY_H_

#include "http.h"
#include "config.h"

#define DIRECTORY_LENGTH 6

typedef char directory_entry[MAX_DIRECTORY_PATH_LENGTH];

struct directory_t
{
    directory_entry key_change;
    directory_entry new_authz;
    directory_entry new_cert;
    directory_entry new_reg;
    directory_entry revoke_cert;
    directory_entry terms_of_service;
};

// Global variables
extern struct directory_t Directory;
extern char Nonce[MAX_NONCE_LENGTH];

int refresh_directory_and_nonce(const char *url, struct httpcfg *cfg);

#endif // _DIRECTORY_H_
