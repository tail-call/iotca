/*	$Id$ */
/*
 * Copyright (c) 2016 Kristaps Dzonsons <kristaps@bsd.lv>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

// Ported to mbedtls by Anton Istomin in 2018

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/socket.h>
#include <sys/param.h>
#include <arpa/inet.h>
#if TLS_API < 20160801
# include <sys/stat.h>
# include <sys/mman.h>
#endif

#include <assert.h>
#include <ctype.h>
#include <err.h>
#if TLS_API < 20160801
# include <fcntl.h>
#endif
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
//#include <tls.h>
#include <unistd.h>

#include "http.h"
//#include "extern.h"

#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/error.h>

#include "jsmn.h"

#ifndef DEFAULT_CA_FILE
# define DEFAULT_CA_FILE "/etc/ssl/cert.pem"
#endif

#define TLS_WANT_POLLIN MBEDTLS_ERR_SSL_WANT_READ
#define TLS_WANT_POLLOUT MBEDTLS_ERR_SSL_WANT_WRITE
#define TLS_PROTOCOLS_ALL 0
#define warnx(...) fprintf(stderr, __VA_ARGS__)
#define warn(...) fprintf(stderr, __VA_ARGS__)

/*
 * A buffer for transferring HTTP/S data.
 */
struct	httpxfer {
    char *hbuf;    /* header transfer buffer */
    size_t hbufsz;  /* header buffer size */
    int headok;  /* header has been parsed */
    char *bbuf;    /* body transfer buffer */
    size_t bbufsz;  /* body buffer size */
    int bodyok;  /* body has been parsed */
    char *headbuf; /* lookaside buffer for headers */
    struct httphead *head;    /* parsed headers */
    size_t headsz;  /* number of headers */
};

/*
 * An HTTP/S connection object.
 */
struct	http {
    /* int fd;     /\* connected socket *\/ */
    mbedtls_net_context *fd; /* connected socket */
    /* short port;   /\* port number *\/ */
    char *port;   /* port number */
    struct source src;    /* endpoint (raw) host */
    char *path;   /* path to request */
    char *host;   /* name of endpoint host */
    /* struct tls *ctx;    /\* if TLS *\/ */
    mbedtls_ssl_context *ctx;    /* if TLS */
    writefp writer; /* write function */
    readfp reader; /* read function */
};

struct	httpcfg {
    mbedtls_ssl_config *ssl_config;
    mbedtls_ctr_drbg_context *ctr_drbg;
    mbedtls_entropy_context *entropy;
};

// TEMP
void
_die (const char *msg)
{
    fprintf(stderr, msg);
    exit(1);
}

static void my_debug( void *ctx, int level,
                      const char *file, int line, const char *str )
{
    ((void) level);
    fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

char tls_error_buffer[256];

// TEMP
char *
tls_error (int code)
{
    mbedtls_strerror(code, tls_error_buffer, sizeof(tls_error_buffer));
    return tls_error_buffer;
}


// DONE
static ssize_t
dosysread(char *buf, size_t sz, const struct http *http)
{
    ssize_t rc;

    rc = mbedtls_net_recv(http->fd, buf, sz);
    if (rc < 0)
        warn("read\n");
    return (rc);
}

// DONE
static ssize_t
dosyswrite(const void *buf, size_t sz, const struct http *http)
{
    ssize_t rc;

    rc = mbedtls_net_send(http->fd, buf, sz);
    if (rc < 0)
        warn("%s: write\n", http->src.ip);
    return(rc);
}

// DONE
static ssize_t
dotlsread(char *buf, size_t sz, const struct http *http)
{
    ssize_t rc;

    do {
        rc = mbedtls_ssl_read(http->ctx, buf, sz);
    } while (TLS_WANT_POLLIN == rc || TLS_WANT_POLLOUT == rc);
    /* printf("%d\n", rc); */

    if (rc < 0)
        warnx("ssl_read: %s\n", tls_error(rc));
    return (rc);
}

// DONE
static ssize_t
dotlswrite(const void *buf, size_t sz, const struct http *http)
{
    ssize_t rc;

    do {
        rc = mbedtls_ssl_write(http->ctx, buf, sz);
    } while (TLS_WANT_POLLIN == rc || TLS_WANT_POLLOUT == rc);

    if (rc < 0)
        warnx("ssl_write: %s\n", tls_error(rc));
    return (rc);
}

/*
 * Free the resources of an http_init() object.
 */
void
http_uninit(struct httpcfg *p)
{
    if (NULL == p)
        return;
    if (NULL != p->ssl_config)
        mbedtls_ssl_config_free(p->ssl_config);
    free(p);
}

/*
 * This function allocates a configuration shared among multiple
 * connections.
 * It will generally be called once, then used in a series of
 * connections.
 * Returns the configuration object or NULL on errors.
 * A returned object must be freed with http_uninit().
 */
// DONE
struct httpcfg *
http_init(void)
{
    struct httpcfg *p;

    mbedtls_ssl_config *ssl_config;
    mbedtls_ctr_drbg_context *ctr_drbg;
    mbedtls_entropy_context *entropy;

    if (NULL == (p = malloc(sizeof(*p)))) {
        warn("malloc\n");
        return (NULL);
    } else if (NULL == (ssl_config = malloc(sizeof(*ssl_config)))) {
        warn("malloc\n");
        return (NULL);
    } else if (NULL == (ctr_drbg = malloc(sizeof(*ctr_drbg)))) {
        warn("malloc\n");
        return (NULL);
    } else if (NULL == (entropy = malloc(sizeof(*entropy)))) {
        warn("malloc\n");
        return (NULL);
    }

    // Init stuff we allocated memory for
    mbedtls_ssl_config_init(ssl_config);
    mbedtls_ctr_drbg_init(ctr_drbg);
    mbedtls_entropy_init(entropy);

    // Assign structure fields
    p->ssl_config = ssl_config;
    p->ctr_drbg = ctr_drbg;
    p->entropy = entropy;

    // Empty personalization string
    const unsigned char* pers = "";

    if (0 != mbedtls_ctr_drbg_seed(
            ctr_drbg, mbedtls_entropy_func, entropy,
            (const unsigned char *) pers,
            strlen(pers))) {
        warn("seed\n");
        goto err;
    }

    if (0 != mbedtls_ssl_config_defaults(
            ssl_config, MBEDTLS_SSL_IS_CLIENT,
            // STREAM is TCP, DATAGRAM is UDP
            MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT)) {
        warn("config_defaults\n");
        goto err;
    }

    // XXX: VERIFY_NONE is the least secure mode, DO NOT USE IT IN
    // WORKING CODE
    mbedtls_ssl_conf_authmode(ssl_config, MBEDTLS_SSL_VERIFY_NONE);

    // Setup RNG
    mbedtls_ssl_conf_rng(ssl_config, mbedtls_ctr_drbg_random, ctr_drbg);
    mbedtls_ssl_conf_dbg(ssl_config, my_debug, stdout );

    // Set read timeout (otherwise no timeout)
    mbedtls_ssl_conf_read_timeout(ssl_config, 2000);

    return (p);
err:
    http_uninit(p);
    return (NULL);
}

// FINE
static ssize_t
http_read(char *buf, size_t sz, const struct http *http)
{
    ssize_t ssz, xfer;

    xfer = 0;
    do {
        ssz = http->reader(buf, sz, http);
        if (0 == ssz || MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY == ssz)
            break;
        if (ssz < 0)
            return (ssz);
        printf("Read %d\n", ssz);
        xfer += ssz;
        sz -= ssz;
        buf += ssz;
    } while (ssz > 0 && sz > 0);

    return (xfer);
}

// FINE
static int
http_write(const char *buf, size_t sz, const struct http *http)
{
    ssize_t	 ssz, xfer;

    xfer = sz;
    while (sz > 0) {
        if ((ssz = http->writer(buf, sz, http)) < 0)
            return (-1);
        sz -= ssz;
        printf("Written %d\n", ssz);
        buf += (size_t)ssz;
    }
    return (xfer);
}

// DONE
void
http_disconnect(struct http *http)
{
    int rc;

    if (NULL != http->ctx) {
        do {
            rc = mbedtls_ssl_close_notify(http->ctx);
        } while (TLS_WANT_POLLIN == rc || TLS_WANT_POLLOUT == rc);
        if (rc < 0)
            warn("tls_close: %s\n", tls_error(rc));
        /* if (-1 == mbedtls_net_free(http->fd)) */
        /*     warn("net_free\n"); */
        mbedtls_net_free(http->fd);
        mbedtls_ssl_free(http->ctx);
    }

    http->fd = NULL;
    http->ctx = NULL;
}

// FINE
void
http_free(struct http *http)
{

    if (NULL == http)
        return;
    http_disconnect(http);
    free(http->host);
    free(http->path);
    free(http);
}

// DONE
struct http *
http_alloc(struct httpcfg *cfg,
           const char *host, const char *port, const char *path)
{
    int family, c, ret;
    mbedtls_net_context *fd;
    mbedtls_ssl_context *ctx;
    size_t cur, i = 0;
    struct http	*http;

    // Allocate stuff
    if (NULL == (http = calloc(1, sizeof(*http)))) {
        warn("calloc\n");
        return (NULL);
    } else if (NULL == (fd = malloc(sizeof(*fd)))) {
        warn("calloc\n");
        return (NULL);
    } else if (NULL == (ctx = malloc(sizeof(*ctx)))) {
        warn("calloc\n");
        return (NULL);
    }

    // Init structures
    mbedtls_net_init(fd);
    mbedtls_ssl_init(ctx);

    // Connect to a host
    ret = mbedtls_net_connect(fd, host, port, MBEDTLS_NET_PROTO_TCP);
    if (0 != ret) {
        warn("%s:%s: net_connect: %d\n", host, port, ret);
        goto err;
    }


    http->fd = fd;
    http->port = strdup(port);
    http->host = strdup(host);
    http->path = strdup(path);
    http->ctx = ctx;
    if (NULL == http->port ||
        NULL == http->host ||
        NULL == http->path) {
        warn("strdup\n");
        goto err;
    }

    if (0 == strcmp(port, "443")) {
        // Need TLS
        if (0 != mbedtls_ssl_setup(http->ctx, cfg->ssl_config)) {
            warn("ssl_setup\n");
            goto err;
        } else if (0 != mbedtls_ssl_set_hostname(http->ctx, "mbed TLS Server 1")) {
            warn("ssl_set_hostname\n");
            goto err;
        }

        mbedtls_ssl_set_bio(http->ctx, http->fd,
                            mbedtls_net_send,
                            mbedtls_net_recv,
                            mbedtls_net_recv_timeout);

        http->writer = dotlswrite;
        http->reader = dotlsread;

        return (http);

    } else {
        // TLS not needed
        http->writer = dosyswrite;
        http->reader = dosysread;

        return (http);
    }

err:
    http_free(http);
    return (NULL);
}

// FINE
struct httpxfer *
http_open(const struct http *http, const void *p, size_t psz)
{
    char *req;
    int c;
    struct httpxfer *trans;

    if (NULL == p) {
        c = asprintf(&req,
                     "GET %s HTTP/1.0\r\n"
                     "Host: %s\r\n"
                     "\r\n",
                     http->path, http->host);
    } else {
        c = asprintf(&req,
                     "POST %s HTTP/1.0\r\n"
                     "Host: %s\r\n"
                     "Content-Length: %zu\r\n"
                     "\r\n",
                     http->path, http->host, psz);
    }
    if (-1 == c) {
        warn("asprintf\n");
        return (NULL);
    } else if ( ! http_write(req, c, http)) {
        free(req);
        return (NULL);
    } else if (NULL != p && ! http_write(p, psz, http)) {
        free(req);
        return (NULL);
    }

    free(req);

    trans = calloc(1, sizeof(struct httpxfer));
    if (NULL == trans)
        warn("calloc\n");
    return (trans);
}

void
http_close(struct httpxfer *x)
{
	if (NULL == x)
		return;
	free(x->hbuf);
	free(x->bbuf);
	free(x->headbuf);
	free(x->head);
	free(x);
}

/*
 * Read the HTTP body from the wire.
 * If invoked multiple times, this will return the same pointer with the
 * same data (or NULL, if the original invocation returned NULL).
 * Returns NULL if read or allocation errors occur.
 * You must not free the returned pointer.
 */
// FINE
char *
http_body_read(const struct http *http,
               struct httpxfer *trans, size_t *sz)
{
    char		 buf[BUFSIZ];
    ssize_t		 ssz;
    void		*pp;
    size_t		 szp;

    if (NULL == sz)
        sz = &szp;

    /* Have we already parsed this? */

    if (trans->bodyok > 0) {
        *sz = trans->bbufsz;
        return (trans->bbuf);
    } else if (trans->bodyok < 0)
        return (NULL);

    *sz = 0;
    trans->bodyok = -1;

    do {
        /* If less than sizeof(buf), at EOF. */
        /* if ((ssz = http_read(buf, sizeof(buf), http)) < 0) */
        /*     return (NULL); */
        ssz = http_read(buf, sizeof(buf), http);

        if (0 == ssz) {
            break;
        }
        // On error return null
        else if (ssz < 0)
            return (NULL);

        pp = realloc(trans->bbuf, trans->bbufsz + ssz);
        if (NULL == pp) {
            warn("realloc\n");
            return (NULL);
        }
        trans->bbuf = pp;
        memcpy(trans->bbuf + trans->bbufsz, buf, ssz);
        trans->bbufsz += ssz;
    } while (sizeof(buf) == ssz);

    trans->bodyok = 1;
    *sz = trans->bbufsz;
    return (trans->bbuf);
}

// FINE
// This extracts specific header probably
struct httphead *
http_head_get(const char *v, struct httphead *h, size_t hsz)
{
    size_t i;

    for (i = 0; i < hsz; i++) {
        if (strcmp(h[i].key, v))
            continue;
        return (&h[i]);
    }
    return (NULL);
}

/*
 * Look through the headers and determine our HTTP code.
 * This will return -1 on failure, otherwise the code.
 */
// FINE
int
http_head_status(const struct http *http,
                 struct httphead *h, size_t sz)
{
    int rc;
    unsigned int code;
    struct httphead *st;

    if (NULL == (st = http_head_get("Status", h, sz))) {
        warnx("%s: no status header\n", http->src.ip);
        return (-1);
    }

    rc = sscanf(st->val, "%*s %u %*s", &code);
    if (rc < 0) {
        warn("sscanf\n");
        return (-1);
    } else if (1 != rc) {
        warnx("%s: cannot convert status header\n",
              http->src.ip);
        return (-1);
    }

    return (code);
}

/*
 * Parse headers from the transfer.
 * Malformed headers are skipped.
 * A special "Status" header is added for the HTTP status line.
 * This can only happen once http_head_read has been called with
 * success.
 * This can be invoked multiple times: it will only parse the headers
 * once and after that it will just return the cache.
 * You must not free the returned pointer.
 * If the original header parse failed, or if memory allocation fails
 * internally, this returns NULL.
 */
// FINE
struct httphead *
http_head_parse(const struct http *http,
                struct httpxfer *trans, size_t *sz)
{
    size_t hsz, szp;
    struct httphead *h;
    char *cp, *ep, *ccp, *buf;

    if (NULL == sz)
        sz = &szp;

    /*
     * If we've already parsed the headers, return the
     * previously-parsed buffer now.
     * If we have errors on the stream, return NULL now.
     */

    if (NULL != trans->head) {
        *sz = trans->headsz;
        return (trans->head);
    } else if (trans->headok <= 0)
        return (NULL);

    if (NULL == (buf = strdup(trans->hbuf))) {
        warn("strdup\n");
        return (NULL);
    }
    hsz = 0;
    cp = buf;

    do {
        if (NULL != (cp = strstr(cp, "\r\n")))
            cp += 2;
        hsz++;
    } while (NULL != cp);

    /*
     * Allocate headers, then step through the data buffer, parsing
     * out headers as we have them.
     * We know at this point that the buffer is nil-terminated in
     * the usual way.
     */

    h = calloc(hsz, sizeof(struct httphead));
    if (NULL == h) {
        warn("calloc\n");
        free(buf);
        return (NULL);
    }

    *sz = hsz;
    hsz = 0;
    cp = buf;

    do {
        if (NULL != (ep = strstr(cp, "\r\n"))) {
            *ep = '\0';
            ep += 2;
        }
        if (0 == hsz) {
            h[hsz].key = "Status";
            h[hsz++].val = cp;
            continue;
        }

        /* Skip bad headers. */
        if (NULL == (ccp = strchr(cp, ':'))) {
            warnx("%s: header without separator\n",
                  http->src.ip);
            continue;
        }

        *ccp++ = '\0';
        while (isspace((int)*ccp))
            ccp++;
        h[hsz].key = cp;
        h[hsz++].val = ccp;
    } while (NULL != (cp = ep));

    trans->headbuf = buf;
    trans->head = h;
    trans->headsz = hsz;
    return (h);
}

/*
 * Read the HTTP headers from the wire.
 * If invoked multiple times, this will return the same pointer with the
 * same data (or NULL, if the original invocation returned NULL).
 * Returns NULL if read or allocation errors occur.
 * You must not free the returned pointer.
 */
// FINE
char *
http_head_read(const struct http *http,
               struct httpxfer *trans, size_t *sz)
{
    char buf[BUFSIZ];
    ssize_t ssz;
    char *ep;
    void *pp;
    size_t szp;

    if (NULL == sz)
        sz = &szp;

    /* Have we already parsed this? */

    if (trans->headok > 0) {
        *sz = trans->hbufsz;
        return (trans->hbuf);
    } else if (trans->headok < 0)
        return (NULL);

    *sz = 0;
    ep = NULL;
    trans->headok = -1;

    /*
     * Begin by reading by BUFSIZ blocks until we reach the header
     * termination marker (two CRLFs).
     * We might read into our body, but that's ok: we'll copy out
     * the body parts into our body buffer afterward.
     */

    do {
        /* If less than sizeof(buf), at EOF. */
        /* if ((ssz = http_read(buf, sizeof(buf), http)) < 0) */
        /*     return (NULL); */
        /* else if (0 == ssz) */
        /*     break; */
        ssz = http_read(buf, sizeof(buf), http);

        if (0 == ssz) {
            break;
        }
        // On error return null
        else if (ssz < 0)
            return (NULL);

        pp = realloc(trans->hbuf, trans->hbufsz + ssz);
        if (NULL == pp) {
            warn("realloc\n");
            return (NULL);
        }
        trans->hbuf = pp;
        memcpy(trans->hbuf + trans->hbufsz, buf, ssz);
        trans->hbufsz += ssz;
        /* Search for end of headers marker. */
        ep = memmem(trans->hbuf, trans->hbufsz, "\r\n\r\n", 4);
    } while (NULL == ep && sizeof(buf) == ssz);

    if (NULL == ep) {
        warnx("%s: partial transfer\n", http->src.ip);
        return (NULL);
    }
    *ep = '\0';

    /*
     * The header data is invalid if it has any binary characters in
     * it: check that now.
     * This is important because we want to guarantee that all
     * header keys and pairs are properly nil-terminated.
     */

    if (strlen(trans->hbuf) != (uintptr_t)(ep - trans->hbuf)) {
        warnx("%s: binary data in header\n", http->src.ip);
        return (NULL);
    }

    /*
     * Copy remaining buffer into body buffer.
     */

    ep += 4;
    trans->bbufsz = (trans->hbuf + trans->hbufsz) - ep;
    trans->bbuf = malloc(trans->bbufsz);
    if (NULL == trans->bbuf) {
        warn("malloc\n");
        return (NULL);
    }
    memcpy(trans->bbuf, ep, trans->bbufsz);

    trans->headok = 1;
    *sz = trans->hbufsz;
    return (trans->hbuf);
}

// FINE
void
http_get_free(struct httpget *g)
{

    if (NULL == g)
        return;
    http_close(g->xfer);
    http_free(g->http);
    free(g);
}

// DONE
struct httpget *
http_get(struct httpcfg *cfg,
         const char *domain, const char *port, const char *path,
         const void *post, size_t postsz)
{
    struct http	*h;
    struct httpxfer *x;
    struct httpget *g;
    struct httphead *head;
    size_t headsz, bodsz, headrsz;
    int code;
    char *bod, *headr;

    h = http_alloc(cfg, domain, port, path);
    if (NULL == h)
        return (NULL);

    if (NULL == (x = http_open(h, post, postsz))) {
        http_free(h);
        return (NULL);
    } else if (NULL == (headr = http_head_read(h, x, &headrsz))) {
        http_close(x);
        http_free(h);
        return (NULL);
    } else if (NULL == (bod = http_body_read(h, x, &bodsz))) {
        http_close(x);
        http_free(h);
        return (NULL);
    }

    http_disconnect(h);

    if (NULL == (head = http_head_parse(h, x, &headsz))) {
        http_close(x);
        http_free(h);
        return (NULL);
    } else if ((code = http_head_status(h, head, headsz)) < 0) {
        http_close(x);
        http_free(h);
        return (NULL);
    }

    if (NULL == (g = calloc(1, sizeof(struct httpget)))) {
        warn("calloc\n");
        http_close(x);
        http_free(h);
        return (NULL);
    }

    g->headpart = headr;
    g->headpartsz = headrsz;
    g->bodypart = bod;
    g->bodypartsz = bodsz;
    g->head = head;
    g->headsz = headsz;
    g->code = code;
    g->xfer = x;
    g->http = h;
    return (g);
}
