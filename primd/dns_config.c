/*
 * Copyright (c) 2010 Satoshi Ebisawa. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. The names of its contributors may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include "dns.h"
#include "dns_config.h"
#include "dns_engine.h"
#include "dns_file.h"
#include "dns_list.h"

#define MODULE "config"

#define SINGULAR   1
#define PLURAL     2

#define CONFIG_STRING_MAX   256

#define CONFIG_PTR(config, offset)   ((void *) ((uint8_t *) (config) + (offset)))

enum {
    CONFIG_TOKEN_ZERO = 0,
    CONFIG_TOKEN_STRING,
    CONFIG_TOKEN_BLOCK_OPEN,    /* { */
    CONFIG_TOKEN_BLOCK_CLOSE,   /* } */
    CONFIG_TOKEN_RB_OPEN,       /* ( */
    CONFIG_TOKEN_RB_CLOSE,      /* ) */
    CONFIG_TOKEN_SB_OPEN,       /* [ */
    CONFIG_TOKEN_SB_CLOSE,      /* ] */
    CONFIG_TOKEN_COMMA,         /* , */
    CONFIG_TOKEN_COLON,         /* : */
    CONFIG_TOKEN_SEMICOLON,     /* ; */
};

typedef struct {
    int                    tok_code;
    char                   tok_string[CONFIG_STRING_MAX];
} config_token_t;

typedef struct {
    dns_file_handle_t      ctx_handle;
    config_token_t         ctx_ungot;
} config_context_t;

typedef struct config_item config_item_t;
typedef struct config_class config_class_t;
typedef void (config_init_t)(void *config);
typedef void (config_destroy_t)(void *config);
typedef int (config_parse_skey_t)(void *dest, config_context_t *context);

struct config_item {
    int                    item_plurality;
    char                  *item_name;
    void *               (*item_parser)(void *dest, char *tstring, config_context_t *context);
    int                    item_offset;
    config_class_t        *item_next;
};

struct config_class {
    config_item_t         *cc_items;
    int                    cc_size;
    config_init_t         *cc_init;
    config_destroy_t      *cc_destroy;
    config_parse_skey_t   *cc_parse_skey;
};

static dns_config_root_t *config_read(char *filename);
static void config_wait_update(void);
static void config_init(void *config, config_class_t *cc);
static void config_free(void *config, config_class_t *cc);
static int config_parse(void *config, config_class_t *cc, config_context_t *context);
static int config_parse_section(void *config,config_class_t *cc, config_context_t *context);
static int config_parse_param(void *config, config_item_t *item, char *tstrinf, config_context_t *context);
static config_item_t *config_get_matched_item(config_item_t *items, char *string);
static int config_get_token(config_token_t *token, config_context_t *context);
static int config_get_token2(config_token_t *token, int code, config_context_t *context);
static void config_unget_token(config_token_t *token, config_context_t *context);
static void config_tokenize(config_token_t *token, char *string);
static void config_error_unexpected(config_token_t *token, config_context_t *context);
static void config_error_eof(config_context_t *context);
static void config_error(char *msg, config_token_t *token, config_context_t *context);
static void *config_parse_int(void *dest, char *tstring, config_context_t *context);
static void *config_parse_string(void *dest, char *tstring, config_context_t *context);
static void *config_parse_zone_engine(void *dest, char *tstring, config_context_t *context);
static void config_zone_search_destroy(dns_config_zone_search_t *zs);
static int config_zone_parse_skey(dns_config_zone_t *zone, config_context_t *context);

static config_item_t ConfigItemZoneSearch[] = {
    { PLURAL,    NULL,        config_parse_zone_engine,   offsetof(dns_config_zone_search_t, zs_engine) },
    { 0 },
};

static config_class_t ConfigClassZoneSearch = {
    ConfigItemZoneSearch,
    sizeof(dns_config_zone_search_t),
    NULL,
    (config_destroy_t *) config_zone_search_destroy,
};

static config_item_t ConfigItemZone[] = {
    { SINGULAR,  "search",   NULL,    offsetof(dns_config_zone_t, z_search),   &ConfigClassZoneSearch },
    { 0 },
};

static config_class_t ConfigClassZone = {
    ConfigItemZone,
    sizeof(dns_config_zone_t),
    NULL,
    NULL,
    (config_parse_skey_t *) config_zone_parse_skey,
};

static config_item_t ConfigItemRoot[] = {
    { PLURAL,    "zone",     NULL,    offsetof(dns_config_root_t, r_zone),     &ConfigClassZone },
    { 0 },
};

static config_class_t ConfigClassRoot = {
    ConfigItemRoot,
    sizeof(dns_config_root_t),
};

dns_config_root_t *ConfigRoot;

int
dns_config_update(char *filename)
{
    dns_config_root_t *old_root = ConfigRoot;

    if (filename == NULL || filename[0] == 0) {
        plog(LOG_ERR, "%s: no configuration found", MODULE);
        return -1;
    }

    plog(LOG_DEBUG, "%s: config = %s", MODULE, filename);

    if ((ConfigRoot = config_read(filename)) == NULL) {
        plog(LOG_ERR, "%s: configuration read failed", MODULE);
        return (old_root == NULL) ? -1 : 0;
    }

    if (old_root != NULL) {
        config_wait_update();
        config_free(old_root, &ConfigClassRoot);
    }

    return 0;
}

static dns_config_root_t *
config_read(char *filename)
{
    dns_config_root_t *root;
    config_context_t context;

    memset(&context, 0, sizeof(context));

    if ((root = calloc(1, sizeof(dns_config_root_t))) == NULL)
        return NULL;

    if (dns_file_open(&context.ctx_handle, filename) < 0) {
        plog(LOG_DEBUG, "%s: dns_file_open() failed", MODULE);
        free(root);
        return NULL;
    }

    config_init(root, &ConfigClassRoot);

    if (config_parse(root, &ConfigClassRoot, &context) < 0) {
        plog(LOG_DEBUG, "%s: config_parse() failed", MODULE);
        dns_file_close(&context.ctx_handle);
        free(root);
        return NULL;
    }

    dns_file_close(&context.ctx_handle);

    return root;
}

static void
config_wait_update(void)
{
    for (;;) {
        if (dns_session_check_config() == 0)
            break;

        plog(LOG_DEBUG, "%s: waiting...", MODULE);
        sleep(1);
    }
}

static void
config_init(void *config, config_class_t *cc)
{
    int i;
    void *p;
    config_item_t *items;

    if (cc->cc_init != NULL)
        cc->cc_init(config);

    for (i = 0, items = cc->cc_items; items[i].item_plurality != 0; i++) {
        p = CONFIG_PTR(config, items[i].item_offset);
        if (items[i].item_next != NULL) {
            if (items[i].item_plurality == SINGULAR)
                config_init(p, items[i].item_next);
        }
    }
}

static void
config_free(void *config, config_class_t *cc)
{
    int i;
    void *p;
    config_item_t *items;
    dns_list_elem_t *elem, *next;

    for (i = 0, items = cc->cc_items; items[i].item_plurality != 0; i++) {
        p = CONFIG_PTR(config, items[i].item_offset);
        if (items[i].item_next != NULL) {
            switch(items[i].item_plurality) {
            case SINGULAR:
                config_free(p, items[i].item_next);
                break;
            case PLURAL:
                elem = dns_list_head((dns_list_t *) p);
                for (; elem != NULL; elem = next) {
                    next = dns_list_next((dns_list_t *) p, elem);
                    config_free(elem, items[i].item_next);
                    free(elem);
                }
            } 
        }
    }

    if (cc->cc_destroy != NULL)
        cc->cc_destroy(config);
}

dns_config_zone_t *
dns_config_find_zone(char *name, int class)
{
    int len, buflen, match_len = 0;
    char buf[DNS_NAME_MAX];
    dns_config_root_t *root;
    dns_config_zone_t *zone, *candidate = NULL;

    if ((root = ConfigRoot) == NULL)
        return NULL;

    STRLCPY(buf, name, sizeof(buf));
    STRLOWER(buf);
    buflen = strlen(buf);

    zone = (dns_config_zone_t *) dns_list_head(&root->r_zone);
    while (zone != NULL) {
        if (zone->z_class == class || class == DNS_CLASS_ANY) {
            len = strlen(zone->z_name);
            if (buflen >= len && len > match_len) {
                if (strcmp(&buf[buflen - len], zone->z_name) == 0) {
                    candidate = zone;
                    match_len = len;
                }
            }
        }

        zone = (dns_config_zone_t *) dns_list_next(&root->r_zone, &zone->z_elem);
    }

    if (candidate == NULL)
        plog(LOG_DEBUG, "%s: no zone found", MODULE);
    else
        plog(LOG_DEBUG, "%s: found zone \"%s\"", MODULE, candidate->z_name);

    return candidate;
}

static int
config_parse(void *config, config_class_t *cc, config_context_t *context)
{
    void *p, *q;
    config_token_t tok;
    config_item_t *matched;

    for (;;) {
        if (config_get_token(&tok, context) < 0)
            return 0;

        if (tok.tok_code == CONFIG_TOKEN_BLOCK_CLOSE) {
            config_unget_token(&tok, context);
            return 0;
        }

        if (tok.tok_code != CONFIG_TOKEN_STRING)
            goto error;
        if ((matched = config_get_matched_item(cc->cc_items, tok.tok_string)) == NULL)
            goto error;

        if (matched->item_next != NULL) {
            p = CONFIG_PTR(config, matched->item_offset);
            if (matched->item_plurality == SINGULAR) {
                if (config_parse_section(p, matched->item_next, context) < 0) {
                    plog(LOG_DEBUG, "%s: config_parse_section() failed", MODULE);
                    return -1;
                }
            } else {
                if ((q = calloc(1, matched->item_next->cc_size)) == NULL) {
                    plog(LOG_ERR, "%s: insufficient memory", MODULE);
                    return -1;
                }

                if (cc->cc_init != NULL)
                    cc->cc_init(q);

                if (config_parse_section(q, matched->item_next, context) < 0) {
                    plog(LOG_DEBUG, "%s: config_parse_section() failed", MODULE);
                    free(q);
                    return -1;
                }

                dns_list_push((dns_list_t *) p, q);
            }
        } else {
            if (config_parse_param(config, matched, tok.tok_string, context) < 0)
                goto error;
            if (config_get_token2(&tok, CONFIG_TOKEN_SEMICOLON, context) < 0) {
                plog(LOG_DEBUG, "%s: config_get_token2() failed", MODULE);
                return -1;
            }
        }
    }

 error:
    config_error_unexpected(&tok, context);
    return -1;
}

static int
config_parse_section(void *config, config_class_t *cc, config_context_t *context)
{
    config_token_t tok;

    if (cc->cc_parse_skey != NULL) {
        if (cc->cc_parse_skey(config, context) < 0)
            return -1;
    }

    if (config_get_token2(&tok, CONFIG_TOKEN_BLOCK_OPEN, context) < 0)
        return -1;
    if (config_parse(config, cc, context) < 0)
        return -1;
    if (config_get_token2(&tok, CONFIG_TOKEN_BLOCK_CLOSE, context) < 0)
        return -1;

    if (config_get_token(&tok, context) == 0) {
        if (tok.tok_code != CONFIG_TOKEN_SEMICOLON)
            config_unget_token(&tok, context);
    }

    return 0;
}

static int
config_parse_param(void *config, config_item_t *item, char *tstring, config_context_t *context)
{
    void *p, *r;

    if (item->item_parser == NULL)
        return 0;

    p = CONFIG_PTR(config, item->item_offset);
    switch (item->item_plurality) {
    case SINGULAR:
        if (item->item_parser(p, tstring, context) == NULL)
            return -1;
        break;

    case PLURAL:
        if ((r = item->item_parser(NULL, tstring, context)) == NULL)
            return -1;
        dns_list_push((dns_list_t *) p, r);
        break;
    }

    return 0;
}

static config_item_t *
config_get_matched_item(config_item_t *items, char *string)
{
    for (; items->item_plurality != 0; items++) {
        if (items->item_name == NULL)
            return items;
        if (strcmp(items->item_name, string) == 0)
            return items;
    }

    return NULL;
}

static int
config_get_token(config_token_t *token, config_context_t *context)
{
    char buf[256];

    if (context->ctx_ungot.tok_code != 0) {
        memcpy(token, &context->ctx_ungot, sizeof(*token));
        context->ctx_ungot.tok_code = 0;
        return 0;
    }

    if (dns_file_get_token(buf, sizeof(buf), &context->ctx_handle) < 0)
        return -1;

//    plog(LOG_DEBUG, "%s: token \"%s\"", MODULE, buf);
    config_tokenize(token, buf);

    return 0;
}

static int
config_get_token2(config_token_t *token, int code, config_context_t *context)
{
    if (config_get_token(token, context) < 0) {
        config_error_eof(context);
        return -1;
    }

    if (token->tok_code != code) {
        config_error_unexpected(token, context);
        return -1;
    }

    return 0;
}

static void
config_unget_token(config_token_t *token, config_context_t *context)
{
    memcpy(&context->ctx_ungot, token, sizeof(*token));
}

static void
config_tokenize(config_token_t *token, char *string)
{
    token->tok_code = CONFIG_TOKEN_STRING;
    STRLCPY(token->tok_string, string, sizeof(token->tok_string));

    switch (string[0]) {
    case '{':  token->tok_code = CONFIG_TOKEN_BLOCK_OPEN;   break;
    case '}':  token->tok_code = CONFIG_TOKEN_BLOCK_CLOSE;  break;
    case '(':  token->tok_code = CONFIG_TOKEN_RB_OPEN;      break;
    case ')':  token->tok_code = CONFIG_TOKEN_RB_CLOSE;     break;
    case '[':  token->tok_code = CONFIG_TOKEN_SB_OPEN;      break;
    case ']':  token->tok_code = CONFIG_TOKEN_RB_CLOSE;     break;
    case ',':  token->tok_code = CONFIG_TOKEN_COMMA;        break;
    case ':':  token->tok_code = CONFIG_TOKEN_COLON;        break;
    case ';':  token->tok_code = CONFIG_TOKEN_SEMICOLON;    break;
    }
}

static void
config_error_unexpected(config_token_t *token, config_context_t *context)
{
    config_error("unexpected token", token, context);
}

static void
config_error_eof(config_context_t *context)
{
    config_error("unexpected EOF", NULL, context);
}

static void
config_error(char *msg, config_token_t *token, config_context_t *context)
{
    if (token == NULL) {
        plog(LOG_ERR, "%s: line %d: %s",
             MODULE, context->ctx_handle.fh_line, msg);
    } else {
        plog(LOG_ERR, "%s: line %d: '%s': %s",
             MODULE, context->ctx_handle.fh_line, token->tok_string, msg);
    }
}


static void *
config_parse_int(void *dest, char *tstring, config_context_t *context)
{
    config_token_t tok;

    if (dest == NULL)
        return NULL;

    if (config_get_token2(&tok, CONFIG_TOKEN_STRING, context) < 0)
        return NULL;

    *((int *) dest) = atoi(tok.tok_string);

    return dest;
}

static void *
config_parse_string(void *dest, char *tstring, config_context_t *context)
{
    config_token_t tok;

    if (dest == NULL)
        return NULL;

    if (config_get_token2(&tok, CONFIG_TOKEN_STRING, context) < 0)
        return NULL;
    if (strlen(tok.tok_string) >= CONFIG_STRING_MAX) {
        config_error("string too long", &tok, context);
        return NULL;
    }

    strcpy(dest, tok.tok_string);

    return dest;
}

static void *
config_parse_zone_engine(void *dest, char *tstring, config_context_t *context)
{
    void *econf;
    config_token_t tok;
    dns_engine_t *engine;
    dns_config_zone_engine_t *ze;

    if (dest != NULL)
        return NULL;

    if ((engine = dns_engine_find(tstring)) == NULL) {
        config_error("unknown query engine name", NULL, context);
        return NULL;
    }

    if (config_get_token(&tok, context) < 0) {
        config_error_eof(context);
        return NULL;
    }

    if ((ze = calloc(1, sizeof(dns_config_zone_engine_t))) == NULL) {
        plog(LOG_ERR, "%s: insufficient memory", MODULE);
        return NULL;
    }

    if ((econf = calloc(1, engine->eng_conflen)) == NULL) {
        plog(LOG_ERR, "%s: insufficient memory", MODULE);
        free(ze);
        return NULL;
    }

    if (tok.tok_code != CONFIG_TOKEN_STRING)
        config_unget_token(&tok, context);
    else {
        if (engine->eng_setarg != NULL) {
            if (engine->eng_setarg(econf, tok.tok_string) < 0) {
                config_error("invalid parameter", &tok, context);
                goto error;
            }
        }
    }

    if (engine->eng_init != NULL) {
        if (engine->eng_init(econf) < 0) {
            config_error("query engine initialization failed", NULL, context);
            goto error;
        }
    }

    ze->ze_engine = engine;
    ze->ze_econf = econf;

    return ze;

 error:
    free(econf);
    free(ze);

    return NULL;
}

static void
config_zone_search_destroy(dns_config_zone_search_t *zs)
{
    void *p, *next;
    dns_engine_t *engine;
    dns_config_zone_engine_t *ze;

    p = dns_list_head(&zs->zs_engine);
    while (p != NULL) {
        ze = (dns_config_zone_engine_t *) p;
        next = dns_list_next(&zs->zs_engine, p);
        engine = (dns_engine_t *) ze->ze_engine;
        if (engine->eng_destroy != NULL)
            engine->eng_destroy(ze->ze_econf);

        free(ze->ze_econf);
        free(ze);
        p = next;
    }
}

static int
config_zone_parse_skey(dns_config_zone_t *zone, config_context_t *context)
{
    config_token_t tok;

    if (config_get_token2(&tok, CONFIG_TOKEN_STRING, context) < 0)
        return -1;

    STRLCPY(zone->z_name, tok.tok_string, sizeof(zone->z_name));

    /* specical: '.' means root domain */
    if (zone->z_name[0] == '.' && zone->z_name[1] == 0)
        zone->z_name[0] = 0;

    if (config_get_token(&tok, context) < 0) {
        config_error_eof(context);
        return -1;
    }

    if (tok.tok_code != CONFIG_TOKEN_STRING) {
        zone->z_class = DNS_CLASS_IN;
        config_unget_token(&tok, context);
    } else {
        if ((zone->z_class = dns_proto_parse_class(tok.tok_string)) < 0) {
            config_error("invalid class", &tok, context);
            return -1;
        }
    }

    plog(LOG_DEBUG, "%s: zone \"%s\"", MODULE, zone->z_name);

    return 0;
}
