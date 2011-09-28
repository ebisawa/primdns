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

typedef int (config_parse_head_t)(void *config, config_context_t *ctx);
typedef int (config_parse_body_t)(void *config, config_context_t *ctx, config_token_t *tok);

static dns_config_root_t *config_read(char *filename);
static void config_wait_update(void);
static void config_free(dns_config_root_t *root);
static void config_free_zone(dns_config_zone_t *zone);
static void config_free_zone_search(dns_config_zone_search_t *zs);
static void config_free_zone_slaves(dns_config_zone_slaves_t *zss);
static void config_free_zone_engine(dns_config_zone_engine_t *ze);
static int config_parse_root(dns_config_root_t *root, config_context_t *ctx);
static int config_parse_zone_head(dns_config_zone_t *zone, config_context_t *ctx);
static int config_parse_zone_body(dns_config_zone_t *zone, config_context_t *ctx, config_token_t *tok);
static int config_parse_zone_search_body(dns_config_zone_search_t *search, config_context_t *ctx, config_token_t *tok);
static int config_parse_zone_slaves_body(dns_config_zone_slaves_t *slaves, config_context_t *ctx, config_token_t *tok);
static int config_parse_zone_search_engine_param(dns_config_zone_search_t *search, config_context_t *ctx, dns_engine_t *engine, void *econf);
static int config_parse_clause(void *config, config_context_t *ctx, config_parse_head_t *parse_head, config_parse_body_t *parse_body);
static int config_parse_clause_body(void *config, config_context_t *ctx, config_parse_body_t *parse_body);
static int config_get_token(config_token_t *token, config_context_t *ctx);
static int config_get_token2(config_token_t *token, int code, config_context_t *ctx);
static void config_unget_token(config_token_t *token, config_context_t *ctx);
static void config_tokenize(config_token_t *token, char *string);
static void config_error_unexpected(config_token_t *token, config_context_t *ctx);
static void config_error_eof(config_context_t *ctx);
static void config_error(char *msg, config_token_t *token, config_context_t *ctx);

dns_config_root_t *ConfigRoot;

int
dns_config_update(char *filename)
{
    dns_config_root_t *old_root = ConfigRoot;

    if (filename == NULL || filename[0] == 0) {
        plog(LOG_ERR, "%s: no config found", MODULE);
        return -1;
    }

    plog(LOG_DEBUG, "%s: config = %s", MODULE, filename);

    if ((ConfigRoot = config_read(filename)) == NULL) {
        plog(LOG_ERR, "%s: config read failed", MODULE);
        return (old_root == NULL) ? -1 : 0;
    }

    if (old_root != NULL) {
        config_wait_update();
        config_free(old_root);
    }

    return 0;
}

dns_config_zone_t *
dns_config_find_zone(char *name, int class)
{
    int len, buflen, match_len = -1;
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
                if (buflen == len || buf[buflen - len - 1] == '.' || len == 0) {
                    if (strcmp(&buf[buflen - len], zone->z_name) == 0) {
                        candidate = zone;
                        match_len = len;
                    }
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

static dns_config_root_t *
config_read(char *filename)
{
    config_context_t ctx;
    dns_config_root_t *root;

    memset(&ctx, 0, sizeof(ctx));
    if ((root = calloc(1, sizeof(dns_config_root_t))) == NULL)
        return NULL;

    if (dns_file_open(&ctx.ctx_handle, filename) < 0) {
        plog(LOG_DEBUG, "%s: dns_file_open() failed", MODULE);
        free(root);
        return NULL;
    }

    if (config_parse_root(root, &ctx) < 0) {
        plog(LOG_DEBUG, "%s: config parse failed", MODULE);
        dns_file_close(&ctx.ctx_handle);
        config_free(root);
        return NULL;
    }

    dns_file_close(&ctx.ctx_handle);

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
config_free(dns_config_root_t *root)
{
    dns_config_zone_t *zone, *next;

    zone = (dns_config_zone_t *) dns_list_head(&root->r_zone);
    for (; zone != NULL; zone = next) {
        next = (dns_config_zone_t *) dns_list_next(&root->r_zone, &zone->z_elem);
        config_free_zone(zone);
    }

    free(root);
}

static void
config_free_zone(dns_config_zone_t *zone)
{
    config_free_zone_search(&zone->z_search);
    config_free_zone_slaves(&zone->z_slaves);
    free(zone);
}

static void
config_free_zone_search(dns_config_zone_search_t *zs)
{
    dns_config_zone_engine_t *ze, *next;

    ze = (dns_config_zone_engine_t *) dns_list_head(&zs->zs_engine);
    for (; ze != NULL; ze = next) {
        next = (dns_config_zone_engine_t *) dns_list_next(&zs->zs_engine, &ze->ze_elem);
        config_free_zone_engine(ze);
    }
}

static void
config_free_zone_slaves(dns_config_zone_slaves_t *zss)
{
    dns_acl_free(&zss->zss_acl);
}

static void
config_free_zone_engine(dns_config_zone_engine_t *ze)
{
    dns_engine_t *engine;

    engine = (dns_engine_t *) ze->ze_engine;
    dns_engine_destroy(engine, ze->ze_econf);

    free(ze->ze_econf);
    free(ze);
}

static int
config_parse_root(dns_config_root_t *root, config_context_t *ctx)
{
    config_token_t tok;
    dns_config_zone_t *zone;

    for (;;) {
        if (config_get_token(&tok, ctx) < 0)
            return 0;

        if (tok.tok_code != CONFIG_TOKEN_STRING)
            return -1;

        if (strcmp(tok.tok_string, "zone") == 0) {
            if ((zone = calloc(1, sizeof(dns_config_zone_t))) == NULL) {
                plog(LOG_ERR, "%s: insufficient memory", MODULE);
                return -1;
            }

            if (dns_acl_init(&zone->z_slaves.zss_acl) < 0) {
                plog(LOG_ERR, "%s: dns_acl_init() failed", MODULE);
                config_free_zone(zone);
                return -1;
            }

            if (config_parse_clause(zone, ctx,
                                    (config_parse_head_t *) config_parse_zone_head,
                                    (config_parse_body_t *) config_parse_zone_body) < 0) {
                config_free_zone(zone);
                return -1;
            }

            dns_list_push(&root->r_zone, &zone->z_elem);
            continue;
        }

        config_error_unexpected(&tok, ctx);
        return -1;
    }
}

static int
config_parse_zone_head(dns_config_zone_t *zone, config_context_t *ctx)
{
    config_token_t tok;

    /* zone name */
    if (config_get_token2(&tok, CONFIG_TOKEN_STRING, ctx) < 0)
        return -1;

    STRLCPY(zone->z_name, tok.tok_string, sizeof(zone->z_name));

    /* specical: '.' means root domain */
    if (zone->z_name[0] == '.' && zone->z_name[1] == 0)
        zone->z_name[0] = 0;

    if (config_get_token(&tok, ctx) < 0) {
        config_error_eof(ctx);
        return -1;
    }

    /* class */
    if (tok.tok_code != CONFIG_TOKEN_STRING) {
        zone->z_class = DNS_CLASS_IN;
        config_unget_token(&tok, ctx);
    } else {
        if ((zone->z_class = dns_proto_parse_class(tok.tok_string)) < 0) {
            config_error("invalid class", &tok, ctx);
            return -1;
        }
    }

    plog(LOG_DEBUG, "%s: zone \"%s\"", MODULE, zone->z_name);
    return 0;
}

static int
config_parse_zone_body(dns_config_zone_t *zone, config_context_t *ctx, config_token_t *tok)
{
    if (strcmp(tok->tok_string, "search") == 0)
        return config_parse_clause(&zone->z_search, ctx, NULL, (config_parse_body_t *) config_parse_zone_search_body);
    if (strcmp(tok->tok_string, "slaves") == 0)
        return config_parse_clause(&zone->z_slaves, ctx, NULL, (config_parse_body_t *) config_parse_zone_slaves_body);

    config_error_unexpected(tok, ctx);
    return -1;
}

static int
config_parse_zone_search_body(dns_config_zone_search_t *search, config_context_t *ctx, config_token_t *tok)
{
    void *econf;
    dns_engine_t *engine;
    dns_config_zone_engine_t *ze;

    if ((engine = dns_engine_find(tok->tok_string)) == NULL) {
        config_error("unknown query engine name", NULL, ctx);
        return -1;
    }

    if ((ze = calloc(1, sizeof(dns_config_zone_engine_t))) == NULL) {
        plog(LOG_ERR, "%s: insufficient memory", MODULE);
        return -1;
    }

    if ((econf = calloc(1, engine->eng_conflen)) == NULL) {
        plog(LOG_ERR, "%s: insufficient memory", MODULE);
        free(ze);
        return -1;
    }

    if (config_parse_zone_search_engine_param(search, ctx, engine, econf) < 0) {
        free(econf);
        free(ze);
        return -1;
    }

    if (config_get_token2(tok, CONFIG_TOKEN_SEMICOLON, ctx) < 0)
        return -1;

    if (dns_engine_init(engine, econf) < 0) {
        config_error("query engine initialization failed", NULL, ctx);
        free(econf);
        free(ze);
        return -1;
    }

    ze->ze_engine = engine;
    ze->ze_econf = econf;
    dns_list_push(&search->zs_engine, &ze->ze_elem);

    return 0;
}

static int
config_parse_zone_slaves_body(dns_config_zone_slaves_t *slaves, config_context_t *ctx, config_token_t *tok)
{
    struct sockaddr_storage ss;

    if (dns_util_str2sa((SA *) &ss, tok->tok_string, 0) < 0) {
        plog(LOG_ERR, "%s: invalid address string", MODULE);
        return -1;
    }

    if (config_get_token2(tok, CONFIG_TOKEN_SEMICOLON, ctx) < 0)
        return -1;

    if (dns_acl_add(&slaves->zss_acl, (SA *) &ss) < 0) {
        plog(LOG_ERR, "%s: dns_acl_add() failed", MODULE);
        return -1;
    }

    return 0;
}

static int
config_parse_zone_search_engine_param(dns_config_zone_search_t *search, config_context_t *ctx, dns_engine_t *engine, void *econf)
{
    config_token_t tok;

    if (config_get_token(&tok, ctx) < 0) {
        config_error_eof(ctx);
        return -1;
    }

    if (tok.tok_code != CONFIG_TOKEN_STRING) {
        config_unget_token(&tok, ctx);
        return 0;
    }

    if (dns_engine_setarg(engine, econf, tok.tok_string) < 0) {
        config_error("invalid parameter", &tok, ctx);
        return -1;
    }

    return 0;
}

static int
config_parse_clause(void *config, config_context_t *ctx, config_parse_head_t *parse_head, config_parse_body_t *parse_body)
{
    config_token_t tok;

    if (parse_head != NULL && parse_head(config, ctx) < 0)
        return -1;
    if (config_get_token2(&tok, CONFIG_TOKEN_BLOCK_OPEN, ctx) < 0)
        return -1;
    if (parse_body != NULL && config_parse_clause_body(config, ctx, parse_body) < 0)
        return -1;
    if (config_get_token2(&tok, CONFIG_TOKEN_BLOCK_CLOSE, ctx) < 0)
        return -1;

    if (config_get_token(&tok, ctx) == 0) {
        if (tok.tok_code != CONFIG_TOKEN_SEMICOLON)
            config_unget_token(&tok, ctx);
    }

    return 0;
}

static int
config_parse_clause_body(void *config, config_context_t *ctx, config_parse_body_t *parse_body)
{
    config_token_t tok;

    for (;;) {
        if (config_get_token(&tok, ctx) < 0)
            return 0;

        if (tok.tok_code == CONFIG_TOKEN_BLOCK_CLOSE) {
            config_unget_token(&tok, ctx);
            return 0;
        }

        if (tok.tok_code != CONFIG_TOKEN_STRING) {
            config_error_unexpected(&tok, ctx);
            return -1;
        }

        if (parse_body(config, ctx, &tok) < 0)
            return -1;
    }
}

static int
config_get_token(config_token_t *token, config_context_t *ctx)
{
    char buf[256];

    if (ctx->ctx_ungot.tok_code != 0) {
        memcpy(token, &ctx->ctx_ungot, sizeof(*token));
        ctx->ctx_ungot.tok_code = 0;
        return 0;
    }

    if (dns_file_get_token(buf, sizeof(buf), &ctx->ctx_handle) < 0)
        return -1;

//    plog(LOG_DEBUG, "%s: token \"%s\"", MODULE, buf);
    config_tokenize(token, buf);

    return 0;
}

static int
config_get_token2(config_token_t *token, int code, config_context_t *ctx)
{
    if (config_get_token(token, ctx) < 0) {
        config_error_eof(ctx);
        return -1;
    }

    if (token->tok_code != code) {
        config_error_unexpected(token, ctx);
        return -1;
    }

    return 0;
}

static void
config_unget_token(config_token_t *token, config_context_t *ctx)
{
    memcpy(&ctx->ctx_ungot, token, sizeof(*token));
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
config_error_unexpected(config_token_t *token, config_context_t *ctx)
{
    config_error("unexpected token", token, ctx);
}

static void
config_error_eof(config_context_t *ctx)
{
    config_error("unexpected EOF", NULL, ctx);
}

static void
config_error(char *msg, config_token_t *token, config_context_t *ctx)
{
    if (token == NULL) {
        plog(LOG_ERR, "%s: line %d: %s",
             MODULE, ctx->ctx_handle.fh_line, msg);
    } else {
        plog(LOG_ERR, "%s: line %d: '%s': %s",
             MODULE, ctx->ctx_handle.fh_line, token->tok_string, msg);
    }
}
