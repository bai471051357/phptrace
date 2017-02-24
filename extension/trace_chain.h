/**
 * Copyright 2017 Bing Bai <silkcutbeta@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TRACE_CHAIN_H
#define TRACE_CHAIN_H

#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "php7_wrapper.h"
#include "php.h"
#include "trace_log.h"
#include "trace_intercept.h"

#define PT_MAX_KEY_LEN             256
#define PT_MAX_VAL_LEN             256 
#define PT_DEFAULT_ID              "0"

#define zend_true                   1
#define zend_flase                  0

#define ADD_HASH_CHAIN_KEY(ht, pck) pt_zend_hash_update(ht, pck->name, (strlen(pck->name) + 1), \
        (void *)&pck, sizeof(pt_chain_key_t *), NULL)

/* key val map */
typedef struct {
    char *name;
    char *receive_key;
    int receive_key_len;
    char *pass_key;
    char *val;
    zend_bool is_pass;
} pt_chain_key_t;

/* chain header */
typedef struct {
    pt_chain_key_t *trace_id;           /* trace id */
    pt_chain_key_t *span_id;            /* span id */
    pt_chain_key_t *parent_span_id;     /* parent sapn id */
    pt_chain_key_t *sampled;            /* sampled */
    pt_chain_key_t *flags;              /* flags */
    HashTable *chain_header_key;        /* chain uri key*/
    zend_bool is_load_header;           /* load_header */
    zend_bool is_sampled;

    char ip[INET_ADDRSTRLEN];           /* device ip */
    int port;
} pt_chain_header_t;

/* chain struct */
typedef struct pt_chain_st {

    pt_chain_header_t pch;              /* chain header */

    /* service name */
    char *service_name;

    /* excute time */
    long execute_begin_time;            /* execute begin time */
    long execute_end_time;              /* execute end time */

    /* http request detail */
    const char *sapi;
    const char *method;
    const char *content_type;
    char *script;
    const char *request_uri;
    const char *query_string;
    zend_bool is_cli;

    /* console paramter */
    int argc; 
    const char **argv;

    /* trace log */
    pt_chain_log_t *pcl; 

    /* trace interceptor */
    pt_interceptor_t pit;
    
} pt_chain_t;

void pt_chain_ctor(pt_chain_t *pct, pt_chain_log_t *pcl, char *service_name);
void pt_chain_dtor(pt_chain_t *pct);
char *pt_rebuild_url(pt_chain_t *pct, char *ori_url);
void build_http_header(pt_chain_t *pct, zval *header, char *span_id);
void pt_build_chain_header(pt_chain_t *pct);
#endif
