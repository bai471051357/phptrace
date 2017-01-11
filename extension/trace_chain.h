
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
#include "php.h"
#include <sys/types.h>

#define PT_MAX_IP_LEN              64
#define PT_MAX_KEY_LEN             256
#define PT_MAX_VAL_LEN             256 
#define PT_DEFAULT_ID              "0"

#define INIT_HEADER_ID(key)     do {                                                \
    pt_chain_key_t *key;                                                            \
    if (zend_hash_find(pch->chain_uri_key, #key, sizeof(#key),                      \
            (void **)&key) == SUCCESS) {                                            \
        char *key_##result = pt_sub_query_key(query_string, trace_id->receive_key);  \
        if (key_##result != NULL) {                                                   \
            key->val = key_##result;                                                \
        } else {                                                                    \
            strncpy(key->val, PT_DEFAULT_ID, strlen(PT_DEFAULT_ID));                      \
        }                                                                           \
    }                                                                               \
} while(0)

#define ADD_HASH_CHAIN_KEY(ht, pck) zend_hash_add(ht, pck->name, (strlen(pck->name) + 1), \
        (void *)&pck, sizeof(pt_chain_key_t *), NULL)



/* key val map */
typedef struct {
    char *name;
    char *receive_key;
    char *pass_key;
    char *val;
    zend_bool is_pass;
}pt_chain_key_t;

/* chain header */
typedef struct {
    pt_chain_key_t *trace_id;    
    pt_chain_key_t *span_id;
    pt_chain_key_t *parent_span_id;
    HashTable *chain_uri_key;           /* chain uri key*/

    char ip[PT_MAX_IP_LEN];             /* device ip */
} pt_chain_header_t;

typedef struct {
    pt_chain_header_t pch;

    /* excute time */
    long execute_begin_time;
    long execute_end_time;

    /* http request detail */
    const char *sapi;
    const char *method;
    const char *script;
    const char *request_uri;
    const char *query_string;
    zend_bool is_cli;

    /* console paramter */
    int argc; 
    const char *argv;
    
} pt_chain_t;

void pt_chain_ctor(pt_chain_t *pct);
void pt_chain_dtor(pt_chain_t *pct);
           
#endif

