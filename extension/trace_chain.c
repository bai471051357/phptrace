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

#include <stdio.h>
#include <php.h>
#include <SAPI.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "trace_chain.h"
#include "php_trace.h"

/* only destory val key */
static void pt_key_destory_func(void *pDest)
{
    pt_chain_key_t *data = (pt_chain_key_t *)pDest;
    free(data->val);
    free(data);
}

/* obtain zval from PG */
static zval *pt_find_server_value(const char *key)
{
    zval **ret; 
    zval *server_global = PG(http_globals)[TRACK_VARS_SERVER];

    php_printf("the server global is %p, the php globals is %p \n", server_global, core_globals.http_globals);
    if (server_global == NULL){
        return NULL;
    }

    if (zend_find_hash(Z_ARRVAL_P(server_global), key, strlen(key)+1, (void**)&ret) == FAILURE) {
        php_printf("the server get server value failure\n");
        return NULL;
    }

    return *ret;
}

/* generate trace id */
static void pt_gen_trace_id(pt_chain_header_t *pch,  pt_chain_key_t *pck, const char *query_string)
{
    pck->val = (char *)malloc(strlen(query_string));
    snprinf(pck->val, PT_MAX_VAL_LEN,"%s-vjsdsds-sadsaa-cwf-de", pch->ip);
}

/* sub query key */
static char *pt_sub_query_key(const char *query_string, char *key)
{
    if (query_string == NULL) {
        return NULL; 
    }

    char *tmp;
    char *p = strstr(query_string, key);
    if (p == NULL) {
        return NULL;
    }

    int len = strlen(key);
    char *val = (char *)malloc(len + 1);
    strncpy(val, p, len);
    val[len] = '\0';

    return val;
}


/* obtain local internal ip */
static void pt_obtain_local_ip(pt_chain_header_t *pch)
{
    struct ifaddrs *myaddrs, *ifa;
    struct sockaddr_in *ipv4;
    char buf[PT_MAX_IP_LEN];
    int status;
    
    memset(pch->ip, 0x00, PT_MAX_IP_LEN);
    strncpy(pch->ip, "127.0.0.1", PT_MAX_IP_LEN);

    status = getifaddrs(&myaddrs); 
    if (status != 0) {
        //todo log 
        return;
    }

    for (ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next) {
        if (NULL == ifa->ifa_addr) {
            continue;
        }

        if ((ifa->ifa_flags & IFF_UP) == 0) {
            continue;
        }

        /* only support ipv4*/
        if (AF_INET == ifa->ifa_addr->sa_family) {
            ipv4 = (struct sockaddr_in *)(ifa->ifa_addr);
            if (inet_ntop(ifa->ifa_addr->sa_family, (void *)&(ipv4), buf, PT_MAX_IP_LEN) != NULL) {

                /* only support  internal network */
                if ((strncasecmp(buf, "10", 2) == 0) ||
                    (strncasecmp(buf, "192", 3) == 0)) {
                    strncpy(pch->ip, buf, PT_MAX_IP_LEN);
                    return;
                }
            }
        }
    }
}

/* build chain header */
void pt_build_chain_header(pt_chain_header_t *pch, const char *query_string)
{
    if (!query_string) {
        return;
    }
    
    pt_obtain_local_ip(pch);
    
    pt_chain_key_t *trace_id = pch->trace_id;
    char *result = pt_sub_query_key(query_string, trace_id->receive_key);
    if (result == NULL) {
        pt_gen_trace_id(pch, trace_id, query_string);
    }  else {
        trace_id->val = result;
    }

    INIT_HEADER_ID(parent_span_id);
}

/* init chain header */
void pt_init_chain_header(pt_chain_header_t *pch)
{
    ALLOC_HASHTABLE(pch->chain_uri_key);

    zend_hash_init(pch->chain_uri_key, 8, NULL,  pt_key_destory_func, 0);
   
    /* chain header */
    pt_chain_key_t *trace_id = malloc(sizeof(pt_chain_key_t));
    trace_id->name = "trace_id";
    trace_id->receive_key = "_trace_id";
    trace_id->pass_key = "_trace_id";
    trace_id->is_pass = 1;
    trace_id->val = NULL;
    pch->trace_id = trace_id;

    pt_chain_key_t *span_id = malloc(sizeof(pt_chain_key_t));
    span_id->name = "span_id";
    span_id->receive_key = "none";
    span_id->pass_key = "_span_id";
    span_id->is_pass = 1;
    span_id->val = NULL;
    pch->span_id = span_id;

    pt_chain_key_t *parent_span_id = malloc(sizeof(pt_chain_key_t));
    parent_span_id->name = "parent_span_id";
    parent_span_id->receive_key = "_span_id";
    parent_span_id->pass_key = "none";
    parent_span_id->is_pass = 0;
    parent_span_id->val = NULL;
    pch->parent_span_id = parent_span_id;

    /* add chain key to hash */
    ADD_HASH_CHAIN_KEY(pch->chain_uri_key, trace_id);
    ADD_HASH_CHAIN_KEY(pch->chain_uri_key, span_id);
    ADD_HASH_CHAIN_KEY(pch->chain_uri_key, parent_span_id);
}

/* pt chain header dtor */
void pt_chain_header_dtor(pt_chain_header_t *pch)
{
   zend_hash_destroy(pch->chain_uri_key);
}

/* pt chain ctor */
void pt_chain_ctor(pt_chain_t *pct)
{
    /* execute time */
    pct->execute_begin_time = (long) SG(global_request_time) * 1000000.00;
    pct->execute_end_time = 0;
    
    /* http request */
    pct->sapi = sapi_module.name;
    pct->method = (char *) SG(request_info).request_method;
    pct->script = SG(request_info).path_translated;
    pct->request_uri = SG(request_info).request_uri;
    pct->query_string = SG(request_info).query_string;
    
    /* almost user use fpm or cli, just judge them */
    if (strncasecmp(pct->sapi, "cli", 3) == 0) {
        pct->is_cli = 1;
    } else {
        pct->is_cli = 0;
    }

    /* cli */
    pct->argc = SG(request_info).argc;
    pct->argv = (const char *)SG(request_info).argv;


    pt_init_chain_header(&(pct->pch));
    pt_build_chain_header(&(pct->pch), pct->query_string);
}

/* pt chain dtor */
void pt_chain_dtor(pt_chain_t *pct)
{
    /* execute end time */
    struct timeval tp = {0};
    if (!gettimeofday(&tp, NULL)) {
        pct->execute_end_time = (long)(tp.tv_sec + tp.tv_usec);
    } else {
        pct->execute_end_time = (long)time(0);
    }



    pt_chain_header_dtor(&(pct->pch));
}







