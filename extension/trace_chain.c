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
#include <string.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "trace_chain.h"
#include "trace_util.h"

/* only destory val key */
static void pt_key_destory_func(void *pDest)
{
    pt_chain_key_t **data = (pt_chain_key_t **)pDest;
    (*data)->val ? efree((*data)->val) : NULL;
    free(*data);
}

/* sub query key */
static char *pt_sub_query_key(const char *query_string, char *key)
{
    if (query_string == NULL) {
        return NULL; 
    }

    char *p = strstr(query_string, key);
    if (p == NULL) {
        return NULL;
    }

    p = p + strlen(key);
    
    if (*p == '=') {
        p++;
    } else {
        return NULL;
    }
    char *start = p;
    
    while(*p != '\0' && *p != '&') p++;
    
    int len = p - start;
    char *val = (char *)malloc(len + 1);
    strncpy(val, start, len);
    val[len] = '\0';

    return val;
}

/* add query string key */
static void pt_add_query_key(char **url, char *key, char *value)
{
    if (url == NULL || *url == NULL) {
        return ;
    }
   
    char *p = strchr(*url, '?');
    int url_len = strlen(*url);
    if (p == NULL) {
        *url = erealloc(*url, url_len + strlen(key) + strlen(value) + 8);
        sprintf(*url + url_len, "?%s=%s", key, value);
    } else {
        if (strstr(*url, key) == NULL) {
            *url = erealloc(*url, url_len + strlen(key) + strlen(value) + 8);
            sprintf(*url + url_len, "&%s=%s", key, value);
        }
    }
}

/* obtain local internal ip */
static void pt_obtain_local_ip(pt_chain_header_t *pch)
{
    struct ifaddrs *myaddrs, *ifa;
    struct sockaddr_in *ipv4;
    char buf[INET_ADDRSTRLEN];
    int status;
    
    memset(pch->ip, 0x00, INET_ADDRSTRLEN);
    strncpy(pch->ip, "127.0.0.1", INET_ADDRSTRLEN);

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
            if (inet_ntop(AF_INET, &ipv4->sin_addr, buf, INET_ADDRSTRLEN) != NULL) {

                /* only support  internal network */
                if ((strncasecmp(buf, "10", 2) == 0) ||
                    (strncasecmp(buf, "192", 3) == 0)) {
                    strncpy(pch->ip, buf, INET_ADDRSTRLEN);
                    return;
                }
            }
        }
    }
}

/* retrive header data */
static void retrive_header_data(void *data, void *arg)
{
    sapi_header_struct *ele = (sapi_header_struct *)(data);
    pt_chain_header_t *pch = (pt_chain_header_t *)arg;
    if (!strncmp(ele->header, CHAIN_HEADER_PREFIX, CHAIN_HEADER_PREFIX_LEN)) {
        pt_chain_key_t **pck;
        char *pos = strchr(ele->header, ':');
        int header_len = ele->header_len;
        char *header = ele->header;
        int position = pos - header;
        char *hkey = estrndup(header, position);
        if (hkey == NULL) {
            return;
        }
        hkey[position] = '\0';
        if (pt_zend_hash_find(pch->chain_header_key, hkey, position, (void **)&pck) == SUCCESS) {
            header += position;
            (*pck)->val = estrndup(header, header_len-position);  
        }
        efree(hkey);
    }
}

/* build chain header */
void pt_build_chain_header(pt_chain_t *pct)
{
    char *result;
    pt_chain_header_t *pch = &(pct->pch);
    
    /* local ip */ 
    pt_obtain_local_ip(pch);

    /* retrive key from header */
    if (pct->is_cli != 1) {
        zend_llist *l = &SG(sapi_headers).headers;
        zend_llist_apply_with_argument(l, retrive_header_data, pch);
    }
    
    if (!pch->trace_id->val) {
       rand64hex(&pch->trace_id->val);
    }

    if (!pch->span_id->val) {
        if (!pch->parent_span_id->val) {
            pch->span_id->val = estrdup(pch->trace_id->val);
        } else {
            rand64hex(&pch->span_id->val);
        }
    }

    /* todo control sampled */
    if (!pch->sampled->val) {
        pch->sampled->val = estrdup("true");
    }

    if (!pch->flags->val) {
        pch->flags->val = estrdup("0");
    }

    /* trace id */ 
    /*
    pt_chain_key_t *trace_id = pch->trace_id;
    result = pt_sub_query_key(query_string, trace_id->receive_key);
    if (result == NULL) {
        pt_gen_trace_id(pch, trace_id, query_string);
    }  else {
        trace_id->val = result;
    }
    */

    /* parent span id */
    /*
    result = pt_sub_query_key(query_string, pch->parent_span_id->receive_key);
    if (result == NULL) { 
        pch->parent_span_id->val = (char *)malloc(sizeof(PT_DEFAULT_ID));
        memset(pch->parent_span_id->val, 0, sizeof(PT_DEFAULT_ID));
        strncpy(pch->parent_span_id->val, PT_DEFAULT_ID, strlen(PT_DEFAULT_ID)); 
    } else {
        pch->parent_span_id->val = result;
    }
    */

    /* span id */
    /*
        pch->span_id->val = (char *)malloc(sizeof(PT_DEFAULT_ID));
        memset(pch->span_id->val, 0, sizeof(PT_DEFAULT_ID));
    strncpy(pch->span_id->val, PT_DEFAULT_ID, strlen(PT_DEFAULT_ID)); 
    */
}

/* init chain header */
void pt_init_chain_header(pt_chain_header_t *pch)
{
    ALLOC_HASHTABLE(pch->chain_header_key);

    zend_hash_init(pch->chain_header_key, 8, NULL,  pt_key_destory_func, 0);
   
    /* chain header */
    /* trace id */
    pt_chain_key_t *trace_id = (pt_chain_key_t *)emalloc(sizeof(pt_chain_key_t));
    trace_id->name = "trace_id";
    trace_id->receive_key = CHAIN_HEADER_TRACE_ID;
    trace_id->receive_key_len = sizeof(CHAIN_HEADER_TRACE_ID) - 1;
    trace_id->pass_key = CHAIN_HEADER_TRACE_ID;
    trace_id->is_pass = 1;
    trace_id->val = NULL;
    pch->trace_id = trace_id;

    /* span id */
    pt_chain_key_t *span_id = (pt_chain_key_t *)emalloc(sizeof(pt_chain_key_t));
    span_id->name = "span_id";
    span_id->receive_key = "none";
    span_id->receive_key_len = 0;
    span_id->pass_key = CHAIN_HEADER_SPAN_ID;
    span_id->is_pass = 1;
    span_id->val = NULL;
    pch->span_id = span_id;

    /* parent_span_id */
    pt_chain_key_t *parent_span_id = (pt_chain_key_t *)emalloc(sizeof(pt_chain_key_t));
    parent_span_id->name = "parent_span_id";
    parent_span_id->receive_key = CHAIN_HEADER_PARENT_SPAN_ID;
    parent_span_id->receive_key_len = sizeof(CHAIN_HEADER_PARENT_SPAN_ID) - 1;
    parent_span_id->pass_key = "";
    parent_span_id->is_pass = 0;
    parent_span_id->val = NULL;
    pch->parent_span_id = parent_span_id;

    /* sampled */
    pt_chain_key_t *sampled = (pt_chain_key_t *)emalloc(sizeof(pt_chain_key_t));
    sampled->name = "sampled";
    sampled->receive_key = CHAIN_HEADER_SAMPLED;
    sampled->receive_key_len = sizeof(CHAIN_HEADER_SAMPLED) - 1;
    sampled->pass_key = CHAIN_HEADER_SAMPLED;
    sampled->is_pass = 1;
    sampled->val = NULL;
    pch->sampled = sampled;

    /* flags */
    pt_chain_key_t *flags = (pt_chain_key_t *)emalloc(sizeof(pt_chain_key_t));
    flags->name = "flags";
    flags->receive_key = CHAIN_HEADER_FLAGS;
    flags->receive_key_len = sizeof(CHAIN_HEADER_FLAGS) - 1;
    flags->pass_key = CHAIN_HEADER_FLAGS;
    flags->is_pass = 1;
    flags->val = NULL;
    pch->flags = flags;

    /* add chain key to hash */
    ADD_HASH_CHAIN_KEY(pch->chain_header_key, trace_id);
    ADD_HASH_CHAIN_KEY(pch->chain_header_key, span_id);
    ADD_HASH_CHAIN_KEY(pch->chain_header_key, parent_span_id);
    ADD_HASH_CHAIN_KEY(pch->chain_header_key, sampled);
    ADD_HASH_CHAIN_KEY(pch->chain_header_key, flags);
}

/* pt chain header dtor */
void pt_chain_header_dtor(pt_chain_header_t *pch)
{
    zend_hash_destroy(pch->chain_header_key);
    FREE_HASHTABLE(pch->chain_header_key);
}

/* pt chain ctor */
void pt_chain_ctor(pt_chain_t *pct, pt_chain_log_t *pcl)
{
    pct->pcl = pcl;
    pt_intercept_ctor(&(pct->pit), pct);    

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
    pct->argv = (const char **)SG(request_info).argv;

    /* build chain header */
    pt_init_chain_header(&(pct->pch));
    pt_build_chain_header(pct);
}

/* chain rebuild url attach trace id and so on */
char *pt_rebuild_url(pt_chain_t *pct, char *ori_url)
{
    char *tmp_url = estrdup(ori_url);     
    pt_add_query_key(&tmp_url, pct->pch.trace_id->pass_key, pct->pch.trace_id->val);
    pt_add_query_key(&tmp_url, pct->pch.span_id->pass_key, pct->pch.span_id->val);
    return tmp_url;
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
    
    /* header dtor */
    pt_chain_header_dtor(&(pct->pch));

    pt_intercept_dtor(&(pct->pit));
}
