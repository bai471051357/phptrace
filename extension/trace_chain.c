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
#include "trace_time.h"

/* only destory val key */
#if PHP_MAJOR_VERSION < 7
static void pt_key_destory_func(void *pDest)
{
    pt_chain_key_t **data = (pt_chain_key_t **)pDest;
    (*data)->val ? efree((*data)->val) : NULL;
    efree(*data);
}
#else
static void pt_key_destory_func(zval *pDest)
{
    pt_chain_key_t *data = (pt_chain_key_t *)Z_PTR_P(pDest);
    data->val ? efree(data->val) : NULL;
    efree(data);
}
#endif

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
        CHAIN_ERROR("getifaddr error");
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
                    break;
                }
            }
        }
    }
    freeifaddrs(myaddrs);
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
static int find_server_var(char *key, int key_size, void **ret) 
{
    if (PG(auto_globals_jit)) {
        pt_zend_is_auto_global("_SERVER", sizeof("_SERVER")-1);
    }
#if PHP_MAJOR_VERSION < 7
    zval **server = (zval **)&PG(http_globals)[TRACK_VARS_SERVER];
    return pt_zend_hash_zval_find(Z_ARRVAL_P(*server), key, key_size, ret);
#else 
    zval *server = &PG(http_globals)[TRACK_VARS_SERVER];
    return pt_zend_hash_zval_find(Z_ARRVAL_P(server), key, key_size, ret);
#endif
}

/* build chain header */
void pt_build_chain_header(pt_chain_t *pct)
{
    char *result;
    pt_chain_header_t *pch = &(pct->pch);
    if (pch->is_load_header == 1) {
        return;
    }
    
    /* local ip */ 
    pt_obtain_local_ip(pch);

    /* retrive key from header */
    if (pct->is_cli != 1) {
        HashTable *ht = pch->chain_header_key;
        zval *tmp = NULL;
        pt_chain_key_t *pck;
        for(zend_hash_internal_pointer_reset(ht); 
                zend_hash_has_more_elements(ht) == SUCCESS;
                zend_hash_move_forward(ht)) {
            
            if (pt_zend_hash_get_current_data(ht, (void **)&pck) == SUCCESS) {
                if (find_server_var(pck->receive_key, pck->receive_key_len, (void **)&tmp) == SUCCESS) {
                    if (Z_TYPE_P(tmp) == IS_STRING) {
                        pck->val = estrdup(Z_STRVAL_P(tmp));
                    }
                }
            }
        }
        //zend_llist *l = &SG(sapi_headers).headers;
        //zend_llist_apply_with_argument(l, retrive_header_data, pch);
    }

    if (!pch->trace_id->val) {
       rand64hex(&pch->trace_id->val);
    }

    if (!pch->span_id->val) {
        //if (!pch->parent_span_id->val) {
        //    pch->span_id->val = estrdup(pch->trace_id->val);
        //} else {
        rand64hex(&pch->span_id->val);
        //}
    }

    if (!pch->sampled->val) {
        //struct timeval tv;
        //int seed = gettimeofday(&tv, NULL) == 0 ? tv.tv_usec * getpid() : getpid();
        //srandom(seed);
        //int rand = random()%5; 
        //
        //todo dynamic sample algorithm 
        int rand = 1;
        if (rand == 1) {
            pch->sampled->val = estrdup("true");
            pch->is_sampled = 1;
        } else {
            pch->sampled->val = estrdup("false");
            pch->is_sampled = 0;
        }
    } else {
        if (strncmp(pch->sampled->val, "true", 4) == 0) {
            pch->is_sampled = 1;
        } else {
            pch->is_sampled = 0;
        }
    }

    if (!pch->flags->val) {
        pch->flags->val = estrdup("0");
    }

    pch->is_load_header = 1;
}

/* add http header */
void build_http_header(pt_chain_t *pct, zval *header, char *span_id)
{
    pt_chain_key_t *pck = NULL;
    if (Z_TYPE_P(header) == IS_ARRAY) {
        HashTable *ht = pct->pch.chain_header_key;
        for(zend_hash_internal_pointer_reset(ht); 
                zend_hash_has_more_elements(ht) == SUCCESS;
                zend_hash_move_forward(ht)) {
            
            if (pt_zend_hash_get_current_data(ht, (void **)&pck) == SUCCESS) {
                if (pck->is_pass != 1) {
                    continue;
                }

                char *pass_value;
                int value_size;
                char *value;
                if (span_id != NULL && strcmp(pck->name, "span_id") == 0) {
                    value = span_id;
                } else {
                    value = pck->val;
                }
                value_size = strlen(pck->pass_key) + sizeof(": ") - 1 + strlen(value) + 1;
                pass_value = emalloc(value_size);
                snprintf(pass_value, value_size, "%s: %s", pck->pass_key, value);
                pass_value[value_size - 1] = '\0';
                pt_add_next_index_string(header, pass_value, 1);
                efree(pass_value);
            }
        }
    }
}

/* init chain header */
void pt_init_chain_header(pt_chain_header_t *pch)
{
    pch->is_load_header = 0;
    ALLOC_HASHTABLE(pch->chain_header_key);
    zend_hash_init(pch->chain_header_key, 8, NULL,  pt_key_destory_func, 0);
   
    /* chain header */
    /* trace id */
    pt_chain_key_t *trace_id = (pt_chain_key_t *)emalloc(sizeof(pt_chain_key_t));
    trace_id->name = "trace_id";
    trace_id->receive_key = CHAIN_REC_TRACE_ID;
    trace_id->receive_key_len = sizeof(CHAIN_REC_TRACE_ID);
    trace_id->pass_key = CHAIN_HEADER_TRACE_ID;
    trace_id->is_pass = 1;
    trace_id->val = NULL;
    pch->trace_id = trace_id;

    /* span id */
    pt_chain_key_t *span_id = (pt_chain_key_t *)emalloc(sizeof(pt_chain_key_t));
    span_id->name = "span_id";
    span_id->receive_key = "none";
    span_id->receive_key_len = sizeof("none");
    span_id->pass_key = CHAIN_HEADER_SPAN_ID;
    span_id->is_pass = 1;
    span_id->val = NULL;
    pch->span_id = span_id;

    /* parent_span_id */
    pt_chain_key_t *parent_span_id = (pt_chain_key_t *)emalloc(sizeof(pt_chain_key_t));
    parent_span_id->name = "parent_span_id";
    parent_span_id->receive_key = CHAIN_REC_SPAN_ID;
    parent_span_id->receive_key_len = sizeof(CHAIN_REC_SPAN_ID);
    parent_span_id->pass_key = "";
    parent_span_id->is_pass = 0;
    parent_span_id->val = NULL;
    pch->parent_span_id = parent_span_id;

    /* sampled */
    pt_chain_key_t *sampled = (pt_chain_key_t *)emalloc(sizeof(pt_chain_key_t));
    sampled->name = "sampled";
    sampled->receive_key = CHAIN_REC_SAMPLED;
    sampled->receive_key_len = sizeof(CHAIN_REC_SAMPLED);
    sampled->pass_key = CHAIN_HEADER_SAMPLED;
    sampled->is_pass = 1;
    sampled->val = NULL;
    pch->sampled = sampled;

    /* flags */
    pt_chain_key_t *flags = (pt_chain_key_t *)emalloc(sizeof(pt_chain_key_t));
    flags->name = "flags";
    flags->receive_key = CHAIN_REC_FLAGS;
    flags->receive_key_len = sizeof(CHAIN_REC_FLAGS);
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
void pt_chain_ctor(pt_chain_t *pct, pt_chain_log_t *pcl, char *service_name)
{
    pct->pcl = pcl;

    /* service name */
    pct->service_name = service_name;

    /* execute time */
    //pct->execute_begin_time = (long) SG(global_request_time) * 1000000.00;
    pct->execute_begin_time = pt_time_usec();
    pct->execute_end_time = 0;
    
    /* http request */
    pct->sapi = sapi_module.name;
    pct->method = (char *) SG(request_info).request_method;
    if (SG(request_info).path_translated != NULL) {
        pct->script = estrdup(SG(request_info).path_translated);
    }
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
    /*
    struct timeval tp = {0};
    if (gettimeofday(&tp, NULL) == 0) {
        pct->execute_end_time = (long)(tp.tv_sec * 1000000 + tp.tv_usec);
    } else {
        pct->execute_end_time = (long)time(0) * 1000000;
    }
    */

    pt_build_chain_header(pct);
    pct->execute_end_time = pt_time_usec();

    /* add main span */
    if (pct->pch.is_sampled == 1) {
        zval *span;
        if (pct->method == NULL) {
            build_main_span(&span, pct->pch.trace_id->val, (char *)pct->sapi, pct->pch.span_id->val, pct->pch.parent_span_id->val, pct->execute_begin_time, pct->execute_end_time - pct->execute_begin_time); 
        } else {
            build_main_span(&span, pct->pch.trace_id->val, (char *)pct->method, pct->pch.span_id->val, pct->pch.parent_span_id->val, pct->execute_begin_time, pct->execute_end_time - pct->execute_begin_time); 
        }
        add_span_annotation(span, "sr", pct->execute_begin_time, pct->service_name,  pct->pch.ip, pct->pch.port);   
        add_span_annotation(span, "ss", pct->execute_end_time, pct->service_name,  pct->pch.ip, pct->pch.port);   

        if (pct->request_uri != NULL) {
            add_span_bannotation(span, "http.url", pct->request_uri, pct->service_name, pct->pch.ip, pct->pch.port);
        }

        if (pct->script != NULL) {
            add_span_bannotation(span, "script", pct->script, pct->service_name, pct->pch.ip, pct->pch.port);
            efree(pct->script);
        }

        if (pct->is_cli == 1 && pct->argc > 1) {
            int i = 1;
            char argv[1024];
            bzero(argv, 1024);
            for(;i < pct->argc; i++) {
                strcat(argv, pct->argv[i]);
                strcat(argv, ",");
            }
            argv[1023] = '\0';
            add_span_bannotation(span, "argv", argv, pct->service_name, pct->pch.ip, pct->pch.port);
        }

        pt_chain_add_span(pct->pcl, span);
    }

    /* header dtor */
    pt_chain_header_dtor(&(pct->pch));
}
