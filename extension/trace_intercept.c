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

#include "php.h"
#include "trace_intercept.h"
#include "trace_type.h"
#include "trace_log.h"
#include "trace_chain.h"

#define HAVE_CURL 1
#include "php_curl.h"
#define RETURN_Z_STRING(zval) (zval && (Z_TYPE_P(zval) == IS_STRING) ? Z_STRVAL_P(zval) : "")
#define RETURN_Z_LONG(zval) (zval && (Z_TYPE_P(zval) == IS_LONG) ? Z_LVAL_P(zval) : -1)
#define INIT_CHAIN_SPAN(span, pit, a_num, ba_num) do {                              \
    span.trace_id = estrdup(pit->pct->pch.trace_id->val);                          \
    rand64hex(&span.span_id);                                                        \
    span.parent_span_id = estrdup(pit->pct->pch.trace_id->val);                    \
    span.timestamp = frame->entry_time;                                             \
    span.duration = frame->exc_time;                                               \
    span.annotations_num = a_num;                                                   \
    span.annotations = ecalloc(sizeof(pt_chain_annotations_t), a_num);              \
    span.bannotations_num = ba_num;                                                 \
    span.bannotations = ecalloc(sizeof(pt_chain_bannotations_t), ba_num);           \
}while(0)

zend_bool pt_intercept_hit(pt_interceptor_t *pit, pt_interceptor_ele_t **eleDest,char *class_name, char *function_name)
{
    pt_interceptor_ele_t *ele;
    if (class_name != NULL) {
        if (pt_zend_hash_find(pit->elements, class_name, strlen(class_name) + 1, (void **)&ele) == SUCCESS) {
            *eleDest = ele;
            if (ele->hit == NULL) {
                return 1;
            } else {
                return ele->hit(class_name, function_name); 
            }
        }
    }

    if (function_name != NULL) {
        if (pt_zend_hash_find(pit->elements, function_name, strlen(function_name) + 1, (void **)&ele) == SUCCESS) {
            *eleDest = ele;
            if (ele->hit == NULL) {
                return 1;
            } else {
                return ele->hit(class_name, function_name); 
            }
        }
    }
    return 0;
}

static void hash_destroy_cb(void *pDest)
{
    pt_interceptor_ele_t **pie = (pt_interceptor_ele_t **)pDest;
    pefree(*pie, 1);
}

/*************curl_init***************/
static void curl_init_capture(pt_interceptor_t *pit, pt_frame_t *frame)
{
    zval **ori_args = frame->ori_args; 
    if (Z_TYPE_PP(ori_args) == IS_STRING) {
        char *tmp_url = pt_rebuild_url(pit->pct, Z_STRVAL_PP(ori_args));              
        ZVAL_STRING(*ori_args, tmp_url, 0);
    }
}

static void curl_init_record(pt_interceptor_t *pit, pt_frame_t *frame)
{
    zval **ori_args = frame->ori_args; 
    if (Z_TYPE_PP(ori_args) == IS_STRING) {
        char *tmp_buf = emalloc(Z_STRLEN_PP(ori_args)  + 256);
        sprintf(tmp_buf, "##[http request][\"curl_init\", \"%s\"] ", Z_STRVAL_PP(ori_args));
        ADD_RECORD(pit,tmp_buf);
        efree(tmp_buf);
    }
}

/*************curl_exec***************/
static void curl_exec_capture(pt_interceptor_t *pit, pt_frame_t *frame)
{
     
}

static void curl_exec_record(pt_interceptor_t *pit, pt_frame_t *frame)
{
    zval ret;
    zval func;
    zval *args[1];
    zval **ori_args = frame->ori_args; 
    args[0] = *ori_args;
    long err = 0;
    char *errstr = NULL;
    ZVAL_STRING(&func, "curl_getinfo", 0);
    int result = call_user_function(EG(function_table), (zval **)NULL, &func, &ret, 1, args);   
    if (result == SUCCESS) {
        if (Z_TYPE(ret) == IS_ARRAY) {
           zval *url; 
           zval *content_type;
           zval *http_code;
           zval *header;
           if (pt_zend_hash_find(Z_ARRVAL(ret), "url", sizeof("url"), (void **)&url) == FAILURE) {
                url = NULL;
           }

           if (pt_zend_hash_find(Z_ARRVAL(ret), "content_type", sizeof("content_type"), (void **)&content_type) == FAILURE) {
                content_type = NULL; 
           }

           if (pt_zend_hash_find(Z_ARRVAL(ret), "http_code", sizeof("http_code"), (void **)&http_code) == FAILURE) {
                http_code = NULL;
           }
            size_t tmp_size = strlen(RETURN_Z_STRING(url))  + 256;
            char *tmp_buf = emalloc(tmp_size);
            snprintf(tmp_buf, tmp_size, "##[http request][\"curl\", \"%s\", \"%s\", %ld] ", RETURN_Z_STRING(url), RETURN_Z_STRING(content_type), RETURN_Z_LONG(http_code));
            
            ADD_RECORD(pit,tmp_buf);
            efree(tmp_buf);
        }
        zval_dtor(&ret);
    }

    /* curl_errno */
    ZVAL_STRING(&func, "curl_errno", 0);
    result = call_user_function(EG(function_table), (zval **)NULL, &func, &ret, 1, args);
    if (result == SUCCESS) {
        if (Z_TYPE(ret) == IS_LONG) {
            err = Z_LVAL(ret);
        }
    }
    
    /* curl_error */
    if (err != 0) {
        ZVAL_STRING(&func, "curl_error", 0);
        result = call_user_function(EG(function_table), (zval **)NULL, &func, &ret, 1, args);
        if (result == SUCCESS) {
            if (Z_TYPE(ret) == IS_STRING) {
                errstr = estrdup(Z_STRVAL(ret)); 
            } else {
                errstr = estrdup("");
            }
        }
    }

    /* add chain log */
    pt_chain_span_t span;
    span.name = estrdup("http");
    //INIT_CHAIN_SPAN(span, pit, 2, 2);
    span.trace_id = estrdup(pit->pct->pch.trace_id->val);
    rand64hex(&span.span_id);
    span.parent_span_id = estrdup(pit->pct->pch.trace_id->val);
    span.timestamp = frame->entry_time;
    span.duration = frame->exc_time;
    span.annotations_num = 2;
    span.annotations = ecalloc(sizeof(pt_chain_annotations_t), 2);
    span.bannotations_num = 2;
    span.bannotations = ecalloc(sizeof(pt_chain_bannotations_t), 2);

}

void pt_intercept_ctor(pt_interceptor_t *pit, struct pt_chain_st *pct)
{
    /* init */ 
    ALLOC_HASHTABLE(pit->elements);
    zend_hash_init(pit->elements, 8, NULL, hash_destroy_cb, 0);
    pit->hit_num = 0;
    pit->exception_num = 0;
    pit->pct = pct;
    
    /* add ele */
    pt_interceptor_ele_t *curl_exec_ele = (pt_interceptor_ele_t *) pemalloc(sizeof(pt_interceptor_ele_t), 1);
    curl_exec_ele->name = "curl";
    curl_exec_ele->keyword = "curl_exec";
    curl_exec_ele->hit = NULL;
    curl_exec_ele->capture = &curl_exec_capture;
    curl_exec_ele->record = &curl_exec_record;
    curl_exec_ele->pit = pit;
    ADD_INTERCEPTOR_ELE(pit, curl_exec_ele);

    /*
    pt_interceptor_ele_t *curl_ele = (pt_interceptor_ele_t *) pemalloc(sizeof(pt_interceptor_ele_t), 1);
    curl_ele->name = "curl";
    curl_ele->keyword = "curl_init";
    curl_ele->hit = NULL;
    curl_ele->capture = &curl_init_capture;
    curl_ele->record = &curl_init_record;
    curl_ele->pit = pit;
    ADD_INTERCEPTOR_ELE(pit, curl_ele);
    */
}

void pt_intercept_dtor(pt_interceptor_t *pit)
{
    zend_hash_destroy(pit->elements);
    FREE_HASHTABLE(pit->elements);
}
