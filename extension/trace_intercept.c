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

#include "trace_intercept.h"
#include "trace_type.h"
#include "trace_log.h"
#include "trace_chain.h"

#include "php.h"
#include "ext/pdo/php_pdo_driver.h"
#include "sds/sds.h"
#define RETURN_Z_STRING(zval) (zval && (PT_Z_TYPE_P(zval) == IS_STRING) ? Z_STRVAL_P(zval) : "")
#define RETURN_Z_LONG(zval) (zval && (PT_Z_TYPE_P(zval) == IS_LONG) ? Z_LVAL_P(zval) : 0)

void build_main_span(zval **span, char *trace_id, char *server_name, char *span_id, char *parent_id, long timestamp, long duration) 
{
    PT_ALLOC_INIT_ZVAL(*span);
    array_init(*span);
    pt_add_assoc_string(*span, "traceId", trace_id, 1);
    pt_add_assoc_string(*span, "name", server_name, 1);
    pt_add_assoc_string(*span, "id", span_id, 1);
    if (parent_id != NULL) {
        pt_add_assoc_string(*span, "parentId", parent_id, 1);
    }
    add_assoc_long(*span, "timestamp", timestamp);
    add_assoc_long(*span, "duration", duration);
    
    /* add annotions */
    zval *annotations;
    PT_ALLOC_INIT_ZVAL(annotations);
    array_init(annotations);
    add_assoc_zval(*span, "annotations", annotations);

    /* add binaryAnnotationss */
    zval *bannotations;
    PT_ALLOC_INIT_ZVAL(bannotations);
    array_init(bannotations);
    add_assoc_zval(*span, "binaryAnnotations", bannotations);

    PT_FREE_ALLOC_ZVAL(annotations);
    PT_FREE_ALLOC_ZVAL(bannotations);
}

static void build_main_span_intercept(zval **span, char *server_name, struct pt_chain_st *pct, pt_frame_t *frame)
{
    build_main_span(span, pct->pch.trace_id->val, server_name, frame->span_id, pct->pch.span_id->val, frame->entry_time, (long)frame->inc_time);
}

char *build_service_name(struct pt_chain_st *pct, char *service_name)
{
    char *g_service_name = pct->service_name; 
    int service_len = strlen(service_name) + strlen(g_service_name) + 3;
    char *full_service_name = emalloc(service_len);
    memset(full_service_name, 0x00, service_len);
    snprintf(full_service_name, service_len, "%s-%s", g_service_name, service_name);
    full_service_name[service_len-1] = '\0';
    return full_service_name;
}

void add_endpoint(zval *annotation, char *service_name, char *ipv4, long port) 
{
    zval *endpoint; 
    PT_ALLOC_INIT_ZVAL(endpoint);
    array_init(endpoint);
    pt_add_assoc_string(endpoint, "serviceName", service_name, 1); 
    pt_add_assoc_string(endpoint, "ipv4", ipv4, 1);
    if (port != 0) {
        add_assoc_long(endpoint, "port", port);
    }
    add_assoc_zval(annotation, "endpoint", endpoint);
    PT_FREE_ALLOC_ZVAL(endpoint);
}

void add_span_annotation(zval *span, const char *value, long timestamp, char *service_name, char *ipv4, long port) 
{
    zval *annotations;
    if (pt_zend_hash_zval_find(Z_ARRVAL_P(span), "annotations", sizeof("annotations"), (void **)&annotations) == FAILURE) {
        return;
    }
    zval *annotation;
    PT_ALLOC_INIT_ZVAL(annotation);
    array_init(annotation);
    pt_add_assoc_string(annotation, "value", (char *)value, 1);
    add_assoc_long(annotation, "timestamp", timestamp);
    add_endpoint(annotation, service_name, ipv4, port);
    add_next_index_zval(annotations, annotation);
    PT_FREE_ALLOC_ZVAL(annotation);
}

void add_span_annotation_intercept(zval *span, const char *value, long timestamp, struct pt_chain_st *pct)
{
    add_span_annotation(span, value, timestamp, pct->service_name, pct->pch.ip, pct->pch.port);
}

void add_span_bannotation(zval *span, const char *key, const char *value, char *service_name, char *ipv4, long port)
{
    zval *bannotations;
    if (pt_zend_hash_zval_find(Z_ARRVAL_P(span), "binaryAnnotations", sizeof("binaryAnnotations"), (void **)&bannotations) == FAILURE) {
        return;
    }
    zval *bannotation;
    PT_ALLOC_INIT_ZVAL(bannotation);
    array_init(bannotation);
    pt_add_assoc_string(bannotation, "key", (char *)key, 1);
    pt_add_assoc_string(bannotation, "value", (char *)value, 1);
    add_endpoint(bannotation, service_name, ipv4, port);
    add_next_index_zval(bannotations, bannotation);
    PT_FREE_ALLOC_ZVAL(bannotation);
}

static void add_span_bannotation_intercept(zval *span, const char *key, const char *value, struct pt_chain_st *pct) 
{
    add_span_bannotation(span, key, value, pct->service_name, pct->pch.ip, pct->pch.port);
}

static void add_span_bannotation_long_intercept(zval *span, const char *key, long value, struct pt_chain_st *pct)
{
    char str[64];
    sprintf(str, "%ld", value);
    add_span_bannotation_intercept(span, key, (const char*)str, pct);
}

zend_bool pt_intercept_hit(pt_interceptor_t *pit, pt_interceptor_ele_t **eleDest, char *class_name, char *function_name)
{
    pt_interceptor_ele_t *ele;
    /*
    int class_len = 0;
    int func_len = 0;
    int match_key_len = 0;
    char *padding_string = "NULL";
    int padding_string_len = strlen(padding_string);
    char connect_char = '$';
    char *match_key;

    if (class_name != NULL) {
        class_len = strlen(class_name);
    } else {
        class_len = padding_string_len;
    }

    if (function_name != 0) {
        func_len = strlen(function_name);
    } else {
        func_len = padding_string_len;
    }
    match_key_len = func_len + class_len + 2; 
    match_key = (char *)emalloc(match_key_len);
    memset(match_key, (void *)0, match_key_len);
    
    if (class_name != NULL) {
        match_key = strncat(match_key, class_name, class_len); 
    } else {
        match_key = strncat(match_key, padding_string, class_len);
    }

    match_key[class_len] = connect_char;


    if (function_name != NULL) {
        match_key = strncat(match_key, function_name, func_len);
    } else {
        match_key = strncat(match_key, padding_, func_len);
    }
    */

    if (class_name != NULL && pit->elements != NULL) {
        if (pt_zend_hash_find(pit->elements, class_name, strlen(class_name) + 1, (void **)&ele) == SUCCESS) {
            *eleDest = ele;
            if (ele->hit == NULL) {
                return 1;
            } else {
                return ele->hit(class_name, function_name); 
            }
        }
    }

    if (function_name != NULL && pit->elements != NULL) {
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

#if PHP_MAJOR_VERSION < 7                                                                                                       
static void hash_destroy_cb(void *pDest)
#else
static void hash_destroy_cb(zval *pDest)
#endif
{
    pt_interceptor_ele_t **pie = (pt_interceptor_ele_t **)pDest;
    pefree(*pie, 1);
}

static char *convert_args_to_string(pt_frame_t *frame)
{
    int i = 0;
    int arg_len = 0;
#define ARGS_MAX_LEN 50
#define ARGS_ELLIPSIS "..."
#define ARGS_ELLIPSIS_LEN (sizeof("...") - 1)
#define ARGS_REAL_LEN (ARGS_MAX_LEN - ARGS_ELLIPSIS_LEN - 1)
    build_args_param(frame);  
    char *string = emalloc(ARGS_MAX_LEN);
    int real_len = 0;
    memset(string, 0x00, ARGS_MAX_LEN);
    for (; i < frame->arg_count; i++) {
        real_len = sdslen(frame->args[i])  + 1;
        if ((arg_len + real_len) >= ARGS_REAL_LEN)  {
            real_len = ARGS_REAL_LEN - arg_len;
        }
        string = strncat(string, frame->args[i], real_len - 1);
        string = strncat(string, ",", 1);
        arg_len += real_len;
    }
    
    if (arg_len >= ARGS_REAL_LEN) {
        string = strncat(string + ARGS_REAL_LEN, ARGS_ELLIPSIS, ARGS_ELLIPSIS_LEN);
        string[ARGS_MAX_LEN] = '\0';
    }

    return string;
}

#if PHP_VERSION_ID < 70000
#define GET_FUNC_ARG(param, arg_num)    zval *param = (frame->ori_args)[arg_num]
#define GET_FUNC_ARG_UNDEC(param, arg_num) param = (frame->ori_args)[arg_num]
#else
#define GET_FUNC_ARG(param, arg_num)    zval *param = ((zval *)(frame->ori_args) + arg_num)
#define GET_FUNC_ARG_UNDEC(param, arg_num) param = ((zval *)(frame->ori_args) + arg_num)
#endif

static zval *build_com_record(pt_interceptor_t *pit, pt_frame_t *frame, int add_args)
{
    char *name;
    int name_len = 0;
    if (frame->class != NULL) {
        name_len += strlen(frame->class);
    }

    if (frame->function != NULL) {
        name_len += strlen(frame->function);
    }
    name_len += 5;

    name = emalloc(name_len);
    memset(name, 0x00, name_len);
    if (frame->class != NULL) {
        strcat(name, frame->class);
        strcat(name, "::");
    }

    if (frame->function != NULL) {
        strcat(name, frame->function);
    }
    zval *span;
    build_main_span_intercept(&span, name, pit->pct, frame);
    add_span_annotation_intercept(span, "cs", frame->entry_time, pit->pct);
    add_span_annotation_intercept(span, "cr", frame->exit_time, pit->pct);

    if (add_args == 1) {
        char *value = convert_args_to_string(frame);                                                                
        add_span_bannotation_intercept(span, name, value, pit->pct);
        efree(value);
    }
    efree(name);
    return span;
}

/***********************curl_init********************************/
static void curl_init_record(pt_interceptor_t *pit, pt_frame_t *frame)
{
    zval *ret = frame->ori_ret;
    if (PT_Z_TYPE_P(ret) == IS_RESOURCE) {
        /* separe zval or no delete ret zval */
        zval *curl_handler;
        PT_ALLOC_INIT_ZVAL(curl_handler);
        MAKE_COPY_ZVAL(&ret, curl_handler);  
        add_index_zval(pit->curl_handlers, Z_RESVAL_P(curl_handler), curl_handler);
    }
}

/********************curl_multi_add_handle*************************/
static void curl_multi_add_handle_record(pt_interceptor_t *pit, pt_frame_t *frame)
{
    zval *ret = frame->ori_ret;
    
    /* execute success will add handle */
    if (PT_Z_TYPE_P(ret) == IS_LONG && Z_LVAL_P(ret) == 0) {

        GET_FUNC_ARG(fir_arg,0);
        GET_FUNC_ARG(sec_arg,1);
        if (PT_Z_TYPE_P(sec_arg) != IS_RESOURCE) {
            return;
        }

        zval *tmp;  
        zval *curl_array;
        //zval *curl_handler;
        //PT_ALLOC_INIT_ZVAL(curl_handler);
        //MAKE_COPY_ZVAL(&sec_arg, curl_handler);  
        if (pt_zend_hash_index_find(Z_ARRVAL_P(pit->curl_multi_handlers), Z_RESVAL_P(fir_arg), (void **)&tmp) == SUCCESS) {
                add_index_long(tmp, Z_RESVAL_P(sec_arg), Z_RESVAL_P(sec_arg));
        } else {
                PT_ALLOC_INIT_ZVAL(curl_array);
                array_init(curl_array);
                add_index_long(curl_array, Z_RESVAL_P(sec_arg), Z_RESVAL_P(sec_arg));
                add_index_zval(pit->curl_multi_handlers, Z_RESVAL_P(fir_arg), curl_array); 
        }
    }
}

#define LOAD_OPT_HTTPHEADER_VAL do {                                                                                                \
    if (Z_LVAL(pit->curl_http_header_const) == -1) {                                                                                \
        if (pt_zend_get_constant("CURLOPT_HTTPHEADER", sizeof("CURLOPT_HTTPHEADER") - 1, &pit->curl_http_header_const) == 0) {      \
            return;                                                                                                                 \
        }                                                                                                                           \
    }                                                                                                                               \
}while(0)

/*************curl_setopt***************/
static void curl_setopt_capture(pt_interceptor_t *pit, pt_frame_t *frame)
{
    if (frame->arg_count != 3) {
        return;
    }
    LOAD_OPT_HTTPHEADER_VAL;
    GET_FUNC_ARG(fir_arg,0);
    GET_FUNC_ARG(sec_arg,1);
    GET_FUNC_ARG(thi_arg,2);
    if (PT_Z_TYPE_P(sec_arg) == IS_LONG 
        && Z_LVAL_P(sec_arg) == Z_LVAL(pit->curl_http_header_const)) {
        zval *copy_header;
        PT_ALLOC_INIT_ZVAL(copy_header);
        ZVAL_ZVAL(copy_header, thi_arg, 1, 0);
        add_index_zval(pit->curl_header_record, Z_RESVAL_P(fir_arg), copy_header);
        PT_FREE_ALLOC_ZVAL(copy_header);
        //add_index_bool(pit->curl_header_record, Z_RESVAL_P(fir_arg), 1);
        //build_http_header(pit->pct, thi_arg);
    }
}

static void curl_setopt_array_capture(pt_interceptor_t *pit, pt_frame_t *frame)
{
    if (frame->arg_count != 2) {
        return;
    }
    LOAD_OPT_HTTPHEADER_VAL;
    GET_FUNC_ARG(fir_arg,0);
    GET_FUNC_ARG(sec_arg,1);
    if (PT_Z_TYPE_P(sec_arg) == IS_ARRAY) {
        HashTable *ht = Z_ARRVAL_P(sec_arg);
        zval *http_header = NULL;
        if (pt_zend_hash_index_zval_find(ht, Z_LVAL(pit->curl_http_header_const), (void **)&http_header) == SUCCESS) {
            zval *copy_header;
            PT_ALLOC_INIT_ZVAL(copy_header);
            ZVAL_ZVAL(copy_header, http_header, 1, 0);
            add_index_zval(pit->curl_header_record, Z_RESVAL_P(fir_arg), copy_header);
            PT_FREE_ALLOC_ZVAL(copy_header);
            //add_index_bool(pit->curl_header_record, Z_RESVAL_P(fir_arg), 1);
            //build_http_header(pit->pct, http_header, frame->span_id);
        }
    }
}

/* add chain header */
static void add_chain_header(pt_interceptor_t *pit, zval *curl_resource, pt_frame_t *frame) 
{
    zval *tmp = NULL;
    zval *option = NULL;
    int is_init = 0;
    if (pt_zend_hash_index_zval_find(Z_ARRVAL_P(pit->curl_header_record), Z_RESVAL_P(curl_resource), (void **)&tmp) == SUCCESS) {
        option = tmp;
    } else {
        PT_ALLOC_INIT_ZVAL(option);
        array_init(option);
        is_init = 1;
    }
    build_http_header(pit->pct, option, frame->span_id);
    
    zval func;
    zval *argv[3];
    zval ret;
    PT_ZVAL_STRING(&func, "curl_setopt", 1);
    argv[0] = curl_resource;
    argv[1] = &pit->curl_http_header_const;
    argv[2] = option;
    pt_call_user_function(EG(function_table), (zval **)NULL, &func, &ret, 3, argv);
    zval_dtor(&ret);
    pt_zval_ptr_dtor(&option);
    if (is_init == 1) {
        PT_FREE_ALLOC_ZVAL(option);
    }
    pt_zval_dtor(&func); 
    add_index_bool(pit->curl_header_record, Z_RESVAL_P(curl_resource), 1);
}

/*************curl_multi_exec**********/
static void curl_multi_exec_capture(pt_interceptor_t *pit, pt_frame_t *frame)
{
    GET_FUNC_ARG(fir_arg,0);
    LOAD_OPT_HTTPHEADER_VAL;
    zval *curl_array;
    if (pt_zend_hash_index_find(Z_ARRVAL_P(pit->curl_multi_handlers), Z_RESVAL_P(fir_arg), (void **)&curl_array) == SUCCESS) {
        HashTable *ht = Z_ARRVAL_P(curl_array);
        zval *val;
        for(zend_hash_internal_pointer_reset(ht); 
                zend_hash_has_more_elements(ht) == SUCCESS;
                zend_hash_move_forward(ht)) {
            
            if (pt_zend_hash_get_current_data(ht, (void **)&val) == SUCCESS) {

                /* check already insert header */ 
                zval *set_header;
                if (pt_zend_hash_index_zval_find(Z_ARRVAL_P(pit->curl_header_record), Z_LVAL_P(val), (void **)&set_header) == FAILURE) {
                    zval *val_res;
                    PT_MAKE_STD_ZVAL(val_res);
                    ZVAL_RESOURCE(val_res, Z_LVAL_P(val));
                    add_chain_header(pit, val_res, frame);
                    FREE_ZVAL(val_res);
                }
            }
        }
    }
}

static void build_curl_bannotation(zval *span, pt_interceptor_t *pit, zval *handle, char *method,zend_bool check_error) 
{
    zval func;
    zval *args[1];
    args[0] = handle;
    long err = 0;
    char *errstr = NULL;
    zval *url = NULL; 
    zval *http_code = NULL;
    zval *primary_ip = NULL;
    zval *primary_port = NULL;
    PT_ZVAL_STRING(&func, "curl_getinfo", 1);
    zval ret1;
    zval ret;
    int result = pt_call_user_function(EG(function_table), (zval **)NULL, &func, &ret1, 1, args);   
    if (result == SUCCESS) {
        if (Z_TYPE(ret1) == IS_ARRAY) {
           if (pt_zend_hash_zval_find(Z_ARRVAL(ret1), "url", sizeof("url"), (void **)&url) == FAILURE) {
                url = NULL;
           }

           if (pt_zend_hash_zval_find(Z_ARRVAL(ret1), "http_code", sizeof("http_code"), (void **)&http_code) == FAILURE) {
                http_code = NULL;
           }
            
           if (pt_zend_hash_zval_find(Z_ARRVAL(ret1), "primary_ip", sizeof("primary_ip"), (void **)&primary_ip) == FAILURE) {
                primary_ip = NULL;
           }

           if (pt_zend_hash_zval_find(Z_ARRVAL(ret1), "primary_port", sizeof("primary_port"), (void **)&primary_port) == FAILURE) {
                primary_port = NULL;
           }
        }
    }
    pt_zval_dtor(&func);

    add_span_bannotation_intercept(span, "method", method, pit->pct);
    add_span_bannotation_intercept(span, "http.url", RETURN_Z_STRING(url), pit->pct);

    if (check_error == 1) {
        PT_ZVAL_STRING(&func, "curl_errno", 1);
        result = pt_call_user_function(EG(function_table), (zval **)NULL, &func, &ret, 1, args);
        if (result == SUCCESS) {
            if (Z_TYPE(ret) == IS_LONG) {
                err = Z_LVAL(ret);
            }
            zval_dtor(&ret);
        }

        pt_zval_dtor(&func); 

        /* curl_error */
        if (err != 0) {
            PT_ZVAL_STRING(&func, "curl_error", 1);
            result = pt_call_user_function(EG(function_table), (zval **)NULL, &func, &ret, 1, args);
            if (result == SUCCESS) {
                if (Z_TYPE(ret) == IS_STRING) {
                    errstr = estrdup(Z_STRVAL(ret)); 
                } else {
                    errstr = estrdup("");
                }
                zval_dtor(&ret);
            }
            pt_zval_dtor(&func); 
        }
        if (err != 0) {
            add_span_bannotation(span, "error", errstr, "http",RETURN_Z_STRING(primary_ip), RETURN_Z_LONG(primary_port));
        } else {
            char tmp_string[32];
            sprintf(tmp_string, "%ld", RETURN_Z_LONG(http_code));
            add_span_bannotation(span, "http.status", tmp_string, "http",RETURN_Z_STRING(primary_ip), RETURN_Z_LONG(primary_port));
        }
    }

    if (errstr != NULL) efree(errstr);
    zval_dtor(&ret1);
}

static void curl_multi_exec_record(pt_interceptor_t *pit, pt_frame_t *frame)
{
    zval *ret = frame->ori_ret;
    GET_FUNC_ARG(fir_arg,0);
    GET_FUNC_ARG(sec_arg,1);
    if (Z_LVAL(pit->CURLM_CALL_MULTI_PERFORM) == -10) {
        if (pt_zend_get_constant("CURLM_CALL_MULTI_PERFORM", sizeof("CURLM_CALL_MULTI_PERFORM") - 1, &pit->CURLM_CALL_MULTI_PERFORM) == 0) {
            return;
        }
    }

    if ((PT_Z_TYPE_P(ret) != IS_LONG) || (Z_LVAL_P(ret) == Z_LVAL(pit->CURLM_CALL_MULTI_PERFORM) || Z_LVAL_P(sec_arg) != 0)) {
        return;
    }

    zval *span;
    build_main_span_intercept(&span, "http", pit->pct, frame);
    add_span_annotation_intercept(span, "cs", frame->entry_time, pit->pct);
    add_span_annotation_intercept(span, "cr", frame->exit_time, pit->pct);
    if (PT_Z_TYPE_P(ret) != IS_FALSE && PT_Z_TYPE_P(fir_arg) == IS_RESOURCE) {
        HashTable *ht = Z_ARRVAL_P(pit->curl_multi_handlers); 
        zval *multi_handle; 
        if (pt_zend_hash_index_find(ht, Z_RESVAL_P(fir_arg), (void **)&multi_handle) == SUCCESS) {
            zval *val;
            HashTable *curl_handle = Z_ARRVAL_P(multi_handle);
            for(zend_hash_internal_pointer_reset(curl_handle); 
                    zend_hash_has_more_elements(curl_handle) == SUCCESS;
                    zend_hash_move_forward(curl_handle)) {
                if (pt_zend_hash_get_current_data(curl_handle, (void **)&val) == SUCCESS) {
                    zval *val_res;
                    PT_MAKE_STD_ZVAL(val_res);
                    ZVAL_RESOURCE(val_res, Z_RESVAL_P(val));
                    build_curl_bannotation(span, pit, val_res, "curl_multi_exec", 1);
                    FREE_ZVAL(val_res);
                }
            }
        }
    }
    pt_chain_add_span(pit->pct->pcl, span);
}


#define DETERMINE_SET_MAIN_SPAN(pit,key) do{                            \
    if (pit->span == NULL) {                                            \
        build_main_span_intercept(&pit->span, #key, pit->pct, frame);   \
    }                                                                   \
}while(0)

/*************curl_exec***************/
static void curl_exec_capture(pt_interceptor_t *pit, pt_frame_t *frame)
{
    GET_FUNC_ARG(fir_arg,0);
    LOAD_OPT_HTTPHEADER_VAL;
    add_chain_header(pit, fir_arg, frame);
    //zval *tmp = NULL;
    //if (pt_zend_hash_index_zval_find(Z_ARRVAL_P(pit->curl_header_record), Z_RESVAL_P(fir_arg), (void **)&tmp) == SUCCESS) {
    //    if (PT_Z_TYPE_P(tmp) == IS_FALSE && Z_BVAL_P(tmp) == 1) {
    //        return;
    //    }
    //} else {
    //    add_chain_header(pit, fir_arg);
    //}
}

static void curl_exec_record(pt_interceptor_t *pit, pt_frame_t *frame)
{
    GET_FUNC_ARG(fir_arg,0);

    /* add chain log */
    zval *curl_span;
    build_main_span_intercept(&curl_span, "http", pit->pct, frame);
    add_span_annotation_intercept(curl_span, "cs", frame->entry_time, pit->pct);
    add_span_annotation_intercept(curl_span, "cr", frame->exit_time, pit->pct);
    build_curl_bannotation(curl_span, pit, fir_arg, "curl_exec", 1);

    /* add span to log */
    pt_chain_add_span(pit->pct->pcl, curl_span);
}

static zend_bool pdo_hit(char *class_name, char *function_name) 
{
    if (strcmp(function_name, "__construct") == 0) {
        return 1; 
    }

    if (strcmp(function_name, "exec") == 0) {
        return 1; 
    }

    if (strcmp(function_name, "query") == 0) {
        return 1;
    }

    if (strcmp(function_name, "commit") == 0) {
        return 1;
    }

    if (strcmp(function_name, "prepare") == 0) {
        return 1;
    }

    return 0;
}


#if PHP_MAJOR_VERSION < 7                                                                                                       
#define GET_PDO_DBH  pdo_dbh_t *dbh = zend_object_store_get_object(object);                                                                                  
#else                                                                                                                               
#define GET_PDO_DBH  pdo_dbh_t *dbh = Z_PDO_DBH_P(object);                                                                                  
#endif                                                                                                                                      


#if PHP_MAJOR_VERSION < 7
#define SET_SPAN_EXCEPTION(exception_ce,service_name,host,port)          do {                                                   \
        if (instanceof_function(Z_OBJCE_P(EG(exception)), exception_ce) == 1) {                                                 \
            zval *message = pt_zend_read_property(exception_ce, EG(exception), "message", sizeof("message") - 1, 1);            \
            add_span_bannotation(span, "error", RETURN_Z_STRING(message), service_name, host, port);                            \
        }                                                                                                                       \
}while(0)
#else
#define SET_SPAN_EXCEPTION(exception_ce,service_name,host,port)          do {                                                   \
        if (instanceof_function(EG(exception)->ce, exception_ce) == 1) {                                                        \
            zval tmp;                                                                                                           \
            ZVAL_OBJ(&tmp, EG(exception));                                                                                      \
            zval *message = pt_zend_read_property(exception_ce, &tmp, "message", sizeof("message") - 1, 1);                     \
            add_span_bannotation(span, "error", RETURN_Z_STRING(message), service_name, host, port);                            \
        }                                                                                                                       \
}while(0)
#endif

#define PDO_SET_EXCEPTION(service_name,host, port)  do {                        \
        if (EG(exception) != NULL) {                                            \
            zend_class_entry *pdo_exception_ce = php_pdo_get_exception();       \
            SET_SPAN_EXCEPTION(pdo_exception_ce,service_name,host, port);       \
        }                                                                       \
}while(0)

#define SET_PDO_RECORD(keyword) do {                                                                                                            \
    if (strcmp(frame->function, #keyword) == 0) {                                                                                               \
        build_main_span_intercept(&span, #keyword, pit->pct, frame);                                                                            \
        add_span_annotation_intercept(span, "cs", frame->entry_time, pit->pct);                                                                 \
        add_span_annotation_intercept(span, "cr", frame->exit_time, pit->pct);                                                                  \
        add_span_bannotation_intercept(span, "PDO."#keyword, RETURN_Z_STRING(fir_arg), pit->pct);                                               \
        GET_PDO_DBH                                                                                                                             \
        add_span_bannotation_intercept(span, "sa", dbh->data_source, pit->pct);                                                                 \
        zval *ret = frame->ori_ret;                                                                                                             \
        if (ret != NULL && PT_Z_TYPE_P(ret) == IS_FALSE) {                                                                                      \
            zval ret;                                                                                                                           \
            zval function;                                                                                                                      \
            PT_ZVAL_STRING(&function, "errorInfo", 1);                                                                                          \
            if (pt_call_user_function(NULL, &object, &function, &ret, 0, NULL) == SUCCESS) {                                                    \
                zval *error_msg;                                                                                                                \
                if ((Z_TYPE(ret) == IS_ARRAY) &&  (pt_zend_hash_index_find(Z_ARRVAL(ret), 2, (void **)&error_msg) == SUCCESS)) {                \
                    add_span_bannotation_intercept(span, "error", Z_STRVAL_P(error_msg), pit->pct);                                             \
                } else {                                                                                                                        \
                    add_span_bannotation_intercept(span, "error", "unknown", pit->pct);                                                         \
                }                                                                                                                               \
            }                                                                                                                                   \
            pt_zval_dtor(&function);                                                                                                            \
            pt_zval_dtor(&ret);                                                                                                                 \
        }                                                                                                                                       \
        PDO_SET_EXCEPTION(pit->pct->service_name, pit->pct->pch.ip, pit->pct->pch.port);                                                        \
        pt_chain_add_span(pit->pct->pcl, span);                                                                                                 \
    }                                                                                                                                           \
}while(0)

/****************************pdo**********************/
static void pdo_record(pt_interceptor_t *pit, pt_frame_t *frame)
{
    zval *object = frame->object;    
    GET_FUNC_ARG(fir_arg,0);
    zval *span;
    SET_PDO_RECORD(__construct);
    SET_PDO_RECORD(exec);
    SET_PDO_RECORD(query);
    SET_PDO_RECORD(commit);
}

static zend_bool pdo_statement_hit(char *class_name, char *function_name)
{
    if (strcmp(function_name, "execute") == 0) {
        return 1;
    }
    return 0;
}

static void pdo_statement_record(pt_interceptor_t *pit, pt_frame_t *frame)
{
    zval *object = frame->object;    
    zval *span;
    build_main_span_intercept(&span, "execute", pit->pct, frame);
    add_span_annotation_intercept(span, "cs", frame->entry_time, pit->pct);
    add_span_annotation_intercept(span, "cr", frame->exit_time, pit->pct);
#if PHP_MAJOR_VERSION < 7
    pdo_stmt_t *stmt = (pdo_stmt_t *)zend_object_store_get_object(object); 
#else
    pdo_stmt_t *stmt = (pdo_stmt_t *)Z_PDO_STMT_P(object); 
#endif
    add_span_bannotation_intercept(span, "PDOStatement::execute", stmt->query_string, pit->pct);
    add_span_bannotation_intercept(span, "sa", stmt->dbh->data_source, pit->pct);                      
    /* todo retrive data from stmt->bound_params and stmt->bound_columns */
    
    zval *ret = frame->ori_ret;
    if (ret != NULL && PT_Z_TYPE_P(ret) == IS_FALSE) {
        zval ret;
        zval function;
        PT_ZVAL_STRING(&function, "errorInfo", 1);
        if (pt_call_user_function(NULL, &object, &function, &ret, 0, NULL) == SUCCESS) {
            zval *error_msg;
            if ((Z_TYPE(ret) == IS_ARRAY) &&  (pt_zend_hash_index_find(Z_ARRVAL(ret), 2, (void **)&error_msg) == SUCCESS)) {
                add_span_bannotation_intercept(span, "error", Z_STRVAL_P(error_msg),  pit->pct);
            } else {
                add_span_bannotation_intercept(span, "error", "unknown", pit->pct);
            }
        }
        pt_zval_dtor(&function);
        zval_dtor(&ret);
    }
    pt_chain_add_span(pit->pct->pcl, span);
}

/*****************redis****************************/
static zend_bool redis_hit(char *class_name, char *function_name)
{
    if (strcmp(function_name, "__construct") == 0) {
        return 0;
    } 

    if (strcmp(function_name, "__destruct") == 0) {
        return 0;
    }
    
    if (strcmp(function_name, "getHost") == 0) {
        return 0;
    }

    if (strcmp(function_name, "getPort") == 0) {
        return 0;
    }

    if (strcmp(function_name, "setOption") == 0) {
        return 0;
    }
    
    if (strcmp(function_name, "getLastError") == 0) {
        return 0;
    }

    return 1;
}

#define INIT_BANNOTATION_PARAM(MODULE)                                                                          \
    int size = sizeof(#MODULE) + strlen(frame->function) + 2;                                                   \
    char *key = (char *)emalloc(size);                                                                          \
    memset(key, 0x00, size);                                                                                    \
    strncpy(key, #MODULE, sizeof(#MODULE) - 1);                                                                 \
    key = strcat(key, "::");                                                                                    \
    key = strcat(key, frame->function);                                                                         \
    char *value = convert_args_to_string(frame);                                                                \
    add_span_bannotation_intercept(span, key, value, pit->pct);                                                 \
    efree(value);                                                                                               \

static void redis_record(pt_interceptor_t *pit, pt_frame_t *frame)
{
    zval *object = frame->object;    
    zval *span;

    build_main_span_intercept(&span, frame->function, pit->pct, frame);
    add_span_annotation_intercept(span, "cs", frame->entry_time, pit->pct);
    add_span_annotation_intercept(span, "cr", frame->exit_time, pit->pct);
    INIT_BANNOTATION_PARAM(Redis)

    zval host;
    zval port;
    zval function;
    PT_ZVAL_STRING(&function, "getHost", 1);
    if (pt_call_user_function(NULL, &object, &function, &host, 0, NULL) == SUCCESS) { 
        if (Z_TYPE(host) != IS_STRING) {
            PT_ZVAL_STRING(&host, "unkown", 1);
        }
    } else {
        PT_ZVAL_STRING(&host, "unkown", 1);
    }
    
    pt_zval_dtor(&function);

    PT_ZVAL_STRING(&function, "getPort", 1);
    if (pt_call_user_function(NULL, &object, &function, &port, 0, NULL) == SUCCESS) { 
        if (Z_TYPE(port) != IS_LONG) {
            ZVAL_LONG(&port, 0);
        }
    } else {
        ZVAL_LONG(&port, 0);
    }
    pt_zval_dtor(&function);

    zval *ret = frame->ori_ret;
    if (ret != NULL && PT_Z_TYPE_P(ret) == IS_FALSE) {
        zval error;
        PT_ZVAL_STRING(&function, "getLastError", 1);
        if (pt_call_user_function(NULL, &object, &function, &error, 0, NULL) == SUCCESS) {
            if (Z_TYPE(error) == IS_STRING) {
                add_span_bannotation(span, "error", Z_STRVAL(error), "Redis", Z_STRVAL(host), Z_LVAL(port));
            }
            zval_dtor(&error);
        }
        pt_zval_dtor(&function);
    }

    add_span_bannotation(span, "sa", "true", key, Z_STRVAL(host), Z_LVAL(port));
    if (EG(exception) != NULL) { 
        zend_class_entry *redis_exception_ce;
        if (pt_zend_hash_find(CG(class_table), "redisexception", sizeof("redisexception"), (void **)&redis_exception_ce) == SUCCESS) {
            SET_SPAN_EXCEPTION(redis_exception_ce, "Redis", Z_STRVAL(host), Z_LVAL(port));
        }
    }
   
    efree(key);
    pt_zval_dtor(&host);
    pt_chain_add_span(pit->pct->pcl, span);
}

/*******************memcached***************************/
static zend_bool memcached_hit(char *class_name, char *function_name) 
{
    if (strcmp(function_name, "__construct") == 0) {
        return 0;
    }

    if (strcmp(function_name, "__destruct") == 0) {
        return 0;
    }

    if (strcmp(function_name, "getResultMessage") == 0) {
        return 0;
    }

    return 1;
}

static void memcached_record(pt_interceptor_t *pit, pt_frame_t *frame)
{
    zval *span;
    zval *object = frame->object;    
    build_main_span_intercept(&span, frame->function, pit->pct, frame);

    /* get add set delete append prepend increment  actions will record annotation */
    /* others record binnaryannotation*/
    if ((strncmp(frame->function, "addServer", sizeof("addServer") - 1) == 0)
        || (strncmp(frame->function, "setOption", sizeof("setOption") - 1) == 0)
        || (strcmp(frame->function, "getOption") == 0) 
        || (strcmp(frame->function, "resetServerList") == 0))  {

    } else {
        add_span_annotation_intercept(span, "cs", frame->entry_time, pit->pct);
        add_span_annotation_intercept(span, "cr", frame->exit_time, pit->pct);
    }

    INIT_BANNOTATION_PARAM(Memcached)

    zval *ret = frame->ori_ret;
    if (ret != NULL && PT_Z_TYPE_P(ret) == IS_FALSE) {
        zval ret;
        zval function;
        PT_ZVAL_STRING(&function, "getResultMessage", 1);
        if (pt_call_user_function(NULL, &object, &function, &ret, 0, NULL) == SUCCESS) {
            zval *error_msg;
            if ((Z_TYPE(ret) == IS_ARRAY) &&  (pt_zend_hash_index_find(Z_ARRVAL(ret), 2, (void **)&error_msg) == SUCCESS)) {
                add_span_bannotation_intercept(span, "error", Z_STRVAL_P(error_msg), pit->pct);
            } else {
                add_span_bannotation_intercept(span, "error", "unknown", pit->pct);
            }
        }
        pt_zval_dtor(&function);
        zval_dtor(&ret);
    }
    efree(key);
    pt_chain_add_span(pit->pct->pcl, span);
}

/*****************************mysqli******************************/
static void mysqli_connect_common_record(pt_interceptor_t *pit, pt_frame_t *frame)
{
    if (frame->arg_count < 1) {
        return;
    }

    zval *span = build_com_record(pit, frame, 0);

    GET_FUNC_ARG(host,0);
    if (frame->arg_count >= 1 && PT_Z_TYPE_P(host) == IS_STRING) {
        add_span_bannotation_intercept(span, "peer.host", Z_STRVAL_P(host), pit->pct);
    }

    GET_FUNC_ARG(dbname,3);
    if (frame->arg_count >= 4 && PT_Z_TYPE_P(dbname) == IS_STRING) {
        add_span_bannotation_intercept(span, "peer.dbname", Z_STRVAL_P(dbname), pit->pct);
    }

    GET_FUNC_ARG(port,4);
    if (frame->arg_count >= 5 && PT_Z_TYPE_P(port) == IS_LONG) {
        add_span_bannotation_long_intercept(span, "peer.port", Z_LVAL_P(port), pit->pct);
    } else if (frame->arg_count >= 5 && PT_Z_TYPE_P(port) == IS_STRING) {
        add_span_bannotation_intercept(span, "peer.port", Z_STRVAL_P(port), pit->pct);
    }

    /* todo add error */
    pt_chain_add_span(pit->pct->pcl, span);
}

static void mysqli_connect_record(pt_interceptor_t *pit, pt_frame_t *frame, char *service_name)
{
    mysqli_connect_common_record(pit, frame);
}

static void db_query_record(pt_interceptor_t *pit, pt_frame_t *frame, int need_resource, char *service_name)
{
    if (need_resource == 1 && frame->arg_count < 2) {
        return;
    }

    if (need_resource == 0 && frame->arg_count < 1) {
        return;
    }

    zval *span = build_com_record(pit, frame, 0);
    zval *sql;
    if (need_resource == 1) {
        GET_FUNC_ARG_UNDEC(sql,1);
    } else {
        GET_FUNC_ARG_UNDEC(sql,0);
    }

    if (PT_Z_TYPE_P(sql) == IS_STRING) {
        add_span_bannotation_intercept(span, "sql", Z_STRVAL_P(sql), pit->pct);
    }
    pt_chain_add_span(pit->pct->pcl, span);
}

static void mysqli_query_record(pt_interceptor_t *pit, pt_frame_t *frame)
{
    db_query_record(pit, frame, 1, "mysqli_query");
}

static zend_bool mysqli_common_hit(char *class_name, char *function_name)
{
    if (strcmp(function_name, "__construct") == 0) {
        return 1;
    }

    if (strcmp(function_name, "query") == 0) {
        return 1;
    }

    if (strcmp(function_name, "commit") == 0) {
        return 1;
    }

    if (strcmp(function_name, "prepare") == 0) {
        return 1;
    }

    return 0;
}

static void mysqli_common_record(pt_interceptor_t *pit, pt_frame_t *frame)
{
    if (strcmp(frame->function, "__construct") == 0) {
        mysqli_connect_common_record(pit, frame);
        return;
    }

    if (strcmp(frame->function, "query") == 0 || strcmp(frame->function, "prepare") == 0) {
        db_query_record(pit, frame, 0, "mysqli::query");
        return;
    }

    zval *span = build_com_record(pit, frame, 0);
    pt_chain_add_span(pit->pct->pcl, span);
}

static zend_bool mysqli_stmt_common_hit(char *class_name, char *function_name)
{
    if (strcmp(function_name, "execute") == 0) {
        return 1;
    }
    return 0;
}

static void mysqli_stmt_common_record(pt_interceptor_t *pit, pt_frame_t *frame)
{
    zval *span = build_com_record(pit, frame, 0);
    pt_chain_add_span(pit->pct->pcl, span);
}

/********************predis***********************************/
static zend_bool predis_hit(char *class_name, char *function_name)
{
    if (strcmp(function_name, "__call") == 0) {
        return 1;
    }
    return 0; 
}

static void predis_record(pt_interceptor_t *pit, pt_frame_t *frame)
{
    zval *span = build_com_record(pit, frame, 1);
    pt_chain_add_span(pit->pct->pcl, span);
}

#define INIT_INTERCEPTOR_ELE(nk,hit_f,capture_f,record_f)  do {                                                 \
    pt_interceptor_ele_t *name##_ele = (pt_interceptor_ele_t *) pemalloc(sizeof(pt_interceptor_ele_t), 1);      \
    name##_ele->name = #nk;                                                                                     \
    name##_ele->keyword = #nk;                                                                                  \
    name##_ele->hit = hit_f;                                                                                    \
    name##_ele->capture = capture_f;                                                                            \
    name##_ele->record = record_f;                                                                              \
    name##_ele->pit = pit;                                                                                      \
    ADD_INTERCEPTOR_ELE(pit, name##_ele);                                                                       \
}while(0)                                                                                                       \

void pt_intercept_ctor(pt_interceptor_t *pit, struct pt_chain_st *pct)
{
    /* init */ 
    //ALLOC_HASHTABLE(pit->elements);
    pit->elements = (HashTable *)pemalloc(sizeof(HashTable), 1);
    zend_hash_init(pit->elements, 8, NULL, hash_destroy_cb, 1);
    pit->hit_num = 0;
    pit->exception_num = 0;
    pit->pct = pct;

    /* add curl ele */
    INIT_INTERCEPTOR_ELE(curl_exec, NULL, &curl_exec_capture, &curl_exec_record);
    INIT_INTERCEPTOR_ELE(curl_setopt, NULL, &curl_setopt_capture, NULL);
    INIT_INTERCEPTOR_ELE(curl_setopt_array, NULL, &curl_setopt_array_capture, NULL);

    /* pdo */
    INIT_INTERCEPTOR_ELE(PDO, &pdo_hit, NULL, &pdo_record);
    INIT_INTERCEPTOR_ELE(PDOStatement, &pdo_statement_hit, NULL, &pdo_statement_record);

    /* mysqli */
    INIT_INTERCEPTOR_ELE(mysqli_connect, NULL, NULL, &mysqli_connect_record);
    INIT_INTERCEPTOR_ELE(mysqli_query, NULL, NULL, &mysqli_query_record);
    INIT_INTERCEPTOR_ELE(mysqli_prepare, NULL, NULL, &mysqli_query_record);
    INIT_INTERCEPTOR_ELE(mysqli_stmt_execute, NULL, NULL, &mysqli_query_record);
    INIT_INTERCEPTOR_ELE(mysqli, &mysqli_common_hit, NULL, &mysqli_common_record);
    INIT_INTERCEPTOR_ELE(mysqli, &mysqli_common_hit, NULL, &mysqli_common_record);
    INIT_INTERCEPTOR_ELE(mysqli_stmt, &mysqli_stmt_common_hit, NULL, &mysqli_stmt_common_record);

    //INIT_INTERCEPTOR_ELE(curl_init, NULL, NULL, &curl_init_record);
    //INIT_INTERCEPTOR_ELE(curl_multi_add_handle, NULL, NULL, &curl_multi_add_handle_record);
    //INIT_INTERCEPTOR_ELE(curl_multi_exec, NULL, &curl_multi_exec_capture, &curl_multi_exec_record);

    /* add phpredis ele */
    /* need check phpredis extension exists or not */
    if (zend_get_module_started("redis") == SUCCESS) {
        INIT_INTERCEPTOR_ELE(Redis, &redis_hit, NULL, &redis_record);
    }

    /* need install memcache */
    /* add memcache ele */
    if (zend_get_module_started("memcached") == SUCCESS) {
        INIT_INTERCEPTOR_ELE(Memcached, &memcached_hit, NULL, &memcached_record);
    }

    /* customer app common */
    INIT_INTERCEPTOR_ELE(Predis\\Client, &predis_hit, NULL, &predis_record);
}

void pt_intercept_init(pt_interceptor_t *pit)
{
    PT_ALLOC_INIT_ZVAL(pit->curl_header_record);
    array_init(pit->curl_header_record);
    PT_ALLOC_INIT_ZVAL(pit->curl_multi_handlers);
    array_init(pit->curl_multi_handlers);
    PT_ALLOC_INIT_ZVAL(pit->curl_handlers);
    array_init(pit->curl_handlers);
    ZVAL_LONG(&(pit->curl_http_header_const), -1);
    ZVAL_LONG(&(pit->CURLM_CALL_MULTI_PERFORM), -10);
}

void pt_intercept_uninit(pt_interceptor_t *pit)
{
    pt_zval_ptr_dtor(&pit->curl_header_record);
    PT_FREE_ALLOC_ZVAL(pit->curl_header_record);
    pt_zval_ptr_dtor(&pit->curl_multi_handlers);
    PT_FREE_ALLOC_ZVAL(pit->curl_multi_handlers);
    pt_zval_ptr_dtor(&pit->curl_handlers);
    PT_FREE_ALLOC_ZVAL(pit->curl_handlers);
    pt_zval_dtor(&pit->curl_http_header_const);
}

void pt_intercept_dtor(pt_interceptor_t *pit)
{
    zend_hash_destroy(pit->elements);
    //FREE_HASHTABLE(pit->elements);
    pefree(pit->elements, 1);
    pit->elements = NULL;
}
