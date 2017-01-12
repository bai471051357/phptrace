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

#ifndef TRACE_INTERCEPT_H
#define TRACE_INTERCEPT_H

#include "php.h"
#include "trace_type.h"
#include "stdint.h"
#include "php7_wrapper.h"
#include "trace_log.h"

#define ADD_INTERCEPTOR_ELE(interceptor, ele) do {   \
    pt_zend_hash_update(interceptor->elements, ele->keyword, strlen(ele->keyword) + 1, (void *)(&ele), sizeof(pt_interceptor_ele_t *), NULL);  \
}while(0)
#define ADD_RECORD(pit,log) do {                            \
    pt_chain_log_add(pit->pct->pcl, log, strlen(log));      \
}while(0)

extern struct pt_chain_st;

/* interceptor */
typedef struct {
    HashTable *elements;
    uint64_t hit_num;    
    uint64_t exception_num;

    struct pt_chain_st *pct;
}pt_interceptor_t;

typedef zend_bool (*hit_func)(char *class_name, char *function_name);
typedef void (*capture_func)(pt_interceptor_t *pit, pt_frame_t *frame);
typedef void (*record_func)(pt_interceptor_t *pit, pt_frame_t *frame);

/* interceptor element */ 
typedef struct {
    char *name;
    char *keyword;
    hit_func hit;
    capture_func capture;
    record_func record;

    pt_interceptor_t *pit;
}pt_interceptor_ele_t;

/* function */
void pt_intercept_ctor(pt_interceptor_t *pit, struct pt_chain_st *pct);
void pt_intercept_dtor(pt_interceptor_t *pit);
zend_bool pt_intercept_hit(pt_interceptor_t *pit, pt_interceptor_ele_t **ele, char *class_name, char *function_name);
#endif

