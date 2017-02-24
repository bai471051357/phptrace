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

#ifndef TRACE_LOG_H
#define TRACE_LOG_H

#include <stdint.h>
#include <limits.h>

# if defined(__linux__)
#include <linux/limits.h>
# endif

#include "php.h"
#include "Zend/zend_llist.h"
#include "trace_type.h"

#ifndef PATH_MAX
#define PATH_MAX 4096 
#endif

#define ALLOC_LOG_SIZE  1024 * 1024
#define DEFAULT_LOG_DIR "/var/wd/log/chain/"
#define DEFAULT_PATH    DEFAULT_LOG_DIR"trace_chain"
#define LOG_FORMAT      "%Y%m%d%H" 

/* chain log */
typedef struct {
    char *path;
    int fd;
    char *format; 
    char *buf;
    uint64_t total_size;
    uint64_t alloc_size;
    uint64_t max_size;
    zval *spans;
} pt_chain_log_t;

/* log format */
typedef struct {
    char *service_name;
    char *ipv4;
    int port;
}pt_chain_endpoint_t;

typedef struct {
    char *key;
    char *value;
    pt_chain_endpoint_t  endpoint;
}pt_chain_bannotations_t;

typedef struct {
    pt_chain_endpoint_t  endpoint;
    int64_t timestamp;
    char *value;
}pt_chain_annotations_t;

typedef struct {
    char *trace_id;
    char *name;
    char *span_id;
    char *parent_span_id;
    int64_t timestamp;
    int64_t duration;
    int annotations_num;
    pt_chain_annotations_t *annotations;
    int bannotations_num;
    pt_chain_bannotations_t *bannotations;
}pt_chain_span_t;

/* function */
void pt_chain_log_ctor(pt_chain_log_t *log, char *log_path);
int pt_chain_log_set_file_path(char *new_path);
void pt_chain_log_add(pt_chain_log_t *log, char *buf, size_t size);
void pt_chain_log_flush(pt_chain_log_t *log);
void pt_chain_log_dtor(pt_chain_log_t *log);
void pt_chain_add_span(pt_chain_log_t *log, zval *span);
#endif
