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

#include <stdint.h>
#include <string.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <error.h>
#include <fcntl.h>
#include <time.h>
#include "trace_log.h"
#include "trace_util.h"
#include "php7_wrapper.h"

void pt_chain_log_ctor(pt_chain_log_t *log, char *log_path)
{
    log->path = log_path;
    log->format = LOG_FORMAT;
    log->buf = pemalloc(ALLOC_LOG_SIZE, 1);
    log->total_size = ALLOC_LOG_SIZE;
    log->alloc_size = 0;
    log->max_size = 0;  //32M
}

/* ervery request reload file */
void pt_chain_log_init(pt_chain_log_t *log)
{
    //memset(log->buf, 0x00, log->total_size);
    log->fd = -1;
    //log->alloc_size = 0; 
    PT_ALLOC_INIT_ZVAL(log->spans);
    array_init(log->spans);
}

void pt_chain_add_span(pt_chain_log_t *log, zval *span)
{
    add_next_index_zval(log->spans, span);
    PT_FREE_ALLOC_ZVAL(span);
}

void pt_chain_log_add(pt_chain_log_t *log, char *buf, size_t size)
{
    if (log->alloc_size + size >= (log->total_size + 1)) {
        int realloc_size = log->alloc_size + ((int)(size/ALLOC_LOG_SIZE) + 1) * ALLOC_LOG_SIZE;
        log->buf = perealloc(log->buf, realloc_size, 1);
    }
    strncpy(log->buf + log->alloc_size, buf, size);
    log->alloc_size  += size;

    strncpy(log->buf + log->alloc_size, "\n", 1);
    log->alloc_size++;
}

static int pt_mkdir_recursive(const char *dir)
{
    if (access(dir, R_OK|W_OK) == 0) {
        return 0;
    }

    char tmp[PATH_MAX];
    strncpy(tmp, dir, PATH_MAX);
    int i, len = strlen(tmp);
    

    if (dir[len - 1] != '/')
    {
        strcat(tmp, "/");
    }

    len = strlen(tmp);

    for (i = 1; i < len; i++)
    {
        if (tmp[i] == '/')
        {
            tmp[i] = 0;
            if (access(tmp, R_OK) != 0)
            {
                if (mkdir(tmp, 0755) == -1)
                {
                    return -1;
                }
            }
            tmp[i] = '/';
        }
    }
    return 0;
}

void pt_chain_log_write(pt_chain_log_t *log)
{
    if (log->alloc_size <= 0) {
        return;
    }
    char *dname; 
    char tmp_path[64];
    char *tmp_dir;
    size_t written_bytes = 0;

    time_t raw_time;
    struct tm* time_info;
    char time_format[32];
    memset(time_format, 0x00, 32);
    memset(tmp_path, 0x00, 64);
    time(&raw_time);
    time_info = localtime(&raw_time);
    strftime(time_format, 32, log->format, time_info);
    sprintf(tmp_path, "%s-%s.log", log->path, time_format);
    tmp_dir = estrdup(tmp_path); 

    dname = dirname(tmp_dir);
    if (pt_mkdir_recursive(dname) == -1) {
        CHAIN_ERROR("recursive make dir error [%s]", tmp_path);
        goto end;
    }
    
    if (log->fd == -1) {
        log->fd = open(tmp_path, O_WRONLY|O_CREAT|O_APPEND, 0666);
        if (log->fd == -1) {
            CHAIN_ERROR("open log error[%d] errstr[%s]", errno, strerror(errno));
            goto end;
        }
    }
    do {
        if ((written_bytes = write(log->fd, log->buf, log->alloc_size) )== -1) {
            CHAIN_ERROR("write log error[%d] errstr[%s]", errno, strerror(errno));
            goto end;
        }
        written_bytes += written_bytes;
    }while(written_bytes < log->alloc_size);

    memset(log->buf, 0x00, log->total_size);
    log->alloc_size = 0; 

end:
    close(log->fd);
    efree(tmp_dir);
}


void pt_chain_log_flush(pt_chain_log_t *log)
{
    
    /* load span from log */
    zval func;
    zval ret;
    zval *args[1];
    args[0] = log->spans;
    PT_ZVAL_STRING(&func, "json_encode", 1);
    int result = pt_call_user_function(EG(function_table), (zval **)NULL, &func, &ret, 1, args);
    if (result == SUCCESS) {
        if (PT_Z_TYPE_P(&ret) != IS_STRING) {
            
            //PT_ZVAL_STRING(&func, "json_last_error", 0);
            //zval ret1; 
            //result = call_user_function(EG(function_table), (zval **)NULL, &func, &ret1, 1, args);
            //if (result == SUCCESS) {
            //    if (Z_TYPE(ret1) == IS_STRING) {
            //        CHAIN_ERROR("%s", Z_STRVAL(ret1));     
            //    }
            //    zval_dtor(&ret1);
            //}
            zval_dtor(&ret);
            goto end;
        }
        
        pt_chain_log_add(log, Z_STRVAL(ret), Z_STRLEN(ret));
        zval_dtor(&ret);
    } else {
        goto end;
    }

    if (log->max_size <= log->alloc_size) {
        pt_chain_log_write(log);
    }

end:
    pt_zval_dtor(&func);
    pt_zval_ptr_dtor(&log->spans);
    PT_FREE_ALLOC_ZVAL(log->spans);
}

void pt_chain_log_dtor(pt_chain_log_t *log)
{
    pt_chain_log_write(log);
    pefree(log->buf, 1);
}
