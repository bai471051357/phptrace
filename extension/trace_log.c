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
#include "trace_log.h"
#include "php.h"

void pt_chain_log_ctor(pt_chain_log_t *log, char *log_path)
{
    log->path = log_path;
    log->format = LOG_FORMAT;
    log->buf = pemalloc(ALLOC_LOG_SIZE, 1);
    log->total_size = ALLOC_LOG_SIZE;
    log->alloc_size = 0;
}

/* ervery request reload file */
void pt_chain_log_init(pt_chain_log_t *log)
{
    memset(log->buf, 0x00, log->total_size);
    log->fd = -1;
    log->alloc_size = 0; 
}

void pt_chain_log_add(pt_chain_log_t *log, char *buf, size_t size)
{
    if (log->alloc_size + size >= log->total_size) {
        int realloc_size = log->alloc_size + ((int)(size/ALLOC_LOG_SIZE) + 1) * ALLOC_LOG_SIZE;
        log->buf = prealloc(log->buf, realloc_size, 1);
    }
    strncpy(log->buf + log->alloc_size, buf, size);
    log->alloc_size  += size;
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

void pt_chain_log_flush(pt_chain_log_t *log)
{
    char *dname; 
    char *tmp_path = strdup(log->path);  
    ssize_t written_bytes = 0;

    if (tmp_path == NULL) {
        ERROR("dup log path error");
    }
    
    dname = dirname(tmp_path);
    
    if (pt_mkdir_recursive(dname) == -1) {
        ERROR("recursive make dir error [%s]", tmp_path);
        goto end;
    }
    
    if (log->fd == -1) {
        log->fd = open(log->path, O_WRONLY|O_CREAT|O_APPEND, 0666);
        if (log->fd == -1) {
            ERROR("open log error[%d] errstr[%s]", errno, strerror(errno));
            goto end;
        }
    }
    
    do {
        if ((written_bytes = write(log->fd, log->buf, log->alloc_size) )== -1) {
            ERROR("write log error[%d] errstr[%s]", errno, strerror(errno));
            goto end;
        }
        written_bytes += written_bytes;
    }while(written_bytes < log->alloc_size);
    

end:
    free(tmp_path);
}

void pt_chain_log_dtor(pt_chain_log_t *log)
{
    pefree(log->buf, 1);
}
