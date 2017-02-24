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

#include <string.h>
#include <stdlib.h>
#include "trace_util.h"
#include "php.h"

#if RAND_MAX/256 >= 0xFFFFFFFFFFFFFF
  #define LOOP_COUNT 1
#elif RAND_MAX/256 >= 0xFFFFFF
  #define LOOP_COUNT 2
#elif RAND_MAX/256 >= 0x3FFFF
  #define LOOP_COUNT 3
#elif RAND_MAX/256 >= 0x1FF
  #define LOOP_COUNT 4
#else
  #define LOOP_COUNT 5
#endif

uint64_t rand_uint64(void) 
{
    uint64_t r = 0;
    int i = 0;
    struct timeval tv;
    int seed = gettimeofday(&tv, NULL) == 0 ? tv.tv_usec * getpid() : getpid();
    srandom(seed);
    for (i = LOOP_COUNT; i > 0; i--) {
      r = r*(RAND_MAX + (uint64_t)1) + random();
    }
    return r;
}


void b2hex(char **output, const unsigned char *input, int input_len)
{
    static const char hexits[17] = "0123456789abcdef";
    int i;
    *output = (char *)emalloc(input_len * 2 + 1); 
    for (i = 0; i < input_len; i++) {
        *(*output + i*2) = hexits[*(input+i) >> 4];
        *(*output + i*2 + 1) = hexits[*(input+i) & 0x0F];
    }
    *(*output + input_len *2) = '\0';
}

void bin2hex64(char **output, const uint64_t *input) 
{
    b2hex(output, (char *)input, 8); 
}

void rand64hex(char **output) 
{
    uint64_t num = rand_uint64();
    return bin2hex64(output, &num);
}

void build_args_param(pt_frame_t *frame) 
{
    int i;
    if (frame->arg_count > 0) {
        frame->args = calloc(frame->arg_count, sizeof(sds));
    }
#if PHP_VERSION_ID < 70000
    for (i = 0; i < frame->arg_count; i++) {
        frame->args[i] = repr_zval(frame->ori_args[i], 32 TSRMLS_CC);
    }
#else
    if (frame->arg_count) {
        zval *p = ZEND_CALL_ARG(ex, 1);
        if (ex->func->type == ZEND_USER_FUNCTION) {
            uint32_t first_extra_arg = ex->func->op_array.num_args;

            if (first_extra_arg && frame->arg_count > first_extra_arg) {
                while (i < first_extra_arg) {
                    frame->args[i++] = repr_zval(p++, 32);
                }
                p = ZEND_CALL_VAR_NUM(ex, ex->func->op_array.last_var + ex->func->op_array.T);
            }
        }

        while(i < frame->arg_count) {
            frame->args[i++] = repr_zval(p++, 32);
        }
    }
#endif
}

/**
 * Trace file line info
 * --------------------- 
 */
void build_file_line_info(pt_frame_t *frame)
{
    zend_execute_data *caller = frame->caller;
    zend_execute_data *ex = frame->ex;
    zend_op_array *op_array = frame->op_array;

#if PHP_VERSION_ID >= 70000
    /* FIXME Sometimes execute_data->opline can be a interger NOT pointer.
     * I dont know how to handle it, this just make it works. */
    if (caller && caller->opline && caller->prev_execute_data &&
            caller->func && caller->func->op_array.opcodes == NULL) {
        caller = caller->prev_execute_data;
    }

    /* skip internal handler */
    if (caller && caller->opline && caller->prev_execute_data &&
            caller->opline->opcode != ZEND_DO_FCALL &&
            caller->opline->opcode != ZEND_DO_ICALL &&
            caller->opline->opcode != ZEND_DO_UCALL &&
            caller->opline->opcode != ZEND_DO_FCALL_BY_NAME &&
            caller->opline->opcode != ZEND_INCLUDE_OR_EVAL) {
        caller = caller->prev_execute_data;
    }
#endif

    /* lineno
     * The method we try to detect line number and filename is different
     * between Zend's debug_backtrace().
     * Because 1. Performance, so we won't use loop to find the valid op_array.
     * 2. And still want to catch internal function call, such as
     * call_user_func().  */
    if (caller && caller->opline) {
        frame->lineno = caller->opline->lineno;
    } else if (caller && caller->prev_execute_data && caller->prev_execute_data->opline) {
        frame->lineno = caller->prev_execute_data->opline->lineno; /* try using prev */
    } else if (op_array && op_array->opcodes) {
        frame->lineno = op_array->opcodes->lineno;
    /* Uncomment to use definition lineno if entry lineno is null, but we won't :P
     * } else if (caller != EG(current_execute_data) && EG(current_execute_data)->opline) {
     *     frame->lineno = EG(current_execute_data)->opline->lineno; [> try using current <]
     */
    } else {
        frame->lineno = 0;
    }

    /* filename */
#if PHP_VERSION_ID < 70000
    if (caller && caller->op_array) {
        op_array = caller->op_array;
    } else if (caller && caller->prev_execute_data && caller->prev_execute_data->op_array) {
        op_array = caller->prev_execute_data->op_array; /* try using prev */
    }
#else
    if (caller->func && ZEND_USER_CODE(caller->func->common.type)) {
        op_array = &(caller->func->op_array);
    } else if (caller->prev_execute_data && caller->prev_execute_data->func &&
            ZEND_USER_CODE(caller->prev_execute_data->func->common.type)) {
        op_array = &(caller->prev_execute_data->func->op_array); /* try using prev */
    }
#endif

    /* Same as upper
     * } else if (caller != EG(current_execute_data) && EG(current_execute_data)->op_array) {
     *     op_array = EG(current_execute_data)->op_array [> try using current <]
     * }
     */
    if (op_array) {
        frame->filename = sdsnew(P7_STR(op_array->filename));
    } else {
        frame->filename = NULL;
    }
}

/**
 * Trace Misc Function
 * --------------------
 */
sds repr_zval(zval *zv, int limit TSRMLS_DC)
{
    int tlen = 0;
    char buf[256], *tstr = NULL;
    sds result;

#if PHP_VERSION_ID >= 70000
    zend_string *class_name;
#endif

    /* php_var_export_ex is a good example */
    switch (Z_TYPE_P(zv)) {
#if PHP_VERSION_ID < 70000
        case IS_BOOL:
            if (Z_LVAL_P(zv)) {
                return sdsnew("true");
            } else {
                return sdsnew("false");
            }
#else
        case IS_TRUE:
            return sdsnew("true");
        case IS_FALSE:
            return sdsnew("false");
#endif
        case IS_NULL:
            return sdsnew("NULL");
        case IS_LONG:
            snprintf(buf, sizeof(buf), "%ld", Z_LVAL_P(zv));
            return sdsnew(buf);
        case IS_DOUBLE:
            snprintf(buf, sizeof(buf), "%.*G", (int) EG(precision), Z_DVAL_P(zv));
            return sdsnew(buf);
        case IS_STRING:
            tlen = (limit <= 0 || Z_STRLEN_P(zv) < limit) ? Z_STRLEN_P(zv) : limit;
            result = sdscatrepr(sdsempty(), Z_STRVAL_P(zv), tlen);
            if (limit > 0 && Z_STRLEN_P(zv) > limit) {
                result = sdscat(result, "...");
            }
            return result;
        case IS_ARRAY:
            /* TODO more info */
            return sdscatprintf(sdsempty(), "array(%d)", zend_hash_num_elements(Z_ARRVAL_P(zv)));
        case IS_OBJECT:
#if PHP_VERSION_ID < 70000
            if (Z_OBJ_HANDLER(*zv, get_class_name)) {
                Z_OBJ_HANDLER(*zv, get_class_name)(zv, (const char **) &tstr, (zend_uint *) &tlen, 0 TSRMLS_CC);
                result = sdscatprintf(sdsempty(), "object(%s)#%d", tstr, Z_OBJ_HANDLE_P(zv));
                efree(tstr);
            } else {
                result = sdscatprintf(sdsempty(), "object(unknown)#%d", Z_OBJ_HANDLE_P(zv));
            }
#else
            class_name = Z_OBJ_HANDLER_P(zv, get_class_name)(Z_OBJ_P(zv));
            result = sdscatprintf(sdsempty(), "object(%s)#%d", P7_STR(class_name), Z_OBJ_HANDLE_P(zv));
            zend_string_release(class_name);
#endif
            return result;
        case IS_RESOURCE:
#if PHP_VERSION_ID < 70000
            tstr = (char *) zend_rsrc_list_get_rsrc_type(Z_LVAL_P(zv) TSRMLS_CC);
            return sdscatprintf(sdsempty(), "resource(%s)#%ld", tstr ? tstr : "Unknown", Z_LVAL_P(zv));
#else
            tstr = (char *) zend_rsrc_list_get_rsrc_type(Z_RES_P(zv) TSRMLS_CC);
            return sdscatprintf(sdsempty(), "resource(%s)#%d", tstr ? tstr : "Unknown", Z_RES_P(zv)->handle);
        case IS_UNDEF:
            return sdsnew("{undef}");
#endif
        default:
            return sdsnew("{unknown}");
    }
}

