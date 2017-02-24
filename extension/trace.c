/**
 * Copyright 2017 Qihoo 360
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_trace.h"

#include "zend_extensions.h"
#include "SAPI.h"

#include "trace_comm.h"
#include "trace_time.h"
#include "trace_type.h"
#include "sds/sds.h"
#include "trace_filter.h"
#include "php7_wrapper.h"

#include "trace_chain.h"
#include "trace_log.h"


/**
 * Trace Global
 * --------------------
 */
/* Debug output */
#if TRACE_DEBUG_OUTPUT
#define PTD(format, ...) fprintf(stderr, "[PTDebug:%d] " format "\n", __LINE__, ##__VA_ARGS__)
#else
#define PTD(format, ...)
#endif

/**
 * Compatible with PHP 5.1, zend_memory_usage() is not available in 5.1.
 * AG(allocated_memory) is the value we want, but it available only when
 * MEMORY_LIMIT is ON during PHP compilation, so use zero instead for safe.
 */
#if PHP_VERSION_ID < 50200
#define zend_memory_usage(args...) 0
#define zend_memory_peak_usage(args...) 0
typedef unsigned long zend_uintptr_t;
#endif

PHP_FUNCTION(trace_chain_truncate);

static void frame_build(pt_frame_t *frame, zend_bool internal, unsigned char type, zend_execute_data *caller, zend_execute_data *ex, zend_op_array *op_array TSRMLS_DC);
static int frame_send(pt_frame_t *frame TSRMLS_DC);
#if PHP_VERSION_ID < 70000
static void frame_set_retval(pt_frame_t *frame, zend_bool internal, zend_execute_data *ex, zend_fcall_info *fci TSRMLS_DC);
#endif

static sds repr_zval(zval *zv, int limit TSRMLS_DC);
static void handle_error(TSRMLS_D);
static void handle_command(void);

#if PHP_VERSION_ID < 50500
static void (*ori_execute)(zend_op_array *op_array TSRMLS_DC);
static void (*ori_execute_internal)(zend_execute_data *execute_data_ptr, int return_value_used TSRMLS_DC);
ZEND_API void pt_execute(zend_op_array *op_array TSRMLS_DC);
ZEND_API void pt_execute_internal(zend_execute_data *execute_data, int return_value_used TSRMLS_DC);
#elif PHP_VERSION_ID < 70000
static void (*ori_execute_ex)(zend_execute_data *execute_data TSRMLS_DC);
static void (*ori_execute_internal)(zend_execute_data *execute_data_ptr, zend_fcall_info *fci, int return_value_used TSRMLS_DC);
ZEND_API void pt_execute_ex(zend_execute_data *execute_data TSRMLS_DC);
ZEND_API void pt_execute_internal(zend_execute_data *execute_data, zend_fcall_info *fci, int return_value_used TSRMLS_DC);
#else
static void (*ori_execute_ex)(zend_execute_data *execute_data);
static void (*ori_execute_internal)(zend_execute_data *execute_data, zval *return_value);
ZEND_API void pt_execute_ex(zend_execute_data *execute_data);
ZEND_API void pt_execute_internal(zend_execute_data *execute_data, zval *return_value);
#endif
static inline zend_function *obtain_zend_function(zend_bool internal, zend_execute_data *ex, zend_op_array *op_array TSRMLS_DC);

/**
 * PHP Extension Init
 * --------------------
 */

ZEND_DECLARE_MODULE_GLOBALS(tracing)

/* Make sapi_module accessable */
extern sapi_module_struct sapi_module;

/* Every user visible function must have an entry in tracing_functions[]. */
const zend_function_entry tracing_functions[] = {
    PHP_FE(trace_chain_truncate, NULL)
#ifdef PHP_FE_END
    PHP_FE_END  /* Must be the last line in trace_functions[] */
#else
    { NULL, NULL, NULL, 0, 0 }
#endif
};

zend_module_entry tracing_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    "tracing",
    tracing_functions,
    PHP_MINIT(tracing),
    PHP_MSHUTDOWN(tracing),
    PHP_RINIT(tracing),
    PHP_RSHUTDOWN(tracing),
    PHP_MINFO(tracing),
#if ZEND_MODULE_API_NO >= 20010901
    TRACE_EXT_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};

#if PHP_VERSION_ID >= 70000 && defined(COMPILE_DL_TRACING) && defined(ZTS)
ZEND_TSRMLS_CACHE_DEFINE();
#endif

#ifdef COMPILE_DL_TRACING
ZEND_GET_MODULE(tracing)
#endif

/* PHP_INI */
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("tracing.enable",    "1",    PHP_INI_SYSTEM, OnUpdateBool, enable, zend_tracing_globals, tracing_globals)
    STD_PHP_INI_ENTRY("tracing.chain_log_path",  DEFAULT_PATH, PHP_INI_SYSTEM, OnUpdateString, chain_log_path, zend_tracing_globals, tracing_globals)
    STD_PHP_INI_ENTRY("tracing.service_name",  "default", PHP_INI_SYSTEM, OnUpdateString, service_name, zend_tracing_globals, tracing_globals)
PHP_INI_END()

/* php_tracing_init_globals */
static void php_tracing_init_globals(zend_tracing_globals *ptg)
{
    memset(&ptg->ctrl, 0, sizeof(ptg->ctrl));
    memset(ptg->ctrl_file, 0, sizeof(ptg->ctrl_file));

    ptg->sock_fd = -1;
    memset(ptg->sock_addr, 0, sizeof(ptg->sock_addr));

    ptg->pid = ptg->level = 0;

    memset(&ptg->request, 0, sizeof(ptg->request));

    ptg->exc_time_table = NULL;
    ptg->exc_time_len = 0;

    pt_filter_ctr(&(ptg->pft));
}


/**
 * PHP Extension Function
 * --------------------
 */
PHP_MINIT_FUNCTION(tracing)
{
    ZEND_INIT_MODULE_GLOBALS(tracing, php_tracing_init_globals, NULL);
    REGISTER_INI_ENTRIES();

    if (!PTG(enable)) {
        return SUCCESS;
    }

    /* Replace executor */
#if PHP_VERSION_ID < 50500
    ori_execute = zend_execute;
    zend_execute = pt_execute;
#else
    ori_execute_ex = zend_execute_ex;
    zend_execute_ex = pt_execute_ex;
#endif
    ori_execute_internal = zend_execute_internal;
    zend_execute_internal = pt_execute_internal;

    /* Init exclusive time table */
    PTG(exc_time_len) = 4096;
    PTG(exc_time_table) = calloc(PTG(exc_time_len), sizeof(long));
    if (PTG(exc_time_table) == NULL) {
        php_error(E_ERROR, "Trace exclusive time table init failed");
        return FAILURE;
    }

    pt_chain_log_ctor(&PTG(pcl), PTG(chain_log_path));
    pt_intercept_ctor(&PTG(pit), &PTG(pct));

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(tracing)
{
    UNREGISTER_INI_ENTRIES();

    if (!PTG(enable)) {
        return SUCCESS;
    }

    /* Restore original executor */
#if PHP_VERSION_ID < 50500
    zend_execute = ori_execute;
#else
    zend_execute_ex = ori_execute_ex;
#endif
    zend_execute_internal = ori_execute_internal;

    /* Destroy exclusive time table */
    if (PTG(exc_time_table) != NULL) {
        free(PTG(exc_time_table));
    }

    /* Close ctrl module */
    PTD("Ctrl module close");
    pt_ctrl_close(&PTG(ctrl));

    /* Close comm module */
    if (PTG(sock_fd) != -1) {
        PTD("Comm socket close");
        pt_comm_close(PTG(sock_fd), NULL);
        PTG(sock_fd) = -1;
    }

    pt_chain_log_dtor(&PTG(pcl));
    pt_intercept_dtor(&PTG(pit));

    return SUCCESS;
}

PHP_RINIT_FUNCTION(tracing)
{
#if PHP_VERSION_ID >= 70000 && defined(COMPILE_DL_TRACING) && defined(ZTS)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
    if (!PTG(enable)) {
        return SUCCESS;
    }

    /* Anything needs pid, init here */
    if (PTG(pid) == 0) {
        PTG(pid) = getpid();
    }
    PTG(level) = 0;

    /* Check ctrl module */
    //handle_command();

    pt_chain_ctor(&PTG(pct), &PTG(pcl), PTG(service_name));
    pt_intercept_init(&PTG(pit));
    pt_chain_log_init(&PTG(pcl));

    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(tracing)
{
    if (!PTG(enable)) {
        return SUCCESS;
    }

    pt_chain_dtor(&PTG(pct));
    if(PTG(pct).pch.is_sampled == 1) {
        pt_chain_log_flush(&PTG(pcl));
    }
    pt_intercept_uninit(&PTG(pit));

    return SUCCESS;
}

PHP_MINFO_FUNCTION(tracing)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "tracing support", "enabled");
    php_info_print_table_end();

    DISPLAY_INI_ENTRIES();
}


/**
 * Trace Interface
 * --------------------
 */
PHP_FUNCTION(trace_chain_truncate)
{      
    /* dtor and flush log */
    pt_chain_dtor(&PTG(pct));
    pt_chain_log_flush(&PTG(pcl));

    /* ctor and init */
    pt_chain_ctor(&PTG(pct), &PTG(pcl), PTG(service_name));
    pt_chain_log_init(&PTG(pcl));
}

/**
 * Obtain zend function
 * -------------------
 */
static inline zend_function *obtain_zend_function(zend_bool internal, zend_execute_data *ex, zend_op_array *op_array TSRMLS_DC)
{
#if PHP_VERSION_ID < 50500
    if (internal || ex) {
        return ex->function_state.function;
    } else {
        return (zend_function *) op_array;
    }
#elif PHP_VERSION_ID < 70000
    return ex->function_state.function;
#else
    return ex->func;
#endif
}

/**
 * Trace Load func and class name
 * --------------------- 
 */
static void load_class_func_name(pt_frame_t *frame)
{
     
}

/**
 * Trace Manipulation of Frame
 * --------------------
 */
static void frame_build(pt_frame_t *frame, zend_bool internal, unsigned char type, zend_execute_data *caller, zend_execute_data *ex, zend_op_array *op_array TSRMLS_DC)
{
    unsigned int i;
    zval **args;
    zend_function *zf;

    /* init */
    memset(frame, 0, sizeof(pt_frame_t));

#if PHP_VERSION_ID < 50500
    if (internal || ex) {
        op_array = ex->op_array;
    }
#endif

    /* load origin data */
    frame->internal = internal;
    frame->caller = caller;
    frame->ex = ex;
    frame->op_array = op_array;

    /* zend function */
    zf = obtain_zend_function(internal, ex, op_array);

    /* types, level */
    frame->type = type;
    frame->functype = internal ? PT_FUNC_INTERNAL : 0x00;
    frame->level = PTG(level);

    /* args init */
    args = NULL;
    frame->arg_count = 0;
    frame->args = NULL;
    frame->function = NULL;
    frame->class = NULL;

    /* names */
    if (zf->common.function_name) {
        /* functype, class name */
#if PHP_VERSION_ID < 70000
        if (caller && P7_EX_OBJ(caller)) {
#else
        if (ex && P7_EX_OBJ(ex)) {
#endif
            frame->functype |= PT_FUNC_MEMBER;
            /* User care about which method is called exactly, so use
             * zf->common.scope->name instead of ex->object->name. */
            if (zf->common.scope) {
                frame->class = sdsnew(P7_STR(zf->common.scope->name));
            } else {
                /* TODO zend uses zend_get_object_classname() in
                 * debug_print_backtrace() */
                php_error(E_WARNING, "Trace catch a entry with ex->object but without zf->common.scope");
            }
        } else if (zf->common.scope) {
            frame->functype |= PT_FUNC_STATIC;
            frame->class = sdsnew(P7_STR(zf->common.scope->name));
        } else {
            frame->functype |= PT_FUNC_NORMAL;
        }

        /* function name */
        if (strcmp(P7_STR(zf->common.function_name), "{closure}") == 0) {
            frame->function = sdscatprintf(sdsempty(), "{closure:%s:%d-%d}", P7_STR(zf->op_array.filename), zf->op_array.line_start, zf->op_array.line_end);
        } else if (strcmp(P7_STR(zf->common.function_name), "__lambda_func") == 0) {
            frame->function = sdscatprintf(sdsempty(), "{lambda:%s}", P7_STR(zf->op_array.filename));
#if PHP_VERSION_ID >= 50414
        } else if (zf->common.scope && zf->common.scope->trait_aliases) {
            /* Use trait alias instead real function name.
             * There is also a bug "#64239 Debug backtrace changed behavior
             * since 5.4.10 or 5.4.11" about this
             * https://bugs.php.net/bug.php?id=64239.*/
            frame->function = sdsnew(P7_STR(zend_resolve_method_name(P7_EX_OBJ(ex) ? P7_EX_OBJCE(ex) : zf->common.scope, zf)));
#endif
        } else {
            frame->function = sdsnew(P7_STR(zf->common.function_name));
        }

        /* args */
#if PHP_VERSION_ID < 50300
        /* TODO support fetching arguments in backtrace */
        if (EG(argument_stack).top >= 2) {
            frame->arg_count = (int)(zend_uintptr_t) *(EG(argument_stack).top_element - 2);
            args = (zval **)(EG(argument_stack).top_element - 2 - frame->arg_count);
        }
#elif PHP_VERSION_ID < 70000
        if (caller && caller->function_state.arguments) {
            frame->arg_count = (int)(zend_uintptr_t) *(caller->function_state.arguments);
            args = (zval **)(caller->function_state.arguments - frame->arg_count);
        }
#else
        frame->arg_count = ZEND_CALL_NUM_ARGS(ex);
#endif
        if (frame->arg_count > 0) {
            frame->args = calloc(frame->arg_count, sizeof(sds));
        }

        frame->object = P7_EX_OBJ_ZVAL(ex);

#if PHP_VERSION_ID < 70000
        for (i = 0; i < frame->arg_count; i++) {
            frame->args[i] = repr_zval(args[i], 32 TSRMLS_CC);
        }
        frame->ori_args = args;
#else
        if (frame->arg_count) {
            i = 0;
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
            frame->ori_args = p;
            while(i < frame->arg_count) {
                frame->args[i++] = repr_zval(p++, 32);
            }
        }
#endif

    } else {
        int add_filename = 1;
        long ev = 0;

#if ZEND_EXTENSION_API_NO < 220100525
        if (caller) {
            ev = caller->opline->op2.u.constant.value.lval;
        } else if (op_array && op_array->opcodes) {
            ev = op_array->opcodes->op2.u.constant.value.lval;
        }
#elif PHP_VERSION_ID < 70000
        if (caller) {
            ev = caller->opline->extended_value;
        } else if (op_array && op_array->opcodes) {
            ev = op_array->opcodes->extended_value;
        }
#else
        if (caller && caller->opline) {
            ev = caller->opline->extended_value;
        }
#endif

        /* special user function */
        switch (ev) {
            case ZEND_INCLUDE_ONCE:
                frame->functype |= PT_FUNC_INCLUDE_ONCE;
                frame->function = "include_once";
                break;
            case ZEND_REQUIRE_ONCE:
                frame->functype |= PT_FUNC_REQUIRE_ONCE;
                frame->function = "require_once";
                break;
            case ZEND_INCLUDE:
                frame->functype |= PT_FUNC_INCLUDE;
                frame->function = "include";
                break;
            case ZEND_REQUIRE:
                frame->functype |= PT_FUNC_REQUIRE;
                frame->function = "require";
                break;
            case ZEND_EVAL:
                frame->functype |= PT_FUNC_EVAL;
                frame->function = "{eval}"; /* TODO add eval code */
                add_filename = 0;
                break;
            default:
                /* should be function main */
                frame->functype |= PT_FUNC_NORMAL;
                frame->function = "{main}";
                add_filename = 0;
                break;
        }
        frame->function = sdsnew(frame->function);
        if (add_filename) {
            frame->arg_count = 1;
            frame->args = calloc(frame->arg_count, sizeof(sds));
            frame->args[0] = sdscatrepr(sdsempty(), P7_STR(zf->op_array.filename), strlen(P7_STR(zf->op_array.filename)));
        }
    }

#if PHP_VERSION_ID >= 70000
    /* FIXME Sometimes execute_data->opline can be a interger NOT pointer.
     * I dont know how to handle it, this just make it works. */
    //if (caller && caller->opline && caller->prev_execute_data &&
    //        caller->func && caller->func->op_array.opcodes == NULL) {
    //    caller = caller->prev_execute_data;
    //}

    ///* skip internal handler */
    //if (caller && caller->opline && caller->prev_execute_data &&
    //        caller->opline->opcode != ZEND_DO_FCALL &&
    //        caller->opline->opcode != ZEND_DO_ICALL &&
    //        caller->opline->opcode != ZEND_DO_UCALL &&
    //        caller->opline->opcode != ZEND_DO_FCALL_BY_NAME &&
    //        caller->opline->opcode != ZEND_INCLUDE_OR_EVAL) {
    //    caller = caller->prev_execute_data;
    //}
#endif

    /* lineno
     * The method we try to detect line number and filename is different
     * between Zend's debug_backtrace().
     * Because 1. Performance, so we won't use loop to find the valid op_array.
     * 2. And still want to catch internal function call, such as
     * call_user_func().  */
    //if (caller && caller->opline) {
    //    frame->lineno = caller->opline->lineno;
    //} else if (caller && caller->prev_execute_data && caller->prev_execute_data->opline) {
    //    frame->lineno = caller->prev_execute_data->opline->lineno; /* try using prev */
    //} else if (op_array && op_array->opcodes) {
    //    frame->lineno = op_array->opcodes->lineno;
    ///* Uncomment to use definition lineno if entry lineno is null, but we won't :P
    // * } else if (caller != EG(current_execute_data) && EG(current_execute_data)->opline) {
    // *     frame->lineno = EG(current_execute_data)->opline->lineno; [> try using current <]
    // */
    //} else {
    //    frame->lineno = 0;
    //}

    /* filename */
#if PHP_VERSION_ID < 70000
    //if (caller && caller->op_array) {
    //    op_array = caller->op_array;
    //} else if (caller && caller->prev_execute_data && caller->prev_execute_data->op_array) {
    //    op_array = caller->prev_execute_data->op_array; /* try using prev */
    //}
#else
    //if (caller->func && ZEND_USER_CODE(caller->func->common.type)) {
    //    op_array = &(caller->func->op_array);
    //} else if (caller->prev_execute_data && caller->prev_execute_data->func &&
    //        ZEND_USER_CODE(caller->prev_execute_data->func->common.type)) {
    //    op_array = &(caller->prev_execute_data->func->op_array); /* try using prev */
    //}
#endif

    /* Same as upper
     * } else if (caller != EG(current_execute_data) && EG(current_execute_data)->op_array) {
     *     op_array = EG(current_execute_data)->op_array [> try using current <]
     * }
     */
    //if (op_array) {
    //    frame->filename = sdsnew(P7_STR(op_array->filename));
    //} else {
    //    frame->filename = NULL;
    //}
    rand64hex(&frame->span_id);
}

#if PHP_VERSION_ID < 70000
static void frame_set_retval(pt_frame_t *frame, zend_bool internal, zend_execute_data *ex, zend_fcall_info *fci TSRMLS_DC)
{
    zval *retval = NULL;

    if (internal) {
        /* Ensure there is no exception occurs before fetching return value.
         * opline would be replaced by the Exception's opline if exception was
         * thrown which processed in function zend_throw_exception_internal().
         * It may cause a SEGMENTATION FAULT if we get the return value from a
         * exception opline. */
#if PHP_VERSION_ID >= 50500
        if (fci != NULL) {
            retval = *fci->retval_ptr_ptr;
        } else if (ex->opline && !EG(exception)) {
            retval = EX_TMP_VAR(ex, ex->opline->result.var)->var.ptr;
        }
#else
        if (ex->opline && !EG(exception)) {
#if PHP_VERSION_ID < 50400
            retval = ((temp_variable *)((char *) ex->Ts + ex->opline->result.u.var))->var.ptr;
#else
            retval = ((temp_variable *)((char *) ex->Ts + ex->opline->result.var))->var.ptr;
#endif
        }
#endif
    } else if (*EG(return_value_ptr_ptr)) {
        retval = *EG(return_value_ptr_ptr);
    }

    if (retval) {
        frame->retval = repr_zval(retval, 32 TSRMLS_CC);
        frame->ori_ret = retval;
    }
}
#endif

/**
 * Trace Misc Function
 * --------------------
 */
static sds repr_zval(zval *zv, int limit TSRMLS_DC)
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

static void handle_error(TSRMLS_D)
{
    /* retry once if ctrl bit still ON */
    if (PTG(sock_fd) != -1) {
        PTD("Comm socket retry connect to %s", PTG(sock_addr));
        PTG(sock_fd) = pt_comm_connect(PTG(sock_addr));
        if (PTG(sock_fd) != -1) {
            PTD("Connect to %s successful", PTG(sock_addr));
            return;
        }
    }

    /* Inactive ctrl module */
    PTD("Ctrl set inactive");
    CTRL_SET_INACTIVE();

    /* Close comm module */
    if (PTG(sock_fd) != -1) {
        PTD("Comm socket close");
        pt_comm_close(PTG(sock_fd), NULL);
        PTG(sock_fd) = -1;
    }

    /* Destroy filter struct */
    pt_filter_dtr(&PTG(pft));
}

static void handle_command(void)
{
    int msg_type;
    pt_comm_message_t *msg;

    /* Open comm socket */
    if (PTG(sock_fd) == -1) {
        PTD("Comm socket connect to %s", PTG(sock_addr));
        PTG(sock_fd) = pt_comm_connect(PTG(sock_addr));
        if (PTG(sock_fd) == -1) {
            PTD("Connect to %s failed, errmsg: %s", PTG(sock_addr), strerror(errno));
            handle_error(TSRMLS_C);
            return;
        }
    }

    /* Handle message */
    while (1) {
        msg_type = pt_comm_recv_msg(PTG(sock_fd), &msg);
        PTD("recv message type: 0x%08x len: %d", msg_type, msg->len);

        switch (msg_type) {
            case PT_MSG_PEERDOWN:
            case PT_MSG_ERR_SOCK:
            case PT_MSG_ERR_BUF:
            case PT_MSG_INVALID:
                PTD("recv message error errno: %d errmsg: %s", errno, strerror(errno));
                handle_error(TSRMLS_C);
                return;

            case PT_MSG_EMPTY:
                PTD("handle EMPTY");
                return;

            default:
                php_error(E_NOTICE, "Trace unknown message received with type 0x%08x", msg->type);
                break;
        }
    }
}


/**
 * Trace Executor Replacement
 * --------------------
 */
#if PHP_VERSION_ID < 50500
ZEND_API void pt_execute_core(int internal, zend_execute_data *execute_data, zend_op_array *op_array, int rvu TSRMLS_DC)
#elif PHP_VERSION_ID < 70000
ZEND_API void pt_execute_core(int internal, zend_execute_data *execute_data, zend_fcall_info *fci, int rvu TSRMLS_DC)
#else
ZEND_API void pt_execute_core(int internal, zend_execute_data *execute_data, zval *return_value)
#endif
{
    zend_bool dobailout = 0;
    zend_execute_data *caller = execute_data;
#if PHP_VERSION_ID < 70000
    zval *retval = NULL;
#else
    zval retval;
#endif
    pt_frame_t frame;

#if PHP_VERSION_ID >= 70000
    if (execute_data->prev_execute_data) {
        caller = execute_data->prev_execute_data;
    }
#elif PHP_VERSION_ID >= 50500
    /* In PHP 5.5 and later, execute_data is the data going to be executed, not
     * the entry point, so we switch to previous data. The internal function is
     * a exception because it's no need to execute by op_array. */
    if (!internal && execute_data->prev_execute_data) {
        caller = execute_data->prev_execute_data;
    }
#endif

    /* Assigning to a LOCAL VARIABLE at begining to prevent value changed
     * during executing. And whether send frame mesage back is controlled by
     * GLOBAL VALUE and LOCAL VALUE both because comm-module may be closed in
     * recursion and sending on exit point will be affected. */

    PTG(level)++;
#if PHP_VERSION_ID < 50500
    zend_function *zf = obtain_zend_function(internal, execute_data, op_array);
#else 
    zend_function *zf = obtain_zend_function(internal, execute_data, NULL);
#endif

    zend_bool match_intercept = 0; 
    pt_interceptor_ele_t *i_ele;
    char *class_name = (zf->common.scope != NULL && zf->common.scope->name != NULL)  ? P7_STR(zf->common.scope->name) : NULL;
    char *function_name = zf->common.function_name == NULL ? NULL : P7_STR(zf->common.function_name);
    match_intercept = pt_intercept_hit(&PTG(pit), &i_ele, class_name, function_name);

    if (match_intercept) {
#if PHP_VERSION_ID < 50500
        frame_build(&frame, internal, PT_FRAME_ENTRY, caller, execute_data, op_array TSRMLS_CC);
#else
        frame_build(&frame, internal, PT_FRAME_ENTRY, caller, execute_data, NULL TSRMLS_CC);
#endif

        /* Register return value ptr */
#if PHP_VERSION_ID < 70000
        if (!internal && EG(return_value_ptr_ptr) == NULL) {
            EG(return_value_ptr_ptr) = &retval;
        }
#else
        if (!internal && execute_data->return_value == NULL) {
            ZVAL_UNDEF(&retval);
            Z_VAR_FLAGS(retval) = 0;
            execute_data->return_value = &retval;
        }
#endif

        frame.inc_time = pt_time_usec();
        frame.entry_time = frame.inc_time;
        i_ele->capture == NULL ? NULL : i_ele->capture(&PTG(pit), &frame);  
    }

    /* Call original under zend_try. baitout will be called when exit(), error
     * occurs, exception thrown and etc, so we have to catch it and free our
     * resources. */
    zend_try {
#if PHP_VERSION_ID < 50500
        if (internal) {
            if (ori_execute_internal) {
                ori_execute_internal(execute_data, rvu TSRMLS_CC);
            } else {
                execute_internal(execute_data, rvu TSRMLS_CC);
            }
        } else {
            ori_execute(op_array TSRMLS_CC);
        }
#elif PHP_VERSION_ID < 70000
        if (internal) {
            if (ori_execute_internal) {
                ori_execute_internal(execute_data, fci, rvu TSRMLS_CC);
            } else {
                execute_internal(execute_data, fci, rvu TSRMLS_CC);
            }
        } else {
            ori_execute_ex(execute_data TSRMLS_CC);
        }
#else
        if (internal) {
            if (ori_execute_internal) {
                ori_execute_internal(execute_data, return_value);
            } else {
                execute_internal(execute_data, return_value);
            }
        } else {
            ori_execute_ex(execute_data);
        }
#endif
    } zend_catch {
        dobailout = 1;
        /* call zend_bailout() at the end of this function, we still want to
         * send message. */
    } zend_end_try();

    if (match_intercept && PTG(pct).pch.is_sampled == 1) {
        long current_time = pt_time_usec(); 
        frame.inc_time = current_time - frame.inc_time;
        frame.exit_time = current_time;

        /* Calculate exclusive time */
        if (PTG(level) + 1 < PTG(exc_time_len)) {
            PTG(exc_time_table)[PTG(level)] += frame.inc_time;
            frame.exc_time = frame.inc_time - PTG(exc_time_table)[PTG(level) + 1];
            PTG(exc_time_table)[PTG(level) + 1] = 0;
        }

        if (!dobailout) {
#if PHP_VERSION_ID < 50500
            frame_set_retval(&frame, internal, execute_data, NULL TSRMLS_CC);
#elif PHP_VERSION_ID < 70000
            frame_set_retval(&frame, internal, execute_data, fci TSRMLS_CC);
#else
            if (return_value) { /* internal */
                frame.retval = repr_zval(return_value, 32);
            } else if (execute_data->return_value) { /* user function */
                frame.retval = repr_zval(execute_data->return_value, 32);
            }
#endif
        }
        frame.type = PT_FRAME_EXIT;
        i_ele->record == NULL ? NULL : i_ele->record(&PTG(pit), &frame);  

#if PHP_VERSION_ID < 70000
        /* Free return value */
        if (!internal && retval != NULL) {
            zval_ptr_dtor(&retval);
            EG(return_value_ptr_ptr) = NULL;
        }
#endif
        pt_type_destroy_frame(&frame);
        efree(frame.span_id);
    }

    PTG(level)--;

    if (dobailout) {
        zend_bailout();
    }
}

#if PHP_VERSION_ID < 50500
ZEND_API void pt_execute(zend_op_array *op_array TSRMLS_DC)
{
    pt_execute_core(0, EG(current_execute_data), op_array, 0 TSRMLS_CC);
}

ZEND_API void pt_execute_internal(zend_execute_data *execute_data, int return_value_used TSRMLS_DC)
{
    pt_execute_core(1, execute_data, NULL, return_value_used TSRMLS_CC);
}
#elif PHP_VERSION_ID < 70000
ZEND_API void pt_execute_ex(zend_execute_data *execute_data TSRMLS_DC)
{
    pt_execute_core(0, execute_data, NULL, 0 TSRMLS_CC);
}

ZEND_API void pt_execute_internal(zend_execute_data *execute_data, zend_fcall_info *fci, int return_value_used TSRMLS_DC)
{
    pt_execute_core(1, execute_data, fci, return_value_used TSRMLS_CC);
}
#else
ZEND_API void pt_execute_ex(zend_execute_data *execute_data)
{
    pt_execute_core(0, execute_data, NULL);
}

ZEND_API void pt_execute_internal(zend_execute_data *execute_data, zval *return_value)
{
    pt_execute_core(1, execute_data, return_value);
}
#endif
