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

#ifndef PHP_TRACE_H
#define PHP_TRACE_H

extern zend_module_entry tracing_module_entry;
#define phpext_tracing_ptr &tracing_module_entry

#ifdef PHP_WIN32
#   define PHP_TRACING_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#   define PHP_TRACING_API __attribute__ ((visibility("default")))
#else
#   define PHP_TRACING_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

#include "trace_ctrl.h"
#include "trace_type.h"
#include "trace_version.h"
#include "trace_filter.h"

#include "trace_chain.h"
#include "trace_intercept.h"
#include "trace_util.h"

PHP_MINIT_FUNCTION(tracing);
PHP_MSHUTDOWN_FUNCTION(tracing);
PHP_RINIT_FUNCTION(tracing);
PHP_RSHUTDOWN_FUNCTION(tracing);
PHP_MINFO_FUNCTION(tracing);

/**
 * Declare any global variables you may need between the BEGIN and END macros
 * here:
 */
ZEND_BEGIN_MODULE_GLOBALS(tracing)
    zend_bool               enable;

    pt_ctrl_t               ctrl;               /* ctrl module */
    char                    ctrl_file[256];     /* ctrl filename */

    int                     sock_fd;            /* comm socket */
    char                    sock_addr[256];     /* comm address */

    pid_t                   pid;                /* process id */
    long                    level;              /* nesting level */

    pt_request_t            request;            /* current request info */

    long                   *exc_time_table;     /* exclusive time table */
    size_t                  exc_time_len;       /* length of time table */

    pt_filter_t             pft;                /* filter module */

    char                    *chain_log_path;    /* chain log path */
    char                    *service_name;      /* service name */
    pt_chain_t              pct;                /* chain module */
    pt_interceptor_t        pit;                /* chain intercept module */
    pt_chain_log_t          pcl;                /* chain log module */
ZEND_END_MODULE_GLOBALS(tracing)


#ifdef ZEND_ENGINE_3
    /* Always refer to the globals in your function as TRACING_G(variable). You are
     * encouraged to rename these macros something shorter, see examples in any
     * other php module directory. */
    #define PTG(v) ZEND_MODULE_GLOBALS_ACCESSOR(tracing, v)

    #if defined(ZTS) && defined(COMPILE_DL_TRACING)
    ZEND_TSRMLS_CACHE_EXTERN();
    #endif
#else
    /* In every utility function you add that needs to use variables in
     * php_tracing_globals, call TSRMLS_FETCH(); after declaring other variables used
     * by that function, or better yet, pass in TSRMLS_CC after the last function
     * argument and declare your utility function with TSRMLS_DC after the last
     * declared argument.  Always refer to the globals in your function as
     * TRACING_G(variable).  You are encouraged to rename these macros something
     * shorter, see examples in any other php module directory. */
    #ifdef ZTS
    #define PTG(v) TSRMG(tracing_globals_id, zend_tracing_globals *, v)
    #else
    #define PTG(v) (tracing_globals.v)
    #endif
#endif

#endif  /* PHP_TRACE_H */
