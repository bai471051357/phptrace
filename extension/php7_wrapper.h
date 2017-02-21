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

#ifndef TRACE_PHP7_WRAPPER_H
#define TRACE_PHP7_WRAPPER_H

#if PHP_MAJOR_VERSION < 7

#define pt_zend_hash_update zend_hash_update
#define pt_zend_hash_add    zend_hash_add
#define P7_EX_OBJ(ex)       ex->object
#define P7_EX_OBJ_ZVAL(ex)  ex->object
#define P7_EX_OBJCE(ex)     Z_OBJCE_P(ex->object)
#define P7_EX_OPARR(ex)     ex->op_array
#define P7_STR(v)           v
#define P7_STR_LEN(v)       strlen(v)
#define PT_ZVAL_STRING      ZVAL_STRING
#define IS_TRUE             1
#define IS_FALSE            -1 
#define PT_MAKE_STD_ZVAL           MAKE_STD_ZVAL
#define PT_ALLOC_INIT_ZVAL         ALLOC_INIT_ZVAL
//#define PT_ARRAY_INIT(p)           PT_ALLOC_INIT_ZVAL(p);array_init(p)

#define PT_COPY_ZVAL_TO_STRING(z, p) do {               \
    ALLOC_INIT_ZVAL(z);                                 \
    ZVAL_ZVAL(z,p,1,0);                                 \
    convert_to_string(z);                               \
}while(0)
#define PT_FREE_COPY_STRING(z)      zval_dtor(z);
#define PT_FREE_ALLOC_ZVAL(p)

#define pt_add_assoc_string         add_assoc_string
#define pt_add_next_index_string    add_next_index_string

#define pt_zend_get_constant    zend_get_constant
#define pt_zval_ptr_dtor        zval_ptr_dtor
#define pt_zval_dtor            zval_dtor
#define pt_call_user_function   call_user_function
#define pt_zend_read_property   zend_read_property

static inline int PT_Z_TYPE_P(zval *z)
{
    if (Z_TYPE_P(z) == IS_BOOL) {
        if ((uint8_t)Z_LVAL_P(z) == 1) {
            return IS_TRUE;     
        } else {
            return IS_FALSE;
        }
    } else {
        return Z_TYPE_P(z);
    }
}
#define PT_Z_TYPE_PP(z)     PT_Z_TYPE_P(*z)

static inline int pt_zend_hash_find(HashTable *ht, char *k, int len, void **v)
{
    zval **tmp = NULL; 
    if (zend_hash_find(ht, k, len, (void **)&tmp) == SUCCESS) {
        *v = *tmp;
        return SUCCESS;
    } else {
        *v = NULL;
        return FAILURE;
    }
}

#define pt_zend_hash_zval_find pt_zend_hash_find

static inline int pt_zend_hash_index_find(HashTable *ht, ulong h, void **v)
{
    zval **tmp = NULL;
    if (zend_hash_index_find(ht, h, (void **)&tmp) == SUCCESS) {
        *v = *tmp;
        return SUCCESS;
    } else {
        *v = NULL;
        return FAILURE;
    }
}

#define pt_zend_hash_index_zval_find pt_zend_hash_index_find

static inline int pt_zend_hash_get_current_data(HashTable *ht, void **v)
{
    zval **tmp = NULL;
    if (zend_hash_get_current_data(ht, (void **)&tmp) == SUCCESS) {
        *v = *tmp;
        return SUCCESS;
    } else {
        *v = NULL;
        return FAILURE;
    }
}



#else 

#define P7_EX_OBJ(ex)               Z_OBJ(ex->This)
#define P7_EX_OBJ_ZVAL(ex)          &(ex->This)
#define P7_EX_OBJCE(ex)             Z_OBJCE(ex->This)
#define P7_EX_OPARR(ex)             (&(ex->func->op_array))
#define P7_STR(v)                   ZSTR_VAL(v)
#define P7_STR_LEN(v)               ZSTR_LEN(v)
#define PT_ZVAL_STRING(z,s,dup)     ZVAL_STRING(z,s)
#define Z_RESVAL(z)                 Z_RES_HANDLE(z)
#define Z_RESVAL_P(z)               Z_RES_HANDLE_P(z)

#define PT_MAKE_STD_ZVAL(p)                     zval _stack_zval_##p; p = &(_stack_zval_##p)
#define PT_ALLOC_INIT_ZVAL(p)                   do{p = emalloc(sizeof(zval)); bzero(p, sizeof(zval));}while(0)
#define pt_add_next_index_string(z,key,dup)     add_next_index_string(z,key)
#define PT_COPY_ZVAL_TO_STRING(z, p) do {               \
    PT_ALLOC_INIT_ZVAL(z);                              \
    ZVAL_DUP(z,p);                                      \
    convert_to_string(z);                               \
}while(0)
#define PT_FREE_COPY_STRING(z)      zval_dtor(z);
//#define PT_ARRAY_INIT(p)                array_init(p)
#define PT_FREE_ALLOC_ZVAL(p)       efree(p)

#define pt_zval_ptr_dtor(p)     zval_ptr_dtor(*p)
#define pt_zval_dtor(p)         zval_ptr_dtor(p)
#define pt_add_assoc_string(array, key, value, dup) add_assoc_string(array, key, value)
#define PT_Z_TYPE_P        Z_TYPE_P
#define PT_Z_TYPE_PP(z)    Z_TYPE_P(*z)

#define PT_PHP_MAX_PARAMS_NUM   20
static inline int pt_call_user_function(HashTable *ht, zval **obj, zval *function_name, zval *retval_ptr, uint32_t param_count, zval **params) 
{
    zval pass_params[PT_PHP_MAX_PARAMS_NUM];
    int i = 0;
    for(;i < param_count; i++){
        pass_params[i] = *params[i];
    }
    zval *pass_obj = obj ? *obj : NULL;
    return call_user_function(ht, pass_obj, function_name, retval_ptr, param_count, pass_params);
}

static inline zval *pt_zend_read_property(zend_class_entry *class_ptr, zval *obj, char *s, int len, int silent)
{
    zval rv;
    return zend_read_property(class_ptr, obj, s, len, silent, &rv);
}

static inline int pt_zend_get_constant(char *key, int len, zval *z)
{
    zend_string *key_str = zend_string_init(key, len, 0);
    zval *c = zend_get_constant(key_str); 
    zend_string_free(key_str);
    if (c != NULL) {
        ZVAL_COPY(z,c);
        return 1;
    } else {
        return 0;
    }
}

/***********************hash********************/
static inline int pt_zend_hash_find(HashTable *ht, char *k, int len, void **v)
{
    void *value = (void *)zend_hash_str_find_ptr(ht, k, len - 1);
    if (value == NULL) {
        return FAILURE;
    } else {
        *v = value;
        return SUCCESS;
    }
}

static inline int pt_zend_hash_zval_find(HashTable *ht, char *k, int len, void **v)
{
    zval *value = zend_hash_str_find(ht, k, len - 1);
    if (value == NULL) {
        return FAILURE;
    } else {
        *v = value;
        return SUCCESS;
    }
}


static inline int pt_zend_hash_index_find(HashTable *ht, ulong h, void **v)
{
    void **value = (void **)zend_hash_index_find_ptr(ht, h);
    if (value == NULL) {
        return FAILURE;
    } else {
        *v = *value;
        return SUCCESS;
    }
}

static inline int pt_zend_hash_index_zval_find(HashTable *ht, ulong h, void **v)
{
    zval *value = zend_hash_index_find(ht, h);
    if (value == NULL) {
        return FAILURE;
    } else {
        *v = value;
        return SUCCESS;
    }
}

static inline int pt_zend_hash_get_current_data(HashTable *ht, void **v)
{
    zval *value = zend_hash_get_current_data(ht);
    if (value == NULL) {
        return FAILURE;
    } else {
        *v = Z_PTR_P(value);
        return SUCCESS;
    }
}

static inline int pt_zend_hash_update(HashTable *ht, char *k, int len, void *val, int nDataSize, void **pDest)
{
    //return zend_hash_str_update_ptr(ht, k, len, val) ? SUCCESS : FAILURE;
    void **v = (void **)val;
    return zend_hash_str_update_ptr(ht, k, len - 1, *v) ? SUCCESS : FAILURE;
}

static inline int pt_zend_hash_add(HashTable *ht, char *k, int len, void *val, int datasize, void **pDest)
{
    void **v = (void **)val;
    return zend_hash_str_add_ptr(ht, k, len - 1, v) ? SUCCESS : FAILURE;
}
           
#endif
#endif

