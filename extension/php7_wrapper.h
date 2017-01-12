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

#define pt_zend_hash_update zend_hash_update
#define pt_zend_hash_add    zend_hash_add
#define P7_EX_OBJ(ex)       ex->object
#define P7_EX_OBJCE(ex)     Z_OBJCE_P(ex->object)
#define P7_EX_OPARR(ex)     ex->op_array
#define P7_STR(v)           v
#define P7_STR_LEN(v)       strlen(v)


#else 

#define P7_EX_OBJ(ex)   Z_OBJ(ex->This)
#define P7_EX_OBJCE(ex) Z_OBJCE(ex->This)
#define P7_EX_OPARR(ex) (&(ex->func->op_array))
#define P7_STR(v)       ZSTR_VAL(v)
#define P7_STR_LEN(v)   ZSTR_LEN(v)

static inline int pt_zend_hash_find(HashTable *ht, char *k, int len, void **v)
{
    zval *value = zend_hash_str_find(ht, k, len - 1);
    if (value == NULL) {
        return FAILURE;
    } else {
        *v = (void *)value;
        return SUCCESS;
    }
}

static inline int pt_zend_hash_update(HashTable *ht, char *k, int len, void *val, int size , void *ptr)
{
    return zend_hash_str_update(ht, k, len-1, val) ? SUCCESS : FAILURE;
}

static inline int pt_zend_hash_add(HashTable *ht, char *k, int len, void *pData, int datasize, void **pDest)
{
    zval **real_p = pData;
    return zend_hash_str_add(ht, k, len-1, *real_p) ? SUCCESS : FAILURE;
}
           
#endif
#endif

