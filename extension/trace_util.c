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
    for (i = LOOP_COUNT; i > 0; i--) {
      r = r*(RAND_MAX + (uint64_t)1) + rand();
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
