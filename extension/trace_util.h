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

#ifndef TRACE_UTIL_H
#define TRACE_UTIL_H

#include <stdint.h>

#define CHAIN_HEADER_PREFIX "X-W-"
#define CHAIN_HEADER_PREFIX_LEN (sizeof(CHAIN_HEADER_PREFIX) - 1)
#define CHAIN_HEADER_TRACE_ID CHAIN_HEADER_PREFIX"TraceId"
#define CHAIN_HEADER_SPAN_ID CHAIN_HEADER_PREFIX"SpanId"
#define CHAIN_HEADER_PARENT_SPAN_ID CHAIN_HEADER_PREFIX"ParentSpanId"
#define CHAIN_HEADER_SAMPLED CHAIN_HEADER_PREFIX"Sampled"
#define CHAIN_HEADER_FLAGS CHAIN_HEADER_PREFIX"Flags"

#define CHAIN_REC_HEADER_PREFIX "HTTP_X_W_"
#define CHAIN_REC_TRACE_ID CHAIN_REC_HEADER_PREFIX"TRACEID"
#define CHAIN_REC_SPAN_ID CHAIN_REC_HEADER_PREFIX"SPANID"
#define CHAIN_REC_SAMPLED CHAIN_REC_HEADER_PREFIX"SAMPLED"
#define CHAIN_REC_FLAGS CHAIN_REC_HEADER_PREFIX"FLAGS"

#ifdef CHAIN_DEBUG
#define CHAIN_ERROR(format, ...) fprintf(stderr, "[PHPCHAIN] [file:%s] [line:%d]" format "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define CHAIN_ERROR(format, ...)
#endif

uint64_t rand_uint64(void);
void b2hex(char **output, const unsigned char *input, int input_len);
void bin2hex64(char **output, const uint64_t *input);
void ran64hex(char **output);

#endif
