/*
 * SPDX-FileCopyrightText: 2025 2025 Thomas Alfroy
 * SPDX-FileCopyrightText: 2025 Thomas Alfroy
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bzlib.h>


#define DEFAULT "\x1B[0m"
#define RED     "\x1B[31m"
#define GREEN   "\x1B[32m"
#define YELLOW  "\x1B[33m"
#define BLUE    "\x1B[34m"
#define MAGENTA "\x1B[35m"
#define CYAN    "\x1B[36m"
#define WHITE   "\x1B[37m"

#define MIN(a,b) ((a < b) ? a : b)
#define MAX(a,b) ((a > b) ? a : b)

#define bool uint8_t

#define false   0
#define true    1


#define TEST(value,...)\
    if(!(value)) { \
        fprintf(stderr,RED "TEST FAILED - file : \"%s\", line : %d, function \"%s\". " MAGENTA  __VA_ARGS__ "\n" ,__FILE__,__LINE__,__func__); \
    }\
    else{\
        fprintf(stdout,GREEN "TEST PASS - file : \"%s\", line : %d, function \"%s\". " WHITE  __VA_ARGS__ "\n",__FILE__,__LINE__,__func__); \
    }

# define RAND(min, max) \
    ((rand()%(int)(((max))-(min)))+ (min))

#define UNUSED(x) (void)(x)

#define CHECK(x) \
  do { \
    if ((x) == -1) { \
      fprintf(stderr, "%s:%d: ", __func__, __LINE__); \
	  if(errno==0) errno=ECANCELED; \
      perror(#x); \
    } \
  } while (0)

#define MAX_BUFF 8192
#define MAX_NLRI 4096
#define MAX_SEND_BUFF  2048


#endif