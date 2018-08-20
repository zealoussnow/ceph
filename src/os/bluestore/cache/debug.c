// SPDX-License-Identifier: GPL-2.0
/*
 * Assorted bcache debug code
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include <execinfo.h>
#include "bcache.h"
#include "btree.h"
#include "debug.h"
#include "extents.h"


#define STACK_DEPTH 100

__printf(2, 3)
bool bch_cache_set_error(struct cache_set *c, const char *fmt, ...)
{
  char formatted_buf[BUFSIZ];
  memset(formatted_buf, 0, BUFSIZ);
  va_list args;
  va_start(args, fmt);
  vsnprintf(formatted_buf, sizeof(formatted_buf), fmt, args);
  CACHE_ERRORLOG(NULL, "%s\n", formatted_buf);
  va_end(args);

  return true;
}

void dump_stack(){
  int j, nptrs;
  void *buffer[BUFSIZ];
  char **strings;

  nptrs = backtrace(buffer, STACK_DEPTH);
  strings = backtrace_symbols(buffer, nptrs);
  if (strings == NULL){
    CACHE_ERRORLOG(NULL, "Get backtrace info failure\n");
    exit(EXIT_FAILURE);
  }

  for (j = 0; j < nptrs; j++)
    CACHE_ERRORLOG(NULL, "%s\n", strings[j]);
  free(strings);
}
