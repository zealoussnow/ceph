// SPDX-License-Identifier: GPL-2.0
/*
 * Some low level IO code, and hacks for various block layer limitations
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include <unistd.h>

#include "bcache.h"
#include "bset.h"
#include "debug.h"

int sync_write( int fd, void *buf, size_t lenght, off_t offset)
{
  int ret=0;

  if ( pwrite(fd, buf, lenght, offset) != lenght ) {
    ret=-1;
  }

  return ret;
}

int sync_read( int fd, void *buf, size_t lenght, off_t offset)
{
  int ret=0;

  if ( pread(fd, buf, lenght, offset) != lenght ) {
    ret=-1;
  }

  return ret;
}
