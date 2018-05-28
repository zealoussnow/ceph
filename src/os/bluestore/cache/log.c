#include <zlog.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <unistd.h>

#include "log.h"


#define LOG_CONF "/etc/ceph/t2store_cachelog.conf"


int 
log_init(const char *log_path, const char *log_instant)
{
  char env_val[BUFSIZ];
  memset(env_val, 0, BUFSIZ);
  snprintf(env_val, BUFSIZ, "%s/ceph-cache.osd.%s.log", log_path, log_instant);
  setenv("LOG_FILENAME", env_val, 1);

  int rc = zlog_init(LOG_CONF);
  if (rc) {
    return -1;
  }

  return 0;
}

void log_fini()
{
  return zlog_fini();
}

void cache_zlog(const char *cat_type, const char *file, 
                size_t filelen, const char *func, size_t funclen, 
                long line, const int level,  const char *format, ...)
{
  char formatted_buf[BUFSIZ];
  memset(formatted_buf, 0, BUFSIZ);

  va_list ap;
  va_start(ap, format);
  vsnprintf(formatted_buf, sizeof(formatted_buf), format, ap);

  zlog_category_t *zc = NULL;
  if (cat_type == NULL ) {
    zc = zlog_get_category(DEFAULT_CAT_TYPE);
  } else {
    zc = zlog_get_category(cat_type);
  }
  if (!zc) {
    zlog_fini();
    return ;
  }

  zlog(zc, file, filelen, func, funclen, line, level, "%s", formatted_buf);

  va_end(ap);
}
