#include <zlog.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <unistd.h>

#include "log.h"


#define LOG_CONF "/etc/ceph/t2store_cachelog.conf"
#define NAME_MAX 255

#define LOG_PAT_LEN 24
#define LOG_PAT "%s/ceph-cache.osd.%s.log"

int g_log_level = ZLOG_LEVEL_INFO;

void set_log_level(int level)
{
  g_log_level = level;
}

void log_init(const char *log_path, const char *log_instant)
{
  char env_val[NAME_MAX + 1] = {0};

  if (strlen(log_path) > NAME_MAX - LOG_PAT_LEN)
    assert("log path too long" == 0);
  snprintf(env_val, NAME_MAX + 1, LOG_PAT, log_path, log_instant);
  setenv("LOG_FILENAME", env_val, 1);

  set_log_level(ZLOG_LEVEL_INFO);
  int rc = zlog_init(LOG_CONF);
  if (rc)
    assert("log init failed" == 0);
}

void log_fini()
{
  return zlog_fini();
}

void cache_zlog(const char *cat_type, const char *file, 
                size_t filelen, const char *func, size_t funclen, 
                long line, const int level,  const char *format, ...)
{
  if ( level < g_log_level) {
    return ;
  }
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

int log_reload()
{
  return zlog_reload(LOG_CONF);
}
