#include <zlog.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <unistd.h>

#include "log.h"

const char *g_whoami = NULL;
const char *g_log_path = NULL;
int g_def_level = ZLOG_LEVEL_INFO;

#define LOG_CAT  "t2store_cache"
#define LOG_CONF "/tmp/t2store_cachelog.conf"
#define LOG_FILE "\"%M(logpath)/ceph-cache.osd.%M(whoami).log\""
#define CONF_LEN 512

static const char *default_log_format =
"[formats]\n"
"logfile_format = \"%d.%us %t [%V] %U %m\"\n"
"debug_format = \"%d.%us %t [%V] %F:%L %U %m\"\n"
"syslog_format  = \"%t [%V] %U %m\"\n"
"\n"
"[rules]\n"
"*.ERROR >syslog,LOG_USER;syslog_format\n"
"*.* " LOG_FILE " ;logfile_format\n";

int log_init(const char *log_path, const char *log_instant)
{
  g_log_path = log_path;
  g_whoami = log_instant;

  if (access(LOG_CONF, F_OK)) {
    FILE *fp = fopen(LOG_CONF, "wr");
    if (fp == NULL) {
      return -1;
    }
    fputs(default_log_format, fp);
    fclose(fp);
  }

  int rc = zlog_init(LOG_CONF);
  if (rc) {
    return -1;
  }
  zlog_put_mdc("whoami", g_whoami);
  zlog_put_mdc("logpath", g_log_path);

  return 0;
}

void log_fini()
{
  return zlog_fini();
}

void set_loglevel(int level)
{
  g_def_level = level;
}

void cache_zlog(const char *file, size_t filelen, const char *func, size_t funclen,
        long line, const int level,
        const char *format, ...)
{
  char buf[BUFSIZ];
  memset(buf, 0, BUFSIZ);

  va_list ap;
  va_start(ap, format);
  vsnprintf(buf, sizeof(buf), format, ap);

  zlog_category_t *zc = NULL;
  zc = zlog_get_category(LOG_CAT);
  if (!zc) {
    zlog_fini();
    return ;
  }

  if (level >= g_def_level)
    zlog(zc, file, filelen, func, funclen, line, level, format, buf); 

  va_end(ap);
}
