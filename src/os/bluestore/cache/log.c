#include <zlog.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "log.h"

static bool log_crash_on_nospc = 0;
static int log_is_init = 0;
static int last_errcode = 0;

#define LOG_CONF "/etc/ceph/t2store_cachelog.conf"
#define NAME_MAX 255

#define LOG_PAT_LEN 24
#define LOG_PAT "%s/ceph-cache.osd.%s.log"

int g_log_level = 40;

int log_level_error = 100;
int log_level_warn = 80;
int log_level_notice = 60;
int log_level_info = 40;
int log_level_debug = 20;
int log_level_dump = 130;

char* log_conf_str = "[levels]\n"
"T2_DUMP   = 130, LOG_DEBUG\n"
"T2_ERROR  = 100, LOG_ERR\n"
"T2_WARN   = 80,  LOG_WARNING\n"
"T2_NOTICE = 60,  LOG_NOTICE\n"
"T2_INFO   = 40,  LOG_INFO\n"
"T2_DEBUG  = 20,  LOG_DEBUG\n"
"[formats]\n"
"logfile_format = \"[%c] %d.%us %t [%V] %U %m\"\n"
"[rules]\n"
"*.* \"%E(LOG_FILENAME)\" ;logfile_format\n";

void set_log_level(int level)
{
  g_log_level = level;
}


int t2ce_set_log_level(char *level)
{
  int log_level;

  if (!strcmp(level, "debug"))
    log_level = LOG_LEVEL_DEBUG;
  else if (!strcmp(level, "info"))
    log_level = LOG_LEVEL_INFO;
  else if (!strcmp(level, "notice"))
    log_level = LOG_LEVEL_NOTICE;
  else if (!strcmp(level, "warn"))
    log_level = LOG_LEVEL_WARN;
  else if (!strcmp(level, "error"))
    log_level = LOG_LEVEL_ERROR;
  else if (!strcmp(level, "dump"))
    log_level = LOG_LEVEL_DUMP;
  else
    return -1;

  CACHE_INFOLOG(NULL, "set log_level to: %s(%d)\n", level,log_level);
  set_log_level(log_level);
  return 0;

}

void log_load_level()
{
  int i = 0;
  zlog_iter_level_t *iter_level;
  while (1) {
    iter_level = zlog_iter_level(i);
    if (iter_level) {
      if (strcmp("T2_ERROR", iter_level->str_uppercase) == 0){
        log_level_error = iter_level->int_level;
      } else if (strcmp("T2_WARN", iter_level->str_uppercase) == 0){
         log_level_warn = iter_level->int_level;
      } else if (strcmp("T2_NOTICE", iter_level->str_uppercase) == 0){
         log_level_notice = iter_level->int_level;
      } else if (strcmp("T2_INFO", iter_level->str_uppercase) == 0){
         log_level_info = iter_level->int_level;
      } else if (strcmp("T2_DEBUG", iter_level->str_uppercase) == 0){
         log_level_debug = iter_level->int_level;
      } else if (strcmp("T2_DUMP", iter_level->str_uppercase) == 0){
         log_level_dump = iter_level->int_level;
      }
      i = iter_level->int_level + 1;
    } else {
      break;
    }
  }
}

void log_init(struct cache_context *ctx)
{
  char env_val[NAME_MAX + 1] = {0};
  char log_path[NAME_MAX + 1] = {0};
  const char *log_file = ctx->log_file;
  const char *log_instant = ctx->whoami;
  int rc;

  log_crash_on_nospc = ctx->log_crash_on_nospc;

  long path_nsep = strrchr(log_file, '/') - log_file;
  strncpy(log_path, log_file, path_nsep);

  if (strlen(log_path) > NAME_MAX - LOG_PAT_LEN)
    assert("log path too long" == 0);
  snprintf(env_val, NAME_MAX + 1, LOG_PAT, log_path, log_instant);
  setenv("LOG_FILENAME", env_val, 1);

  set_log_level(40);

  if (!log_is_init) {
    // Check log config file exsis.
    // If not, log init form log_conf_str.
    if( access( LOG_CONF, F_OK ) != -1 ) {
      rc = zlog_init(LOG_CONF);
    } else {
      rc = zlog_init_from_string(log_conf_str);
    }
    if (rc)
      assert("log init failed" == 0);
    log_is_init = 1;
    log_load_level();
  }
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

  va_list args;
  va_start(args, format);
  int rc = t2zlog(zc, file, filelen, func, funclen, line, level, format, args);
  if (rc != last_errcode) {
    if (rc < 0) {
      fprintf(stderr, "log output failed, errno: %d\n", errno);
      if (log_crash_on_nospc)
        assert("log output failed" == 0);
    }
    last_errcode = rc;
  }

  va_end(args);
}

int log_reload()
{
  int rc = 0;
  if( access( LOG_CONF, F_OK ) != -1 ) {
    rc = zlog_reload(LOG_CONF);
  } else {
    rc = zlog_reload_from_string(log_conf_str);
  }
  if (rc)
    assert("log reload failed" == 0);
  log_load_level();
  return rc;
}
