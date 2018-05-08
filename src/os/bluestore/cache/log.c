


#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "log.h"

static const char *const cache_level_names[] = {
        [CACHE_LOG_ERROR]        = "ERROR",
        [CACHE_LOG_WARN]         = "WARNING",
        [CACHE_LOG_NOTICE]       = "NOTICE",
        [CACHE_LOG_INFO]         = "INFO",
        [CACHE_LOG_DEBUG]        = "DEBUG",
};

enum cache_log_level g_cache_log_level = CACHE_LOG_NOTICE;

#define MAX_TMPBUF 1024


void cache_log_open()
{
  openlog("t2cache", LOG_PID, LOG_LOCAL7);
}

void cache_log_close()
{
  closelog();
}

void cache_log_set_level(enum cache_log_level level)
{
  g_cache_log_level = level;
}

enum cache_log_level cache_log_get_level(void) 
{
  return g_cache_log_level;
}

void cache_log(enum cache_log_level level, const char *file, 
    const int line, const char *func, const char *format, ...)

{
  int severity = LOG_INFO;
  char buf[MAX_TMPBUF];
  va_list ap;

  switch (level) {
    case CACHE_LOG_ERROR:
      severity = LOG_ERR;
      break;
    case CACHE_LOG_WARN:
      severity = LOG_WARNING;
      break;
    case CACHE_LOG_NOTICE:
     severity = LOG_NOTICE;
     break;
    case CACHE_LOG_INFO:
    case CACHE_LOG_DEBUG:
      severity = LOG_INFO;
      break;
    }
    
  va_start(ap, format);
  vsnprintf(buf, sizeof(buf), format, ap);
  
  if (level <= g_cache_log_level) {
    /*syslog(severity, "%s:%4d:%s: *%s*: %s", file, line, func, cache_level_names[level], buf);*/
    syslog(severity, "%s: *%s*: %s", func, cache_level_names[level], buf);
  }

  va_end(ap);
}


/*int main()*/
/*{*/
  /*CACHE_DEBUGLOG(" xxxxxx debug xxxx \n");*/
  /*CACHE_ERRORLOG(" xxxxx error xxxxx \n");*/
  /*CACHE_WARNLOG(" xxxxx warn xxxxx \n");*/
  /*CACHE_NOTICELOG(" xxxx notic xxxxxx \n");*/
/*}*/
