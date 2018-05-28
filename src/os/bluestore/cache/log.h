#ifndef CACHE_LOG_H
#define CACHE_LOG_H

#include <zlog.h>

extern int log_init(const char *log_path, const char *log_instant);
extern void set_loglevel(int level);
extern void log_fini();
extern void cache_zlog(const char *file, size_t filelen, const char *func, size_t funclen,
        long line, const int level,
        const char *format, ...);

#define CACHE_ERRORLOG(format, args...) \
        cache_zlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
        ZLOG_LEVEL_ERROR, format, ##args)

#define CACHE_WARNLOG(format, args...) \
        cache_zlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
        ZLOG_LEVEL_WARN, format, ##args)

#define CACHE_NOTICELOG(format, args...) \
        cache_zlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
        ZLOG_LEVEL_NOTICE, format, ##args)

#define CACHE_INFOLOG(format, args...) \
        cache_zlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
        ZLOG_LEVEL_INFO, format, ##args)

#define CACHE_DEBUGLOG(format, args...) \
        cache_zlog(__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
        ZLOG_LEVEL_DEBUG, format, ##args)

#endif


