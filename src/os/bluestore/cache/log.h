#ifndef CACHE_LOG_H
#define CACHE_LOG_H

#include <zlog.h>
#include "libcache.h"

extern int log_reload();
extern int t2ce_set_log_level(char *level);
extern void set_log_level(int level);
extern void log_init(struct cache_context *ctx);
extern void log_fini();
extern void cache_zlog(const char *cat_type, const char *file,
        size_t filelen, const char *func, size_t funclen,
        long line, const int level, const char *format, ...);

extern int log_level_error;
extern int log_level_warn;
extern int log_level_notice;
extern int log_level_info;
extern int log_level_debug;
extern int log_level_dump;

#define DEFAULT_CAT_TYPE  "cache"
#define CAT_BTREE "btree"
#define CAT_JOURNAL "journal"
#define CAT_PIN "pin"
#define CAT_BSET "bset"
#define CAT_WRITEBACK "writeback"
#define CAT_GC "gc"
#define CAT_WB "wb"
#define CAT_AIO "aio"
#define CAT_AIO_WRITE "aio_write"
#define CAT_READ "read"
#define CAT_WRITE "write"
#define CAT_ALLOC "alloc"
#define CAT_ALLOC_BUCKET "alloc_bucket"
#define CAT_RELEASE_BUCKET "release_bucket"
#define CAT_MARK_BUCKET "mark_bucket"
#define CAT_LIST "list"
#define CAT_BKEY "bkey"
#define CAT_EVENT "event"
#define BUILD_TREE "build_tree"
#define SEARCH_TREE "search_tree"
#define MOVINGGC "movinggc"
#define WRITEBACK "writeback"

#define LOG_LEVEL_ERROR  log_level_error
#define LOG_LEVEL_WARN   log_level_warn
#define LOG_LEVEL_NOTICE log_level_notice
#define LOG_LEVEL_INFO   log_level_info
#define LOG_LEVEL_DEBUG  log_level_debug
#define LOG_LEVEL_DUMP   log_level_dump

#define CACHE_ERRORLOG(cat_type, format, args...) \
        cache_zlog(cat_type, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
        LOG_LEVEL_ERROR, format, ##args)

#define CACHE_WARNLOG(cat_type, format, args...) \
        cache_zlog(cat_type, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
        LOG_LEVEL_WARN, format, ##args)

#define CACHE_NOTICELOG(cat_type, format, args...) \
        cache_zlog(cat_type, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
        LOG_LEVEL_NOTICE, format, ##args)

#define CACHE_INFOLOG(cat_type, format, args...) \
        cache_zlog(cat_type,__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
        LOG_LEVEL_INFO, format, ##args)

#define CACHE_DEBUGLOG(cat_type, format, args...) \
        cache_zlog(cat_type, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
        LOG_LEVEL_DEBUG, format, ##args)

#define CACHE_DUMPLOG(cat_type, format, args...) \
        cache_zlog(cat_type, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
        LOG_LEVEL_DUMP, format, ##args)

#endif


