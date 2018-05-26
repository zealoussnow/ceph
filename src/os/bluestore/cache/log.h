#ifndef CACHE_LOG_H
#define CACHE_LOG_H

#include <zlog.h>

extern int log_init(const char *log_path, const char *log_instant);
extern void log_fini();
extern void cache_zlog(const char *cat_type, const char *file, 
        size_t filelen, const char *func, size_t funclen, 
        long line, const int level, const char *format, ...);



#define DEFAULT_CAT_TYPE  "cache"
#define CAT_BTREE "btree"
#define CAT_JOURNAL "journal"
#define CAT_BSET "bset"
#define CAT_WRITEBACK "writeback"
#define CAT_GC "gc"
#define CAT_AIO "aio"
#define CAT_AIO_WRITE "aio_write"
#define CAT_READ "read"
#define CAT_WRITE "write"
#define CAT_ALLOC "alloc"
#define CAT_LIST "list"
#define BUILD_TREE "build_tree"
#define SEARCH_TREE "search_tree"

#define CACHE_ERRORLOG(cat_type, format, args...) \
        cache_zlog(cat_type, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
        ZLOG_LEVEL_ERROR, format, ##args)

#define CACHE_WARNLOG(cat_type, format, args...) \
        cache_zlog(cat_type, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
        ZLOG_LEVEL_WARN, format, ##args)

#define CACHE_NOTICELOG(cat_type, format, args...) \
        cache_zlog(cat_type, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
        ZLOG_LEVEL_NOTICE, format, ##args)

#define CACHE_INFOLOG(cat_type, format, args...) \
        cache_zlog(cat_type,__FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
        ZLOG_LEVEL_INFO, format, ##args)

#define CACHE_DEBUGLOG(cat_type, format, args...) \
        cache_zlog(cat_type, __FILE__, sizeof(__FILE__)-1, __func__, sizeof(__func__)-1, __LINE__, \
        ZLOG_LEVEL_DEBUG, format, ##args)

#endif


