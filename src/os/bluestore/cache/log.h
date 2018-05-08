#ifndef _LOG_H
#define _LOG_H




enum cache_log_level {
        CACHE_LOG_ERROR,
        CACHE_LOG_WARN,
        CACHE_LOG_NOTICE,
        CACHE_LOG_INFO,
        CACHE_LOG_DEBUG,
};


void cache_log_open();
void cache_log_close();
void cache_log_set_level(enum cache_log_level level);
enum cache_log_level cache_log_get_level(void);

#define CACHE_ERRORLOG(...) cache_log(CACHE_LOG_ERROR, __FILE__, __LINE__, __func__, __VA_ARGS__); 
#define CACHE_WARNLOG(...) cache_log(CACHE_LOG_WARN, __FILE__, __LINE__, __func__, __VA_ARGS__); 
#define CACHE_NOTICELOG(...) cache_log(CACHE_LOG_NOTICE, __FILE__, __LINE__, __func__, __VA_ARGS__); 
#define CACHE_INFOLOG(...) cache_log(CACHE_LOG_INFO, __FILE__, __LINE__, __func__, __VA_ARGS__); 
#define CACHE_DEBUGLOG(...) cache_log(CACHE_LOG_INFO, __FILE__, __LINE__, __func__, __VA_ARGS__); 

#endif


