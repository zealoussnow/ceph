// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_OSD_BLUESTORE_CACHEDEVICE_H
#define CEPH_OSD_BLUESTORE_CACHEDEVICE_H

#include <atomic>
#include <uuid/uuid.h>
#include <queue>

#include "os/fs/FS.h"
#include "include/interval_set.h"

#include "aio.h"
#include "BlockDevice.h"
#include "cache/libcache.h"
#include "common/perf_counters.h"

enum class IOCommand {
  READ_COMMAND,
  WRITE_COMMAND,
  FLUSH_COMMAND
};

class Task;

class CacheDevice : public BlockDevice, public md_config_obs_t  {
  int fd_direct, fd_buffered, fd_cache;
  uint64_t size;
  uint64_t block_size;
  std::string path;
  std::string cache_path;
  bool aio, dio;

  Mutex debug_lock;
  Mutex queue_lock;
  aio_queue_t aio_queue;
  interval_set<uint64_t> debug_inflight;

  std::atomic<bool> io_since_flush = {false};
  std::mutex flush_mutex;

  bool aio_stop;

  struct AioCompletionThread : public Thread {
    CacheDevice *bdev;
    explicit AioCompletionThread(CacheDevice *b) : bdev(b) {}
    void *entry() override {
      bdev->_aio_thread();
      return NULL;
    }
  };

  std::atomic_int injecting_crash;

  std::queue<Task*> task_queue;
  Cond queue_cond;
  void queue_task(Task *t, uint64_t ops = 1);
  vector<AioCompletionThread*> aio_threads;

  void _aio_writeback(struct ring_items *items);
  void _aio_writearound(struct ring_items *items);
  void _aio_writethrough(struct ring_items *items);
  void _aio_thread();
  int _aio_start();
  void _aio_stop();

  void _init_logger();
  void _shutdown_logger();

  void _aio_log_start(IOContext *ioc, uint64_t offset, uint64_t length);
  void _aio_log_finish(IOContext *ioc, uint64_t offset, uint64_t length);

  int _sync_write(uint64_t off, bufferlist& bl, bool buffered);

  int _lock();

  int direct_read_unaligned(uint64_t off, uint64_t len, char *buf);

  // stalled aio debugging
  aio_list_t debug_queue;
  std::mutex debug_queue_lock;
  aio_t *debug_oldest = nullptr;
  utime_t debug_stall_since;
  void debug_aio_link(aio_t& aio);
  void debug_aio_unlink(aio_t& aio);
  friend class CacheSocketHook;
  class CacheSocketHook *asok_hook;
  void asok_register();
  void asok_unregister();

public:
  CacheDevice(CephContext* cct, aio_callback_t cb, void *cbpriv);
  ~CacheDevice();
  struct cache_context cache_ctx;
  void aio_submit(IOContext *ioc) override;
  aio_callback_t aio_callback;
  void *aio_callback_priv;
  std::atomic_ulong completed_op_seq, queue_op_seq;
  PerfCounters *logger = nullptr;

  bool supported_cache() override { return true; }
  uint64_t get_size() const override {
    return size;
  }
  uint64_t get_block_size() const override {
    return block_size;
  }

  int collect_metadata(std::string prefix, map<std::string,std::string> *pm) const override;

  int read(uint64_t off, uint64_t len, bufferlist *pbl,
	   IOContext *ioc,
	   bool buffered) override;
  int aio_read(uint64_t off, uint64_t len, bufferlist *pbl,
	       IOContext *ioc) override;
  int read_random(uint64_t off, uint64_t len, char *buf, bool buffered) override;

  int write(uint64_t off, bufferlist& bl, bool buffered) override;
  int aio_write(uint64_t off, bufferlist& bl,
		IOContext *ioc,
		bool buffered) override;
  int flush() override;

  // for managing buffered readers/writers
  int invalidate_cache(uint64_t off, uint64_t len) override;
  int invalidate_region(uint64_t off, uint64_t len) override;
  int open(const std::string& path) override;
  int open(const std::string& path, const std::string& c_path) override;
  int mkfs(const std::string& path, const char *uuid_str) override;
  int init(const std::string& path, const char *fsid) override;

  void close() override;

  // handle conf change
  const char** get_tracked_conf_keys() const override;
  void handle_conf_change(const struct md_config_t *conf,
      const std::set <std::string> &changed) override;
  // handle new asok command for cache module
  bool asok_command(string admin_command, cmdmap_t& cmdmap, string format, ostream& ss);
};

#endif
