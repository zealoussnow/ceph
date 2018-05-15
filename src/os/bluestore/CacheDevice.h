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

enum class IOCommand {
  READ_COMMAND,
  WRITE_COMMAND,
  FLUSH_COMMAND
};

class Task;

class CacheDevice : public BlockDevice {
  int fd_direct, fd_buffered, fd_cache;
  uint64_t size;
  uint64_t block_size;
  std::string path;
  std::string cache_path;
  FS *fs;
  bool aio, dio;

  Mutex debug_lock;
  interval_set<uint64_t> debug_inflight;

  std::atomic<bool> io_since_flush = {false};
  std::mutex flush_mutex;

  aio_queue_t aio_queue;
  bool aio_stop;

  struct AioCompletionThread : public Thread {
    CacheDevice *bdev;
    explicit AioCompletionThread(CacheDevice *b) : bdev(b) {}
    void *entry() override {
      bdev->_aio_thread();
      return NULL;
    }
  } aio_thread;

  std::atomic_int injecting_crash;

  Mutex queue_lock;
  std::queue<Task*> task_queue;
  std::atomic_bool queue_empty;
  Cond queue_cond;
  void queue_task(Task *t, uint64_t ops = 1);
  vector<AioCompletionThread*> aio_threads;

  void _aio_thread();
  int _aio_start();
  void _aio_stop();

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

public:
  CacheDevice(CephContext* cct, aio_callback_t cb, void *cbpriv);
  struct cache_context cache_ctx;
  void aio_submit(IOContext *ioc) override;
  aio_callback_t aio_callback;
  void *aio_callback_priv;
  std::atomic_ulong completed_op_seq, queue_op_seq;

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
  int write_cache_super(const std::string& path) override;
  int cache_init() override;

  void close() override;
};

#endif
