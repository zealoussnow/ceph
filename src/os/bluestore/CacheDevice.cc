// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2014 Red Hat
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
//#include <blkid.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <uuid/uuid.h>

#include "CacheDevice.h"
#include "include/types.h"
#include "include/compat.h"
#include "include/stringify.h"
#include "common/errno.h"
#include "common/debug.h"
#include "common/blkdev.h"
#include "common/align.h"


#define dout_context cct
#define dout_subsys ceph_subsys_bdev
#undef dout_prefix
#define dout_prefix *_dout << "bdev(" << this << " " << path << ") "
uint64_t g_completion=0;
static constexpr uint32_t data_buffer_size = 8192;
static constexpr uint16_t inline_segment_num = 32;

struct IORequest {
  uint16_t cur_seg_idx = 0;
  uint16_t nseg;
  uint32_t cur_seg_left = 0;
  void *inline_segs[inline_segment_num];
  void **extra_segs = nullptr;
};

struct Task {
  CacheDevice *device;
  IOContext *ctx = nullptr;
  IOCommand command;
  uint64_t offset;
  uint64_t len;
  bufferlist write_bl;
  bufferlist read_bl;
  bufferptr read_ptr;
  std::function<void()> fill_cb;
  Task *next = nullptr;
  int64_t return_code;
  ceph::coarse_real_clock::time_point start;
  IORequest io_request;
  std::mutex lock;
  std::condition_variable cond;
  Task(CacheDevice *dev, IOCommand c, uint64_t off, uint64_t l, int64_t rc = 0)
    : device(dev), command(c), offset(off), len(l),
      return_code(rc),
      start(ceph::coarse_real_clock::now()) {}
  ~Task() {
    //assert(!io_request.nseg);
  }

#if 0
  void release_segs(SharedDriverQueueData *queue_data) {
    if (io_request.extra_segs) {
      for (uint16_t i = 0; i < io_request.nseg; i++)
        queue_data->data_buf_mempool.push_back(io_request.extra_segs[i]);
      delete io_request.extra_segs;
    } else if (io_request.nseg) {
      for (uint16_t i = 0; i < io_request.nseg; i++)
        queue_data->data_buf_mempool.push_back(io_request.inline_segs[i]);
    }
    io_request.nseg = 0;
  }
#endif

  void copy_to_buf(char *buf, uint64_t off, uint64_t len) {
      //pbl->append(read_bl);
    //read_bl.copy(off, len, static_cast<char*>(buf));
  }

  void io_wait() {
    std::unique_lock<std::mutex> l(lock);
    cond.wait(l);
  }

  void io_wake() {
    std::lock_guard<std::mutex> l(lock);
    cond.notify_all();
  }
};

CacheDevice::CacheDevice(CephContext* cct, aio_callback_t cb, void *cbpriv)
  : BlockDevice(cct),
    fd_direct(-1),
    fd_buffered(-1),
    size(0), block_size(0),
    fs(NULL), aio(false), dio(false),
    debug_lock("CacheDevice::debug_lock"),
        queue_lock("CacheDevice::queue_lock"),
        queue_op_seq(0),
        queue_empty(false),
        completed_op_seq(0),
    aio_queue(cct->_conf->bdev_aio_max_queue_depth),
    aio_callback(cb),
    aio_callback_priv(cbpriv),
    aio_stop(false),
    aio_thread(this),
    injecting_crash(0)
{
  cache_ctx.registered=false;
}

int CacheDevice::_lock()
{
  struct flock l;
  memset(&l, 0, sizeof(l));
  l.l_type = F_WRLCK;
  l.l_whence = SEEK_SET;
  int r = ::fcntl(fd_direct, F_SETLK, &l);
  if (r < 0)
    return -errno;
  return 0;
}

int CacheDevice::cache_init()
{
  int r = 0;
  cache_ctx.fd_cache=fd_cache;
  cache_ctx.fd_direct=fd_direct;
  cache_ctx.fd_buffered=fd_buffered;

  dout(1)<< __func__ << " lb cache_ctx.registered "<< cache_ctx.registered <<dendl;
  if (cache_ctx.registered)
    return r;
  //assert(cache_ctx.registered==true);
  //struct cache_context cache_ctx;
  r = T2Store_Cache_register_cache(&cache_ctx);

  return r;
}

int CacheDevice::write_cache_super(const std::string& path)
{
  int r = 0;
  unsigned block_size = 1;
  unsigned bucket_size = 1024;
  bool writeback = 0;
  bool discard = 0;
  bool wipe_bcache = 1;
  unsigned cache_replacement_policy = 0;
  uint64_t data_offset = 16;

  r = t2store_cache_write_cache_sb(path.c_str(), block_size, bucket_size,
                         writeback, discard, wipe_bcache,
                         cache_replacement_policy,
                         data_offset,false);
  return r;
}
#if 1
int CacheDevice::open(const string& p, const string& c_path)
{
  path = p;
  cache_path = c_path;
  int r = 0;
  fd_cache = ::open(cache_path.c_str(), O_RDWR);
  if (fd_cache < 0) {
    r = -errno;
    derr << __func__ << " open got: " << cpp_strerror(r) << dendl;
    return r;
  }

  fd_direct = ::open(path.c_str(), O_RDWR | O_DIRECT);
  if (fd_direct < 0) {
    r = -errno;
    derr << __func__ << " open got: " << cpp_strerror(r) << dendl;
    goto out_cache;
    return r;
  }

  fd_buffered = ::open(path.c_str(), O_RDWR);
  if (fd_buffered < 0) {
    r = -errno;
    derr << __func__ << " open got: " << cpp_strerror(r) << dendl;
    goto out_direct;
  }
  dio = true;
  aio = cct->_conf->bdev_aio;
  if (!aio) {
    assert(0 == "non-aio not supported");
  }

  // disable readahead as it will wreak havoc on our mix of
  // directio/aio and buffered io.
  r = posix_fadvise(fd_buffered, 0, 0, POSIX_FADV_RANDOM);
  if (r) {
    r = -r;
    derr << __func__ << " open got: " << cpp_strerror(r) << dendl;
    goto out_fail;
  }

  r = _lock();
  if (r < 0) {
    derr << __func__ << " failed to lock " << path << ": " << cpp_strerror(r)
         << dendl;
    goto out_fail;
  }

  struct stat st;
  r = ::fstat(fd_direct, &st);
  if (r < 0) {
    r = -errno;
    derr << __func__ << " fstat got " << cpp_strerror(r) << dendl;
    goto out_fail;
  }

  // Operate as though the block size is 4 KB.  The backing file
  // blksize doesn't strictly matter except that some file systems may
  // require a read/modify/write if we write something smaller than
  // it.
  block_size = cct->_conf->bdev_block_size;
  if (block_size != (unsigned)st.st_blksize) {
    dout(1) << __func__ << " backing device/file reports st_blksize "
            << st.st_blksize << ", using bdev_block_size "
            << block_size << " anyway" << dendl;
  }

  if (S_ISBLK(st.st_mode)) {
    int64_t s;
    r = get_block_device_size(fd_direct, &s);
    if (r < 0) {
      goto out_fail;
    }
    size = s;
  } else {
    size = st.st_size;
  }
  if (cct->_conf->get_val<bool>("bdev_inject_bad_size")) {
    derr << "injecting bad size; actual 0x" << std::hex << size
         << " but using 0x" << (size & ~block_size) << std::dec << dendl;
    size &= ~(block_size);
  }

  {
    char partition[PATH_MAX], devname[PATH_MAX];
    r = get_device_by_fd(fd_buffered, partition, devname, sizeof(devname));
    if (r < 0) {
      derr << "unable to get device name for " << path << ": "
           << cpp_strerror(r) << dendl;
      rotational = true;
    } else {
      dout(20) << __func__ << " devname " << devname << dendl;
      rotational = block_device_is_rotational(devname);
    }
  }

  r = _aio_start();
  if (r < 0) {
    goto out_fail;
  }
  fs = FS::create_by_fd(fd_direct);
  assert(fs);

  // round size down to an even block
  size &= ~(block_size - 1);

  dout(1) << __func__
          << " size " << size
          << " (0x" << std::hex << size << std::dec << ", "
          << pretty_si_t(size) << "B)"
          << " block_size " << block_size
          << " (" << pretty_si_t(block_size) << "B)"
          << " " << (rotational ? "rotational" : "non-rotational")
          << dendl;


  return 0;

 out_fail:
  VOID_TEMP_FAILURE_RETRY(::close(fd_buffered));
  fd_buffered = -1;
 out_direct:
  VOID_TEMP_FAILURE_RETRY(::close(fd_direct));
  fd_direct = -1;
 out_cache:
  VOID_TEMP_FAILURE_RETRY(::close(fd_cache));
  fd_cache = -1;
  return r;
}
#endif
int CacheDevice::open(const string& p)
{
  path = p;
  int r = 0;
  dout(1) << __func__ << " path " << path << dendl;

  fd_direct = ::open(path.c_str(), O_RDWR | O_DIRECT);
  if (fd_direct < 0) {
    r = -errno;
    derr << __func__ << " open got: " << cpp_strerror(r) << dendl;
    return r;
  }
  fd_buffered = ::open(path.c_str(), O_RDWR);
  if (fd_buffered < 0) {
    r = -errno;
    derr << __func__ << " open got: " << cpp_strerror(r) << dendl;
    goto out_direct;
  }
  dio = true;
  aio = cct->_conf->bdev_aio;
  if (!aio) {
    assert(0 == "non-aio not supported");
  }

  // disable readahead as it will wreak havoc on our mix of
  // directio/aio and buffered io.
  r = posix_fadvise(fd_buffered, 0, 0, POSIX_FADV_RANDOM);
  if (r) {
    r = -r;
    derr << __func__ << " open got: " << cpp_strerror(r) << dendl;
    goto out_fail;
  }

  r = _lock();
  if (r < 0) {
    derr << __func__ << " failed to lock " << path << ": " << cpp_strerror(r)
         << dendl;
    goto out_fail;
  }

  struct stat st;
  r = ::fstat(fd_direct, &st);
  if (r < 0) {
    r = -errno;
    derr << __func__ << " fstat got " << cpp_strerror(r) << dendl;
    goto out_fail;
  }

  // Operate as though the block size is 4 KB.  The backing file
  // blksize doesn't strictly matter except that some file systems may
  // require a read/modify/write if we write something smaller than
  // it.
  block_size = cct->_conf->bdev_block_size;
  if (block_size != (unsigned)st.st_blksize) {
    dout(1) << __func__ << " backing device/file reports st_blksize "
            << st.st_blksize << ", using bdev_block_size "
            << block_size << " anyway" << dendl;
  }

  if (S_ISBLK(st.st_mode)) {
    int64_t s;
    r = get_block_device_size(fd_direct, &s);
    if (r < 0) {
      goto out_fail;
    }
    size = s;
  } else {
    size = st.st_size;
  }
  if (cct->_conf->get_val<bool>("bdev_inject_bad_size")) {
    derr << "injecting bad size; actual 0x" << std::hex << size
         << " but using 0x" << (size & ~block_size) << std::dec << dendl;
    size &= ~(block_size);
  }

  {
    char partition[PATH_MAX], devname[PATH_MAX];
    r = get_device_by_fd(fd_buffered, partition, devname, sizeof(devname));
    if (r < 0) {
      derr << "unable to get device name for " << path << ": "
           << cpp_strerror(r) << dendl;
      rotational = true;
    } else {
      dout(20) << __func__ << " devname " << devname << dendl;
      rotational = block_device_is_rotational(devname);
    }
  }

  r = _aio_start();
  if (r < 0) {
    goto out_fail;
  }

  fs = FS::create_by_fd(fd_direct);
  assert(fs);

  // round size down to an even block
  size &= ~(block_size - 1);

  dout(1) << __func__
          << " size " << size
          << " (0x" << std::hex << size << std::dec << ", "
          << pretty_si_t(size) << "B)"
          << " block_size " << block_size
          << " (" << pretty_si_t(block_size) << "B)"
          << " " << (rotational ? "rotational" : "non-rotational")
          << dendl;
  return 0;

 out_fail:
  VOID_TEMP_FAILURE_RETRY(::close(fd_buffered));
  fd_buffered = -1;
 out_direct:
  VOID_TEMP_FAILURE_RETRY(::close(fd_direct));
  fd_direct = -1;
  return r;
}

void CacheDevice::close()
{
  dout(1) << __func__ << dendl;
  _aio_stop();

  assert(fs);
  delete fs;
  fs = NULL;

  assert(fd_direct >= 0);
  VOID_TEMP_FAILURE_RETRY(::close(fd_direct));
  fd_direct = -1;

  assert(fd_buffered >= 0);
  VOID_TEMP_FAILURE_RETRY(::close(fd_buffered));
  fd_buffered = -1;

  //assert(fd_cache >= 0);
  //VOID_TEMP_FAILURE_RETRY(::close(fd_cache));
  //fd_cache = -1;

  path.clear();
}

static string get_dev_property(const char *dev, const char *property)
{
  char val[1024] = {0};
  get_block_device_string_property(dev, property, val, sizeof(val));
  return val;
}

int CacheDevice::collect_metadata(string prefix, map<string,string> *pm) const
{
  (*pm)[prefix + "rotational"] = stringify((int)(bool)rotational);
  (*pm)[prefix + "size"] = stringify(get_size());
  (*pm)[prefix + "block_size"] = stringify(get_block_size());
  (*pm)[prefix + "driver"] = "CacheDevice";
  if (rotational) {
    (*pm)[prefix + "type"] = "hdd";
  } else {
    (*pm)[prefix + "type"] = "ssd";
  }

  struct stat st;
  int r = ::fstat(fd_buffered, &st);
  if (r < 0)
    return -errno;
  if (S_ISBLK(st.st_mode)) {
    (*pm)[prefix + "access_mode"] = "blk";
    char partition_path[PATH_MAX];
    char dev_node[PATH_MAX];
    int rc = get_device_by_fd(fd_buffered, partition_path, dev_node, PATH_MAX);
    switch (rc) {
    case -EOPNOTSUPP:
    case -EINVAL:
      (*pm)[prefix + "partition_path"] = "unknown";
      (*pm)[prefix + "dev_node"] = "unknown";
      break;
    case -ENODEV:
      (*pm)[prefix + "partition_path"] = string(partition_path);
      (*pm)[prefix + "dev_node"] = "unknown";
      break;
    default:
      {
        (*pm)[prefix + "partition_path"] = string(partition_path);
        (*pm)[prefix + "dev_node"] = string(dev_node);
        (*pm)[prefix + "model"] = get_dev_property(dev_node, "device/model");
        (*pm)[prefix + "dev"] = get_dev_property(dev_node, "dev");

        // nvme exposes a serial number
        string serial = get_dev_property(dev_node, "device/serial");
        if (serial.length()) {
          (*pm)[prefix + "serial"] = serial;
        }

        // nvme has a device/device/* structure; infer from that.  there
        // is probably a better way?
        string nvme_vendor = get_dev_property(dev_node, "device/device/vendor");
        if (nvme_vendor.length()) {
          (*pm)[prefix + "type"] = "nvme";
        }
      }
    }
  } else {
    (*pm)[prefix + "access_mode"] = "file";
    (*pm)[prefix + "path"] = path;
  }
  return 0;
}

int CacheDevice::flush()
{
  // protect flush with a mutex.  note that we are not really protecting
  // data here.  instead, we're ensuring that if any flush() caller
  // sees that io_since_flush is true, they block any racing callers
  // until the flush is observed.  that allows racing threads to be
  // calling flush while still ensuring that *any* of them that got an
  // aio completion notification will not return before that aio is
  // stable on disk: whichever thread sees the flag first will block
  // followers until the aio is stable.
  std::lock_guard<std::mutex> l(flush_mutex);

  bool expect = true;
  if (!io_since_flush.compare_exchange_strong(expect, false)) {
    dout(10) << __func__ << " no-op (no ios since last flush), flag is "
             << (int)io_since_flush.load() << dendl;
    return 0;
  }

  dout(10) << __func__ << " start" << dendl;
  if (cct->_conf->bdev_inject_crash) {
    ++injecting_crash;
    // sleep for a moment to give other threads a chance to submit or
    // wait on io that races with a flush.
    derr << __func__ << " injecting crash. first we sleep..." << dendl;
    sleep(cct->_conf->bdev_inject_crash_flush_delay);
    derr << __func__ << " and now we die" << dendl;
    cct->_log->flush();
    _exit(1);
  }
  utime_t start = ceph_clock_now();
  int r = ::fdatasync(fd_direct);
  utime_t end = ceph_clock_now();
  utime_t dur = end - start;
  if (r < 0) {
    r = -errno;
    derr << __func__ << " fdatasync got: " << cpp_strerror(r) << dendl;
    ceph_abort();
  }
  dout(5) << __func__ << " in " << dur << dendl;;
  return r;
}

int CacheDevice::_aio_start()
{
  if (aio) {
    dout(10) << __func__ << dendl;
    int r = aio_queue.init();
    if (r < 0) {
      if (r == -EAGAIN) {
        derr << __func__ << " io_setup(2) failed with EAGAIN; "
                << "try increasing /proc/sys/fs/aio-max-nr" << dendl;
      } else {
        derr << __func__ << " io_setup(2) failed: " << cpp_strerror(r) << dendl;
      }
        return r;
    }
    aio_thread.create("bstore_aio");
  }
  
  return 0;
}

void CacheDevice::_aio_stop()
{
  if (aio) {
    dout(10) << __func__ << dendl;
    aio_queue.shutdown();
    {
      Mutex::Locker l(queue_lock);
      aio_stop = true;
      queue_cond.Signal();
    }
    aio_thread.join();
    aio_stop = false;
  }

}

void io_complete(void *t)
{
  //printf("   CacheDevice io completion \n");
  Task *task = static_cast<Task*>(t);
  CacheDevice *cache_device = task->device;
  ++cache_device->completed_op_seq;
  IOContext *ctx = task->ctx;
  //printf("******** completion g_completion=%lu \n", g_completion);
  //g_completion++;
  assert(ctx != NULL);
  if (task->command == IOCommand::WRITE_COMMAND) {
    if (ctx->priv) {
      if (!--ctx->num_running) {
        //printf(" call bluestore aio completion \n");
        task->device->aio_callback(task->device->aio_callback_priv, ctx->priv);
        //printf(" call bluestore aio completion done\n");
      }
    } else {
      ctx->try_aio_wake();
    }
  delete task;
  } else if (task->command == IOCommand::READ_COMMAND) {
    //task->fill_cb();
    if(!task->return_code) {
      if (ctx->priv) {
        if (!--ctx->num_running) {
          task->device->aio_callback(task->device->aio_callback_priv, ctx->priv);
        }
      } else {
        ctx->try_aio_wake();
      }
    delete task;
    } else {
      task->return_code = 0;
        if (!--ctx->num_running) {
          task->io_wake();
        }
    }
  } else {
    assert(task->command == IOCommand::FLUSH_COMMAND);
    task->return_code = 0;
  }

}

void CacheDevice::_aio_thread()
{
  Task *t = nullptr;
  uint64_t off, len;
  void *data = nullptr;
  int r = 0;

  dout(10) << __func__ << " linbing " << dendl;
  while (true) {
    bool inflight = queue_op_seq.load() - completed_op_seq.load();
    for (; t; t = t->next) {
      off = t->offset;
      len = t->len;
      data = malloc(len);
      switch (t->command) {
        case IOCommand::WRITE_COMMAND:
        {
          dout(20) << __func__ << " write command issued " << off << "~" << len << dendl;
          auto blp = t->write_bl.begin();
          blp.copy(len, static_cast<char*>(data));
          // TODO submit data to cache module
          r = T2Store_Cache_aio_write(&cache_ctx, data, off, len, (void *)io_complete,(void *)t);
          if (r < 0) {
            derr << __func__ << " failed to do write command" << dendl;
            free(data);
            delete t;
            ceph_abort();
          }
          break;
        }
        case IOCommand::READ_COMMAND:
        {
          dout(20) << __func__ << " read command issued " << off << "~" << len << dendl;
          r = T2Store_Cache_aio_read(&cache_ctx, t->read_ptr.c_str(), off, len, (void *)io_complete,(void *)t);
          if (r < 0) {
            derr << __func__ << " failed to do read command" << dendl;
            free(data);
            delete t;
            ceph_abort();
          }
          break;
        }
        case IOCommand::FLUSH_COMMAND:
        {
          // TODO
          dout(20) << __func__ << " flush command issueed " << dendl;
          break;
        }
      }
    }
          
    if (!queue_empty.load()) {
      Mutex::Locker l(queue_lock);
      if (!task_queue.empty()) {
        t = task_queue.front();
        task_queue.pop();
      }

      if (!t) {
        queue_empty = true;
      }
    } else {
      // task queue is empty
      if (!inflight) {
        Mutex::Locker l(queue_lock);
        if (queue_empty.load()) {
          if (aio_stop) {
            break;
          }
        queue_cond.Wait(queue_lock);
        }
      }
    }
  }

  reap_ioc();
  dout(10) << __func__ << " end" << dendl;
}

void CacheDevice::_aio_log_start(
  IOContext *ioc,
  uint64_t offset,
  uint64_t length)
{
  dout(20) << __func__ << " 0x" << std::hex << offset << "~" << length
           << std::dec << dendl;
  if (cct->_conf->bdev_debug_inflight_ios) {
    Mutex::Locker l(debug_lock);
    if (debug_inflight.intersects(offset, length)) {
      derr << __func__ << " inflight overlap of 0x"
           << std::hex
           << offset << "~" << length << std::dec
           << " with " << debug_inflight << dendl;
      ceph_abort();
    }
    debug_inflight.insert(offset, length);
  }
}

void CacheDevice::debug_aio_link(aio_t& aio)
{
  if (debug_queue.empty()) {
    debug_oldest = &aio;
  }
  debug_queue.push_back(aio);
}

void CacheDevice::debug_aio_unlink(aio_t& aio)
{
  if (aio.queue_item.is_linked()) {
    debug_queue.erase(debug_queue.iterator_to(aio));
    if (debug_oldest == &aio) {
      if (debug_queue.empty()) {
        debug_oldest = nullptr;
      } else {
        debug_oldest = &debug_queue.front();
      }
      debug_stall_since = utime_t();
    }
  }
}

void CacheDevice::_aio_log_finish(
  IOContext *ioc,
  uint64_t offset,
  uint64_t length)
{
  dout(20) << __func__ << " " << aio << " 0x"
        << std::hex << offset << "~" << length << std::dec << dendl;
  if (cct->_conf->bdev_debug_inflight_ios) {
    Mutex::Locker l(debug_lock);
    debug_inflight.erase(offset, length);
  }
}

void CacheDevice::aio_submit(IOContext *ioc)
{
  dout(20) << __func__ << " ioc " << ioc
                << " pending " << ioc->num_pending.load()
                << " running " << ioc->num_running.load()
                << dendl;

  int pending = ioc->num_pending.load();
  Task *t = static_cast<Task*>(ioc->cache_task_first);

  if ( pending && t ) {
    ioc->num_running += pending;
    ioc->num_pending -= pending;
    assert( ioc->num_pending.load() == 0);
    queue_task(t, pending);
    ioc->cache_task_first = ioc->cache_task_last = nullptr;
  }

}

int CacheDevice::_sync_write(uint64_t off, bufferlist &bl, bool buffered)
{
  uint64_t len = bl.length();
  dout(5) << __func__ << " 0x" << std::hex << off << "~" << len
          << std::dec << " buffered" << dendl;
#if 0
  if (cct->_conf->bdev_inject_crash &&
      rand() % cct->_conf->bdev_inject_crash == 0) {
    derr << __func__ << " bdev_inject_crash: dropping io 0x" << std::hex
         << off << "~" << len << std::dec << dendl;
    ++injecting_crash;
    return 0;
  }
  vector<iovec> iov;
  bl.prepare_iov(&iov);
  int r = ::pwritev(buffered ? fd_buffered : fd_direct,
                    &iov[0], iov.size(), off);
#endif 
#if 1
  char * data = (char *)malloc(len);
  char * pos = data;
  for ( auto p : bl.buffers()){
        memmove(pos,(void *)p.c_str(), p.length());
        pos = pos+p.length();
  }
  int r = 0;
  r = T2Store_Cache_sync_write(&cache_ctx, data, off, len);
#endif 
  if (r < 0) {
    r = -errno;
    derr << __func__ << " pwritev error: " << cpp_strerror(r) << dendl;
    return r;
  }
  if (buffered) {
     //initiate IO (but do not wait)
    r = ::sync_file_range(fd_buffered, off, len, SYNC_FILE_RANGE_WRITE);
    if (r < 0) {
      r = -errno;
      derr << __func__ << " sync_file_range error: " << cpp_strerror(r) << dendl;
      return r;
    }
  }

  io_since_flush.store(true);

  return 0;
}

int CacheDevice::write(
  uint64_t off,
  bufferlist &bl,
  bool buffered)
{
  uint64_t len = bl.length();
  dout(20) << __func__ << " 0x" << std::hex << off << "~" << len << std::dec
           << (buffered ? " (buffered)" : " (direct)")
           << dendl;
  assert(off % block_size == 0);
  assert(len % block_size == 0);
  assert(len > 0);
  assert(off < size);
  assert(off + len <= size);

  if ((!buffered || bl.get_num_buffers() >= IOV_MAX) &&
      bl.rebuild_aligned_size_and_memory(block_size, block_size)) {
    dout(20) << __func__ << " rebuilding buffer to be aligned" << dendl;
  }
  dout(40) << "data: ";
  bl.hexdump(*_dout);
  *_dout << dendl;

  return _sync_write(off, bl, buffered);
}

void CacheDevice::queue_task(Task *t, uint64_t ops)
{
  // TODO
  queue_op_seq += ops;
  Mutex::Locker l(queue_lock);
  task_queue.push(t);
  if (queue_empty.load()) {
    queue_empty = false;
    queue_cond.Signal();
  }
}

int CacheDevice::aio_write(
  uint64_t off,
  bufferlist &bl,
  IOContext *ioc,
  bool buffered)
{
  uint64_t len = bl.length();
  dout(20) << __func__ << " 0x" << std::hex << off << "~" << len << std::dec
           << (buffered ? " (buffered)" : " (direct)")
           << dendl;
  assert(off % block_size == 0);
  assert(len % block_size == 0);
  assert(len > 0);
  assert(off < size);
  assert(off + len <= size);

  if ((!buffered || bl.get_num_buffers() >= IOV_MAX) &&
    bl.rebuild_aligned_size_and_memory(block_size, block_size)) {
    dout(20) << __func__ << " rebuilding buffer to be aligned" << dendl;
  }
  //dout(20) << "data: ";
  //bl.hexdump(*_dout);
  //*_dout << dendl;

  Task *task = new Task(this, IOCommand::WRITE_COMMAND, off, len);
  task->write_bl = std::move(bl);

  if (buffered) {
    queue_task(task);
  } else {
    task->ctx = ioc;
    Task *first = static_cast<Task*>(ioc->cache_task_first);
    Task *last = static_cast<Task*>(ioc->cache_task_last);
    if (last) {
      last->next = task;
    }
    if (!first) {
      ioc->cache_task_first = task;
    }
    ioc->cache_task_last = task;
    ++ioc->num_pending;
  }
  _aio_log_start(ioc, off, len);

  return 0;
}

int CacheDevice::read(uint64_t off, uint64_t len, bufferlist *pbl,
                      IOContext *ioc,
                      bool buffered)
{
  dout(5) << __func__ << " 0x" << std::hex << off << "~" << len << std::dec
          << (buffered ? " (buffered)" : " (direct)")
          << dendl;
  int r;
  assert(off % block_size == 0);
  assert(len % block_size == 0);
  assert(len > 0);
  assert(off < size);
  assert(off + len <= size);

  _aio_log_start(ioc, off, len);

  Task *t = new Task(this, IOCommand::READ_COMMAND, off, len, 1);
  t->read_ptr = buffer::create_page_aligned(len);
  pbl->append(t->read_ptr);
  t->ctx = ioc;
  ++ioc->num_running;

  queue_task(t);

  while ( t->return_code > 0 ) {
    t->io_wait();
  }
  r = t->return_code;

  delete t;
  return r;
}

int CacheDevice::aio_read(
  uint64_t off,
  uint64_t len,
  bufferlist *pbl,
  IOContext *ioc)
{
  dout(5) << __func__ << " 0x" << std::hex << off << "~" << len << std::dec
          << dendl;

  int r = 0;
  assert(off % block_size == 0);
  assert(len % block_size == 0);
  assert(len > 0);
  assert(off < size);
  assert(off + len <= size);

  Task *t = new Task(this, IOCommand::READ_COMMAND, off, len);
  t->read_ptr = buffer::create_page_aligned(len);
  pbl->append(t->read_ptr);
  t->ctx = ioc;
  Task *first = static_cast<Task*>(ioc->cache_task_first);
  Task *last = static_cast<Task*>(ioc->cache_task_last);
  if (last)
    last->next = t;
  if (!first)
    ioc->cache_task_first = t;
  ioc->cache_task_last = t;
  ++ioc->num_pending;

  return 0;
}

int CacheDevice::direct_read_unaligned(uint64_t off, uint64_t len, char *buf)
{
  int ret = 0;
  return ret;
}

int CacheDevice::read_random(uint64_t off, uint64_t len, char *buf,
                       bool buffered)
{
  int ret = 0;
  return ret;
}

int CacheDevice::invalidate_cache(uint64_t off, uint64_t len)
{
  dout(5) << __func__ << " 0x" << std::hex << off << "~" << len << std::dec
          << dendl;
  assert(off % block_size == 0);
  assert(len % block_size == 0);
  int r = posix_fadvise(fd_buffered, off, len, POSIX_FADV_DONTNEED);
  if (r) {
    r = -r;
    derr << __func__ << " 0x" << std::hex << off << "~" << len << std::dec
         << " error: " << cpp_strerror(r) << dendl;
  }
  return r;
}

