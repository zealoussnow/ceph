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
#include "common/admin_socket.h"
#include "common/errno.h"
#include "common/debug.h"
#include "common/blkdev.h"
#include "common/align.h"


#define dout_context cct
#define dout_subsys ceph_subsys_cdev
#undef dout_prefix
#define dout_prefix *_dout << "cdev(" << this << " " << path << ") "
#define BITS_PER_HEX 4

static constexpr uint32_t data_buffer_size = 8192;
static constexpr uint16_t inline_segment_num = 32;

static int xdigit2val(unsigned char c) {
  int val;

  if (isdigit(c))
    val = c - '0';
  else if (isupper(c))
    val = c - 'A' + 10;
  else
    val = c - 'a' + 10;
  return val;
}

static int str2cpuset(const char *coremask, cpu_set_t *mask) {
  unsigned int cpu_nums = sysconf(_SC_NPROCESSORS_CONF);
  char c;
  int i;
  unsigned int j, val, idx = 0;
  CPU_ZERO(mask);

  if (coremask == NULL)
    return -1;
  while (isblank(*coremask))
    coremask++;
  if (coremask[0] == '0' && ((coremask[1] == 'x')
                             || (coremask[1] == 'X')))
    coremask += 2;
  i = strlen(coremask);
  while ((i > 0) && isblank(coremask[i - 1]))
    i--;
  if (i == 0)
    return -1;
  for (i = i - 1; i >= 0; i--) {
    c = coremask[i];
    if (isxdigit(c) == 0) {
      /* invalid characters */
      return -1;
    }
    val = xdigit2val(c);
    for (j = 0; j < BITS_PER_HEX && idx < __CPU_SETSIZE; j++, idx++) {
      if (idx < cpu_nums && (1 << j) & val){
        CPU_SET(idx, mask);
      }
      else if ((1 << j) & val) {
        return -1;
      }
    }
  }
  return 0;
}

struct Task {
  CacheDevice *device;
  IOContext *ctx = nullptr;
  IOCommand command;
  uint64_t offset;
  uint64_t len;
  bufferlist write_bl;
  bufferptr read_ptr;
  std::function<void()> fill_cb;
  Task *next = nullptr;
  int64_t return_code;
  utime_t start;
  std::mutex lock;
  std::condition_variable cond;
  Task(CacheDevice *dev, IOCommand c, uint64_t off, uint64_t l, int64_t rc = 0)
    : device(dev), command(c), offset(off), len(l),
      return_code(rc),
      start(ceph_clock_now()) {}
  ~Task() {
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
    aio(false), dio(false),
    debug_lock("CacheDevice::debug_lock"),
    queue_lock("CacheDevice::queue_lock"),
    aio_queue(cct->_conf->bdev_aio_max_queue_depth),
    aio_stop(false),
    injecting_crash(0),
    asok_hook(nullptr),
    cache_ctx{0},
    aio_callback(cb),
    aio_callback_priv(cbpriv)
{
  _init_logger();
  dout(20) << "add observer..." << ", " << this << dendl;
  cct->_conf->add_observer(this);
  cache_ctx.registered=false;
}

CacheDevice::~CacheDevice()
{
  dout(20) << "remove CacheDevice observer..." << dendl;
  cct->_conf->remove_observer(this);
  asok_unregister();
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

void logger_tinc(void *cd, int serial, struct timespec start, struct timespec end)
{
  CacheDevice *cache_device = static_cast<CacheDevice*>(cd);
  utime_t u_start(start);
  utime_t u_end(end);
  utime_t dur = u_end - u_start;

  cache_device->logger->tinc(serial, dur);
}

int CacheDevice::cache_init(const std::string& path)
{
  int r = 0;
  bdev_path = path + "/bdev.conf.in";
  cache_ctx.fd_cache=fd_cache;
  cache_ctx.fd_direct=fd_direct;
  cache_ctx.bdev_path = bdev_path.c_str();
  cache_ctx.whoami = cct->_conf->name.get_id().c_str();
  cache_ctx.log_file = cct->_conf->log_file.c_str();
  cache_ctx.logger_cb = (void*)logger_tinc;
  cache_ctx.bluestore_cd = (void*)this;
  cache_ctx.log_crash_on_nospc = cct->_conf->log_crash_on_nospc;

  dout(0)<< __func__ << " ceph log file "<< cache_ctx.log_file <<dendl;
  dout(1)<< __func__ << " lb cache_ctx.registered "<< cache_ctx.registered <<dendl;
  if (cache_ctx.registered)
    return r;

  r = t2store_cache_register_cache(&cache_ctx);
  if(r)
    return r;

  r = _aio_start();
  if(r)
    return r;

  // register asok command
  asok_register();

  return r;
}

void CacheDevice::_init_logger()
{
  PerfCountersBuilder b(cct, "cachedevice",
                        l_cachedevice_first, l_cachedevice_last);

  b.add_time_avg(l_bluestore_cachedevice_aio_write_lat, "blue_aio_write",
                 "bluestore cache aio write");
  b.add_time_avg(l_bluestore_cachedevice_aio_read_lat, "blue_aio_read",
                 "bluestore cache aio read");
  b.add_time_avg(l_bluestore_cachedevice_flush_lat, "blue_flush",
                 "bluestore cache flush");
  b.add_time_avg(l_bluestore_cachedevice_write_queue_lat, "blue_write_queue",
                 "bluestore cache write queue latency");
  b.add_time_avg(l_bluestore_cachedevice_t2cache_write_lat, "t2cache_write",
                 "cache write latency");
  b.add_time_avg(l_bluestore_cachedevice_t2cache_read_lat, "t2cache_read",
                 "cache read latency");
  b.add_time_avg(l_bluestore_cachedevice_t2cache_libaio_write_lat, "t2cache_libaio_write",
                 "cache aio write latency");
  b.add_time_avg(l_bluestore_cachedevice_t2cache_libaio_read_lat, "t2cache_libaio_read",
                 "cache aio read latency");
  b.add_time_avg(l_bluestore_cachedevice_t2cache_alloc_sectors, "t2cache_alloc_sectors",
                 "alloc bucket for cache");
  b.add_time_avg(l_bluestore_cachedevice_t2cache_insert_keys, "t2cache_insert_keys",
                 "cache bkey insert");
  b.add_time_avg(l_bluestore_cachedevice_t2cache_journal_write, "t2cache_journal_write",
                 "cache journal write");

  logger = b.create_perf_counters();
  cct->get_perfcounters_collection()->add(logger);
}

void CacheDevice::_shutdown_logger()
{
  cct->get_perfcounters_collection()->remove(logger);
  delete logger;
}

int CacheDevice::write_cache_super(const std::string& path)
{
  int r = 0;
  unsigned block_size = 8;
  unsigned bucket_size = 1024;
  bool writeback = 0;
  bool discard = 0;
  bool wipe_bcache = 1;
  unsigned cache_replacement_policy = 0;
  uint64_t data_offset = 16;
  cache_ctx.whoami = cct->_conf->name.get_id().c_str();
  cache_ctx.log_file = cct->_conf->log_file.c_str();
  cache_ctx.log_crash_on_nospc = cct->_conf->log_crash_on_nospc;

  r = t2store_cache_write_cache_sb(&cache_ctx, path.c_str(),
                        block_size, bucket_size, writeback, discard, 
                        wipe_bcache,cache_replacement_policy,
                        data_offset,false);
  return r;
}
int CacheDevice::open(const string& p, const string& c_path)
{
  path = p;
  cache_path = c_path;
  int r = 0;
  int flgs = O_RDWR | O_DIRECT;
  if (cct->_conf->t2store_dev_flush){
    flgs |= O_DSYNC;
    dout(1) << __func__ << " open device with O_DSYNC flag " << dendl;
  }

  fd_cache = ::open(cache_path.c_str(), flgs);
  if (fd_cache < 0) {
    r = -errno;
    derr << __func__ << " open got: " << cpp_strerror(r) << dendl;
    return r;
  }

  fd_direct = ::open(path.c_str(), flgs);
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
  if (cache_ctx.registered)
    t2store_cache_destroy_cache(&cache_ctx);

  _shutdown_logger();
  assert(fd_direct >= 0);
  VOID_TEMP_FAILURE_RETRY(::close(fd_direct));
  fd_direct = -1;

  assert(fd_buffered >= 0);
  VOID_TEMP_FAILURE_RETRY(::close(fd_buffered));
  fd_buffered = -1;

  assert(fd_cache >= 0);
  VOID_TEMP_FAILURE_RETRY(::close(fd_cache));
  fd_cache = -1;

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
  
  // We heave O_DSYNC in open.
  // so, return now
  return 0;
/*
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
*/
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

    cpu_set_t mask;
    const char *coremask = cct->_conf->t2store_core_mask.c_str();
    r = str2cpuset(coremask, &mask);
    if (r) {
      derr << __func__ << " t2store_core_mask transform error: "
        << cct->_conf->t2store_core_mask
        << " Syntax error or CPU number is not enough." << dendl;
      return r;
    }

    unsigned cpu_nums = sysconf(_SC_NPROCESSORS_CONF);
    for (unsigned i = 0; i < cpu_nums; i++) {
      if (CPU_ISSET(i, &mask)) {
        char *thread_name = (char*)calloc(17, sizeof(char));
        sprintf(thread_name, "caio_%u", i);
        AioCompletionThread *aio_thread = new AioCompletionThread(this);
        aio_thread->create(thread_name);
        //aio_thread->set_affinity(i);
        aio_threads.push_back(aio_thread);
      }
    }
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
    vector<AioCompletionThread *>::iterator it;
    for (it = aio_threads.begin(); it != aio_threads.end(); it++) {
      (*it)->join();
    }
    aio_stop = false;
  }

}

void io_complete(void *t)
{
#undef dout_prefix
#define dout_prefix *_dout << "cdev "

  Task *task = static_cast<Task*>(t);
  CacheDevice *cache_device = task->device;
  IOContext *ctx = task->ctx;

  assert(ctx != NULL);
  assert(cache_device != NULL);
  utime_t dur = ceph_clock_now() - task->start;
  if (task->command == IOCommand::WRITE_COMMAND) {
    ldout(g_ceph_context, 5) << __func__ << " write ioc(" << ctx << " num_pending "
        << ctx->num_pending << " num_running " << ctx->num_running << " priv "
        << ctx->priv <<") task " << task << " (write_bl[" << task->write_bl
        << "] 0x" << std::hex << task->offset << "~" << task->len << std::dec
        << " return_code " << task->return_code << ")" << dendl;

    auto i = ctx->writing_aios.find(task->offset);
    if (i == ctx->writing_aios.end() || task->len != i->second) {
      lderr(g_ceph_context) << __func__ << " task io err off 0x" << std::hex
        << task->offset << "~" << task->len << " ioctx off 0x" <<
        i->first << "~" << i->second << "error aios" << ctx->writing_aios
        << std::dec << dendl;
      assert("task io err" == 0);
    }

    if (ctx->priv) {
      if (!--ctx->num_running) {
        task->device->aio_callback(task->device->aio_callback_priv, ctx->priv);
      }
    } else {
      ctx->try_aio_wake();
    }


    ldout(g_ceph_context, 6) << __func__ << "io complete, now release task " << task << dendl;
    delete task;
  } else if (task->command == IOCommand::READ_COMMAND) {
    ldout(g_ceph_context, 5) << __func__ << " read ioc(" << ctx << " num_pending "
        << ctx->num_pending << " num_running " << ctx->num_running << " priv "
        << ctx->priv <<") task " << task << " (read_ptr[" << task->read_ptr
        << "] 0x" << std::hex << task->offset << "~" << task->len << std::dec
        << " return_code " << task->return_code << ")" << dendl;
    cache_device->logger->tinc(l_bluestore_cachedevice_aio_read_lat, dur);
    if(!task->return_code) {
      // we have not priv for read at present, maybe have in futher, so assert
      assert(ctx->priv == 0);
      if (ctx->priv) {
        if (!--ctx->num_running) {
          task->device->aio_callback(task->device->aio_callback_priv, ctx->priv);
        }
      } else {
        ctx->try_aio_wake();
      }
      ldout(g_ceph_context, 6) << __func__ << "io complete, now release task " << task << dendl;
      delete task;
    } else {
      task->return_code = 0;
      if (!--ctx->num_running) {
        task->io_wake();
      }
    }
  } else {
    assert(task->command == IOCommand::FLUSH_COMMAND);
    cache_device->logger->tinc(l_bluestore_cachedevice_flush_lat, dur);
    task->return_code = 0;
  }
#undef dout_prefix
#define dout_prefix *_dout << "cdev(" << this << " " << path << ") "
}

void CacheDevice::_aio_writeback(struct ring_items *items)
{
  int r;
  int size = t2store_cache_ring_items_get_size(items);
  if (size > 0) { 
    dout(20) << __func__ << "batch size " << size << dendl;
    r = t2store_cache_aio_writeback_batch(&cache_ctx, items);
    if (r < 0) {
      derr << __func__ << " failed to do write command" << dendl;
      ceph_abort();
    }
    t2store_cache_aio_items_reset(items);
    assert(t2store_cache_ring_items_get_size(items) == 0);
  }
}

void CacheDevice::_aio_writearound(struct ring_items *items)
{
  int r;
  int size = t2store_cache_ring_items_get_size(items);
  if (size > 0) {
    dout(20) << __func__ << "batch size " << size << dendl;
    r = t2store_cache_aio_writearound_batch(&cache_ctx, items);
    if (r < 0) {
      derr << __func__ << " failed to do write command" << dendl;
      ceph_abort();
    }
    t2store_cache_aio_items_reset(items);
    assert(t2store_cache_ring_items_get_size(items) == 0);
  }
}

void CacheDevice::_aio_writethrough(struct ring_items *items)
{
  int r;
  int size = t2store_cache_ring_items_get_size(items);
  if (size > 0) {
    dout(20) << __func__ << "batch size " << size << dendl;
    r = t2store_cache_aio_writethrough_batch(&cache_ctx, items);
    if (r < 0) {
      derr << __func__ << " failed to do write command" << dendl;
      ceph_abort();
    }
    t2store_cache_aio_items_reset(items);
    assert(t2store_cache_ring_items_get_size(items) == 0);
  }
}

void CacheDevice::_aio_thread()
{
  Task *t = nullptr;
  uint64_t off, len;
  int r = 0;
  uint8_t strategy;
  int max_buffer = cct->_conf->cache_aio_write_batch_max_size;
  r = t2store_cache_aio_thread_init(&cache_ctx);
  if (r < 0) {
    derr << __func__ << " failed to do thread init" << dendl;
    ceph_abort();
  }
  struct ring_items *items_wb = t2store_cache_aio_items_alloc(max_buffer);
  assert(items_wb !=NULL);
  struct ring_items *items_wa = t2store_cache_aio_items_alloc(max_buffer);
  assert(items_wa !=NULL);
  struct ring_items *items_wt = t2store_cache_aio_items_alloc(max_buffer);
  assert(items_wt !=NULL);
  struct ring_item *item;

  dout(5) << __func__ << " start aio thread" << dendl;
  while (true) {
    Task *current_task = t;
    Task *next_task    = nullptr;

    while (current_task) {
      next_task = current_task->next;
      off = current_task->offset;
      len = current_task->len;
      utime_t dur = ceph_clock_now() - current_task->start;
      switch (current_task->command) {
        case IOCommand::WRITE_COMMAND:
        {
          current_task->device->logger->tinc(l_bluestore_cachedevice_write_queue_lat, dur);
          dout(6) << __func__ << " write command issued ioc(" << current_task->ctx << " num_pending "
                  << current_task->ctx->num_pending << " num_running " << current_task->ctx->num_running
                  << ") task " << current_task << " (write_bl[" << current_task->write_bl << "] 0x"
                  << std::hex << current_task->offset << "~" << current_task->len  << std::dec << ")"
                  << " offset 0x" << std::hex << off << "~" << len << std::dec << dendl;
          assert( current_task->write_bl.c_str() != NULL);
          assert( off != 0);
          assert( len != 0);
          if (cct->_conf->cache_aio_write_batch) {
            item = t2store_cache_aio_get_item(current_task->write_bl.c_str(), off, len, (void *) io_complete, (void *)current_task);
            assert(item);
            strategy = t2store_cache_aio_get_cache_strategy(&cache_ctx, item);
            switch (strategy) {
              case CACHE_MODE_WRITEBACK:
retry_wb:       if (t2store_cache_aio_items_add(items_wb, item) < 0) {
                  dout(20) << __func__ << "add writeback items full, flush and retry" << dendl;
                  _aio_writeback(items_wb);
                  goto retry_wb;
                }
                break;
              case CACHE_MODE_WRITEAROUND:
retry_wa:       if (t2store_cache_aio_items_add(items_wa, item) < 0) {
                  dout(20) << __func__ << "add writearound items full, flush and retry" << dendl;
                  _aio_writearound(items_wa);
                  goto retry_wa;
                }
                break;
              case CACHE_MODE_WRITETHROUGH:
retry_wt:       if (t2store_cache_aio_items_add(items_wt, item) < 0) {
                  dout(20) << __func__ << "add writethrough items full, flush and retry" << dendl;
                  _aio_writethrough(items_wt);
                  goto retry_wt;
                }
                break;
              default:
                assert("Unsupported io stragegy" == 0);
            }
            break;
          }
          // for no batch
          r = t2store_cache_aio_write(&cache_ctx, current_task->write_bl.c_str(), off, len, (void *)io_complete,(void *)current_task);
          if (r < 0) {
            derr << __func__ << " failed to do write command" << dendl;
            delete current_task;
            current_task = nullptr;
            ceph_abort();
          }
          break;
        }
        case IOCommand::READ_COMMAND:
        {
          dout(6) << __func__ << " read command issued ioc(" << current_task->ctx << " num_pending "
                  << current_task->ctx->num_pending << " num_running " << current_task->ctx->num_running
                  << ") task " << current_task << " (read_ptr[" << current_task->read_ptr << "] 0x"
                  << std::hex << current_task->offset << "~" << current_task->len  << std::dec << ")"
                  << " offset 0x" << std::hex << off << "~" << len << std::dec << dendl;
          assert( current_task->read_ptr.c_str() != NULL);
          assert( off != 0);
          assert( len != 0);
          r = t2store_cache_aio_read(&cache_ctx, current_task->read_ptr.c_str(), off, len, (void *)io_complete,(void *)current_task);
          if (r < 0) {
            derr << __func__ << " failed to do read command" << dendl;
            delete current_task;
            current_task = nullptr;
            ceph_abort();
          }
          break;
        }
        case IOCommand::FLUSH_COMMAND:
        {
          // TODO
          dout(6) << __func__ << " flush command issueed " << dendl;
          assert(" flush commnad not imp yet " == 0);
          break;
        }
      }
      current_task = nullptr;
      if (next_task == nullptr)
        break;
      current_task = next_task;
    }

    t = nullptr;
    {
      Mutex::Locker l(queue_lock);
      if (!task_queue.empty()) {
        t = task_queue.front();
        assert(t);
        task_queue.pop();
      } else {
        _aio_writeback(items_wb);
        _aio_writethrough(items_wt);
        _aio_writearound(items_wa);
        if (aio_stop) {
          t2store_cache_aio_items_free(items_wb);
          t2store_cache_aio_items_free(items_wt);
          t2store_cache_aio_items_free(items_wa);
          break;
        }
        queue_cond.Wait(queue_lock);
      }
    }
  }

  reap_ioc();
  dout(5) << __func__ << " end aio thread" << dendl;
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
  dout(6) << __func__ << " ioc " << ioc
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
  return 0;
}

int CacheDevice::write(
  uint64_t off,
  bufferlist &bl,
  bool buffered)
{
  assert(0 == "get in write, for test");

  IOContext ioc(cct, NULL);
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

  _aio_log_start(&ioc, off, len);

  Task *t = new Task(this, IOCommand::WRITE_COMMAND, off, len, 1);
  t->write_bl = std::move(bl);
  t->ctx = &ioc;
  ++ioc.num_running;

  queue_task(t);

  ioc.aio_wait();
  return 0;
}

void CacheDevice::queue_task(Task *t, uint64_t ops)
{
  // TODO
  Mutex::Locker l(queue_lock);
  task_queue.push(t);
  queue_cond.Signal();
}

int CacheDevice::aio_write(
  uint64_t off,
  bufferlist &bl,
  IOContext *ioc,
  bool buffered)
{
  uint64_t len = bl.length();

  dout(5) << __func__ << " ioc(" << ioc << " num_pending "
      << ioc->num_pending << " num_running " << ioc->num_running
      <<") 0x" << std::hex << off << "~" << len << std::dec
      << (buffered ? " (buffered)" : " (direct)")
      << dendl;

  assert(off % block_size == 0);
  assert(len % block_size == 0);
  assert(len > 0 && len <= MAX_AIO_WRITE_LEN);
  assert(off < size);
  assert(off + len <= size);

  if ((!buffered || bl.get_num_buffers() >= IOV_MAX) &&
    bl.rebuild_aligned_size_and_memory(block_size, block_size)) {
    dout(20) << __func__ << " rebuilding buffer to be aligned" << dendl;
  }
  dout(40) << "data: ";
  bl.hexdump(*_dout);
  *_dout << dendl;

  Task *t = new Task(this, IOCommand::WRITE_COMMAND, off, len);
  t->write_bl = std::move(bl);

  if (buffered) {
    queue_task(t);
  } else {
    t->ctx = ioc;
    Task *first = static_cast<Task*>(ioc->cache_task_first);
    Task *last = static_cast<Task*>(ioc->cache_task_last);
    if (last) {
      last->next = t;
    }
    if (!first) {
      ioc->cache_task_first = t;
    }
    assert(t->next == nullptr);
    ioc->cache_task_last = t;
    ++ioc->num_pending;
  }

  dout(6) << __func__ << " ioc(" << t->ctx << " num_pending "
      << t->ctx->num_pending << " num_running "
      << t->ctx->num_running << ") task " << t
      << " (write_bl[" << t->write_bl << "] 0x" << std::hex
      << t->offset << "~" << t->len << std::dec << ")" << dendl;

  auto ret = ioc->writing_aios.insert(pair<uint64_t, uint64_t>(off, len));
  if (!ret.second) {
    derr << __func__ << " 0x" << std::hex << off << "~" << len << " error aios: "
      << ioc->writing_aios << std::dec <<dendl;
    assert("writing aios insert failed" == 0);
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

  assert("using aio_read instead of sync read, still have bug of dead lock" == 0);

  int r;
  assert(off % block_size == 0);
  assert(len % block_size == 0);
  assert(len > 0);
  assert(off < size);
  assert(off + len <= size);

  _aio_log_start(ioc, off, len);

  Task *t = new Task(this, IOCommand::READ_COMMAND, off, len, 1);
  t->read_ptr = buffer::create_page_aligned(len);
  assert(t->read_ptr.c_str());
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
  dout(5) << __func__ << " ioc(" << ioc << " num_pending "
      << ioc->num_pending << " num_running " << ioc->num_running
      <<") 0x" << std::hex << off << "~" << len << std::dec
      << dendl;

  assert(off % block_size == 0);
  assert(len % block_size == 0);
  assert(len > 0);
  assert(off < size);
  assert(off + len <= size);

  Task *t = new Task(this, IOCommand::READ_COMMAND, off, len);
  t->read_ptr = buffer::create_page_aligned(len);
  assert(t->read_ptr.c_str());
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

  dout(6) << __func__ << " ioc(" << t->ctx << " num_pending "
      << t->ctx->num_pending << " num_running "
      << t->ctx->num_running << ") task " << t
      << " (read_ptr[" << t->read_ptr << "] 0x" << std::hex
      << t->offset << "~" << t->len << std::dec << ")" << dendl;
  _aio_log_start(ioc, off, len);

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

int CacheDevice::invalidate_region(uint64_t off, uint64_t len)
{
  int ret = 0;
  ret = t2store_cache_invalidate_region(&cache_ctx, off, len);
  return ret;
}

const char** CacheDevice::get_tracked_conf_keys() const
{
  static const char *KEYS[] = {
    "t2store_gc_pause",
    "t2store_gc_moving_stop",
    "t2store_writeback_stop",
    "t2store_cache_mode",
    "t2store_writeback_percent",
    "t2store_writeback_rate_update_seconds",
    "t2store_sequential_cutoff",
    "t2store_cutoff_writeback",
    "t2store_cutoff_writeback_sync",
    "t2store_cutoff_cache_add",
    "t2store_cutoff_gc",
    "t2store_gc_mode",
    "t2store_max_gc_keys_onetime",
    "t2store_cached_hits",
    NULL
  };

  return KEYS;
}

void CacheDevice::handle_conf_change(const struct md_config_t *conf,
      const std::set <std::string> &changed)
{
  struct update_conf u_conf;
  memset(&u_conf, 0, sizeof(u_conf));

  for (const char **i = get_tracked_conf_keys(); *i; ++i) {
    if (changed.count(std::string(*i))) {
      char *pval = NULL;
      int r = conf->get_val(*i, &pval, -1);
      assert(r >= 0);
      u_conf.opt_name = *i;
      u_conf.val = pval;
      dout(5) << "handle_conf_change " << this << " , opt_name: " << u_conf.opt_name << ", val: " << u_conf.val << dendl;
      t2store_handle_conf_change(&cache_ctx, &u_conf);
      free(pval);
    }
  }
}


class CacheSocketHook : public AdminSocketHook {
public:
  explicit CacheSocketHook(CacheDevice *cd) : cache_device(cd) { }

  bool call(std::string command, cmdmap_t& cmdmap, std::string format,
      bufferlist& out) override {
    stringstream ss;
    bool r = cache_device->asok_command(command, cmdmap, format, ss);
    out.append(ss);
    return r;
  }

private:
  CacheDevice *cache_device;
};

static string bytes_unit(uint64_t size)
{
  stringstream out;
  static const char* units[] = {"B", "KB", "MB", "GB", "TB"};
  static const int max_units = sizeof(units)/sizeof(*units);

  int unit = 0;
  while (size >= 1024 && unit < max_units) {
    if (size < 1048576 && (size % 1024 != 0))
      break;
    size >>= 10;
    unit++;
  }

  out << size << " " << units[unit];
  return out.str();
}

bool CacheDevice::asok_command(string command, cmdmap_t& cmdmap,
                               string format, ostream& ss)
{
  std::unique_ptr<Formatter> f(Formatter::create(format, "json-pretty", "json"));
  // dump number of btree nodes and number of bkeys
  if (command == "dump_btree_info") {
    struct btree_info bi;
    t2store_btree_info(&cache_ctx, &bi);
    f->open_object_section("btree_info");
    f->dump_unsigned("btree_nodes", bi.btree_nodes);
    f->dump_unsigned("btree_nbkeys", bi.btree_nbkeys);
    f->dump_unsigned("btree_bad_bkeys", bi.btree_bad_nbeys);
    f->dump_unsigned("btree_null_nbkeys", bi.btree_null_nbkeys);
    f->dump_unsigned("zero_keysize_nbkeys", bi.zero_keysize_nbkeys);
    f->dump_unsigned("btree_dirty_bkeys", bi.btree_dirty_nbkeys);
    f->dump_string("total_size", bytes_unit(bi.total_size));
    f->dump_string("dirty_size", bytes_unit(bi.dirty_size));
    f->close_section();
  }

  if (command == "dump_btree_detail") {
    int ret = t2store_reload_zlog_config();
    assert(ret == 0);
    t2store_btree_info(&cache_ctx, NULL);
  }

  if (command == "dump_wb_status") {
    struct wb_status ws;
    t2store_wb_status(&cache_ctx, &ws);
    f->open_object_section("wb_status");
    f->dump_string("cache_mode", ws.cache_mode);
    f->dump_string("wb_running_state", ws.wb_running_state);
    f->dump_int("writeback_stop", ws.writeback_stop);
    f->dump_int("cached_hits", ws.cached_hits);
    f->dump_int("has_dirty", ws.has_dirty);
    f->dump_unsigned("dirty_sectors", ws.dirty_sectors);
    f->dump_int("sequential_cutoff", ws.sequential_cutoff);
    f->dump_int("writeback_percent", ws.writeback_percent);
    f->dump_int("writeback_delay", ws.writeback_delay);
    f->dump_int("real_wb_delay", ws.real_wb_delay);
    f->dump_int("writeback_rate", ws.writeback_rate);
    f->dump_int("writeback_rate_d_term", ws.writeback_rate_d_term);
    f->dump_int("writeback_rate_p_term_inverse", ws.writeback_rate_p_term_inverse);
    f->dump_int("writeback_rate_update_seconds", ws.writeback_rate_update_seconds);
    f->dump_int("cutoff_writeback", ws.cutoff_writeback);
    f->dump_int("cutoff_writeback_sync", ws.cutoff_writeback_sync);
    f->dump_int("cutoff_cache_add", ws.cutoff_cache_add);
    f->close_section();
  }

  if (command == "dump_gc_status") {
    struct gc_status gs;
    t2store_gc_status(&cache_ctx, &gs);
    f->open_object_section("gc status");
    f->dump_float("gc_mark_in_use", gs.gc_mark_in_use);
    f->dump_int("sectors_to_gc", gs.sectors_to_gc);
    f->dump_string("gc_running_state", gs.gc_running_state);
    f->dump_int("invalidate_needs_gc", gs.invalidate_needs_gc);
    f->dump_int("cutoff_gc", gs.cutoff_gc);
    f->dump_int("cutoff_gc_busy", gs.cutoff_gc_busy);
    f->dump_int("max_gc_keys_onetime", gs.max_gc_keys_onetime);
    f->close_section();
    f->open_object_section("all buckets");
    f->dump_unsigned("gc_all_buckets", gs.gc_all_buckets);
    f->dump_unsigned("gc_avail_buckets", gs.gc_avail_buckets);
    f->dump_unsigned("gc_unavail_buckets", gs.gc_unavail_buckets);
    f->close_section();
    f->open_object_section("availbale buckets");
    f->dump_unsigned("gc_init_buckets", gs.gc_init_buckets);
    f->dump_unsigned("gc_reclaimable_buckets", gs.gc_reclaimable_buckets);
    f->close_section();
    f->open_object_section("unavailbale buckets");
    f->dump_unsigned("gc_meta_buckets", gs.gc_meta_buckets);
    f->dump_unsigned("gc_dirty_buckets", gs.gc_dirty_buckets);
    f->close_section();
    f->open_object_section("meta buckets");
    f->dump_unsigned("gc_uuids_buckets", gs.gc_uuids_buckets);
    f->dump_unsigned("gc_writeback_dirty_buckets", gs.gc_writeback_dirty_buckets);
    f->dump_unsigned("gc_journal_buckets", gs.gc_journal_buckets);
    f->dump_unsigned("gc_prio_buckets", gs.gc_prio_buckets);
    f->close_section();
    f->open_object_section("gc moving");
    f->dump_int("gc_moving_stop", gs.gc_moving_stop);
    f->dump_unsigned("gc_moving_buckets", gs.gc_moving_buckets);
    f->dump_unsigned("gc_pin_buckets", gs.gc_pin_buckets);
    f->dump_unsigned("gc_empty_buckets", gs.gc_empty_buckets);
    f->dump_unsigned("gc_full_buckets", gs.gc_full_buckets);
    f->close_section();
  }

  if (command == "reload_zlog_config") {
    int ret = t2store_reload_zlog_config();
    assert(ret == 0);
  }

  if (command == "set_log_level") {
    string log_level;
    string error;
    bool success = false;
    for (auto item : cmdmap)
      dout(0) << item.first << dendl;
    if (!cmd_getval(cct, cmdmap, "level", log_level)) {
      error = "unable to get log level";
      success = false;
    } else {
      if (t2store_set_log_level(log_level.c_str())) {
        error = "log level is not specified";
        success = false;
      } else
        success = true;
    }
    f->open_object_section("result");
    f->dump_string("error", error);
    f->dump_bool("success", success);
    f->close_section();
  }

  if (command == "set_gc_pause") {
    int64_t pause= 0;
    cmd_getval(cct, cmdmap, "pause", pause);
    dout(0) << "set_gc_pause: " << pause << dendl;
    t2store_set_gc_pause(&cache_ctx, pause);
  }

  if (command == "wake_up_gc") {
    t2store_wakeup_gc(&cache_ctx);
  }

  if (command == "expensive_debug_checks") {
    int64_t state = 0;
    cmd_getval(cct, cmdmap, "state", state);
    dout(0) << "set expensive_debug_checks: " << state << dendl;
    t2store_expensive_debug_checks(&cache_ctx, state);
  }

  f->flush(ss);

  return true;
}

void CacheDevice::asok_register()
{
  AdminSocket *admin_socket = cct->get_admin_socket();
  asok_hook = new CacheSocketHook(this);

  int r = admin_socket->register_command("dump_btree_info", "dump_btree_info",
                                     asok_hook, "dump btree overview");
  assert(r == 0);

  r = admin_socket->register_command("dump_btree_detail", "dump_btree_detail",
                                     asok_hook, "dump btree detail");
  assert(r == 0);

  r = admin_socket->register_command("dump_wb_status", "dump_wb_status",
                                     asok_hook, "dump writeback status");
  assert(r == 0);
  r = admin_socket->register_command("dump_gc_status", "dump_gc_status",
                                     asok_hook, "dump gc status");
  assert(r == 0);
  r = admin_socket->register_command("reload_zlog_config", "reload_zlog_config",
                                     asok_hook, "reload zlog config");
  assert(r == 0);
  r = admin_socket->register_command("set_log_level",
                                     "set_log_level name=level,type=CephString",
                                     asok_hook, "set zlog level");
  assert(r == 0);
  r = admin_socket->register_command("set_gc_pause",
                                     "set_gc_pause name=pause,type=CephInt",
                                     asok_hook, "set gc pause");
  assert(r == 0);
  r = admin_socket->register_command("wake_up_gc", "wake_up_gc",
                                     asok_hook, "forced wakeup gc");
  assert(r == 0);
  r = admin_socket->register_command("expensive_debug_checks",
                                     "expensive_debug_checks name=state,type=CephInt",
                                     asok_hook, "expensive debug checks");
  assert(r == 0);
}

void CacheDevice::asok_unregister()
{
  cct->get_admin_socket()->unregister_command("dump_btree_info");
  cct->get_admin_socket()->unregister_command("dump_btree_detail");
  cct->get_admin_socket()->unregister_command("dump_wb_status");
  cct->get_admin_socket()->unregister_command("dump_gc_status");
  cct->get_admin_socket()->unregister_command("reload_zlog_config");
  cct->get_admin_socket()->unregister_command("set_log_level");
  cct->get_admin_socket()->unregister_command("set_gc_pause");
  cct->get_admin_socket()->unregister_command("wake_up_gc");

  if (asok_hook) {
    delete asok_hook;
    asok_hook = nullptr;
  }
}
