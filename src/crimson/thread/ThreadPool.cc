#include "ThreadPool.h"

namespace ceph::thread {

ThreadPool::ThreadPool(size_t n)
  : threads{create_threads(n)}
{}

ThreadPool::~ThreadPool()
{
  stop = true;
  cond.notify_all();
  join();
}

std::vector<std::thread> ThreadPool::create_threads(size_t n)
{
  std::vector<std::thread> workers;
  for (size_t i = 0; i < n; i++) {
    workers.emplace_back([this] {
      loop();
    });
  }
  return workers;
}

void ThreadPool::loop()
{
  while (!stopping()) {
    WorkItem* work_item = nullptr;
    {
      std::unique_lock lock{mutex};
      cond.wait(lock, [this, &work_item] {
        return stopping() || pending.pop(work_item);
      });
    }
    if (work_item) {
      work_item->process();
    }
  }
}

void ThreadPool::join()
{
  for (auto& thread : threads) {
    thread.join();
  }
}

}
