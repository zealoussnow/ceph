// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab

#include <atomic>
#include <condition_variable>
#include <tuple>
#include <type_traits>
#include <boost/lockfree/queue.hpp>
#include <boost/optional.hpp>
#include <core/future.hh>

#include "Condition.h"

namespace ceph::thread {

struct WorkItem {
  virtual ~WorkItem() {}
  virtual void process() = 0;
};

template<typename Func, typename T = std::invoke_result_t<Func>>
struct Task final : WorkItem {
  Func func;
  boost::optional<T> result;
  ceph::thread::Condition on_done;
  Task(Func&& f) : func(std::move(f)) {}
  void process() override {
    result = func();
    on_done.notify();
  }
  seastar::future<T> get_future() {
    return on_done.wait().then([this] {
	auto res = std::move(result.get());
	delete this;
	return res;
      }).then([](T&& result) {
        return seastar::make_ready_future<T>(std::move(result));
      });
  }
};

/// an engine for scheduling non-seastar tasks from seastar threads
class ThreadPool {
  std::atomic<bool> stop = false;
  std::mutex mutex;
  std::condition_variable cond;
  std::vector<std::thread> threads;

  // please note, each Task has its own ceph::thread::Condition, which
  // possesses a fd, so we should keep the number of WorkItem in-flight under a
  // reasonable limit.
  static constexpr size_t num_queue_size = 128;
  using item_queue_t =
    boost::lockfree::queue<WorkItem*,
			   boost::lockfree::capacity<num_queue_size>>;
  item_queue_t pending;

  std::vector<std::thread> create_threads(size_t n);
  void loop();
  void join();
  bool stopping() const {
    return stop.load(std::memory_order_relaxed);
  }

  ThreadPool(const ThreadPool&) = delete;
  ThreadPool& operator=(const ThreadPool&) = delete;
public:
  explicit ThreadPool(size_t n);
  ~ThreadPool();
  template<typename Func, typename...Args>
  auto submit(Func&& func, Args&&... args) {
    // using T = std::invoke_result_t<Func, Args...>;
    auto task = new Task{
      [func=std::move(func), args=std::forward_as_tuple(args...)] {
	return std::apply(std::move(func), std::move(args));
      }
    };
    auto fut = task->get_future();
    pending.push(task);
    cond.notify_one();
    return fut;
  }
};

} // namespace ceph::thread
