# 通过admin socket新增的配置和命令

## 新增的配置

### 使新增的配置生效只需要实现:

* 将当前类添加至全局conf的observer，即`add_observer`接口
* 全局conf需要track的配置选项，`get_tracked_conf_keys`接口
* 当选项值修改时，回调至当前类的处理函数，`handle_conf_change`接口

### 目前添加的配置有：

* t2store_gc_stop
* t2store_gc_moving_stop
* t2store_writeback_stop
* t2store_cache_mode
* t2store_writeback_percent
* t2store_writeback_rate_update_seconds
* t2store_sequential_cutoff
* t2store_cutoff_writeback
* t2store_cutoff_writeback_sync
* t2store_cutoff_cache_add

### 通过admin socket实现配置动态更改：

目前ceph已经实现了通过admin socket来动态修改配置的命令行参数，即：`ceph daemon osd.<osd id> config set <config option> <option value>`，比如；

动态设置`t2store_writeback_rate_update_seconds`这个选项：

```shell
# ceph daemon osd.0 config set t2store_writeback_rate_update_seconds 5
```

设置完成之后，可以通过`config get`来获取当前值是否正确

```shell
# ceph daemon osd.0 config get t2store_writeback_rate_update_seconds
{
    "t2store_writeback_rate_update_seconds": "5"
}
```

## 新增的命令

### 新增admin socket命令需要实现：

* 获取全局admin_socket实例，并调用register_command接口来添加新的命令
* 实现AdminSocketHook的call接口

### 目前新增的命令有

1.dump_btree_info

导出当前cache模块btree的相关信息：

```shell
# ceph daemon osd.0 dump_btree_info
```

2.dump_btree_detail

```shell
# ceph daemon osd.0 dump_btree_detail
```

执行该命令后，会将btree中的结点打印到cache的日志当中。

3.dump_wb_status

```shell
# ceph daemon osd.0 dump_wb_status
```

导出与writeback相关的状态信息

4.dump_gc_status

```shell
# ceph daemon osd.0 dump_gc_status
```

导出与gc相关的状态信息

5.reload_zlog_config

重新加载zlog的配置

6.set_log_level

设置zlog的日志级别，允许的级别有：DEBUG、INFO、NOTICE、WARN、ERROR、DUMP，如：

```shell
# ceph daemon osd.0 set_log_level INFO
{
    "error": "",
    "success": true
}
```

如果指定的日志级别不存在时，如下：

```shell
# ceph daemon osd.0 set_log_level TRACE
{
    "error": "log level is not specified",
    "success": false
}
```

7.set_gc_stop

设置gc_stop的值，当gc_stop为1时，gc线程会等待；为0时，当条件满足时gc过程可以继续运行

```shell
# ceph daemon osd.0 set_gc_stop 1
```

8.wake_up_gc

手动唤醒gc线程，如下

```shell
# ceph daemon osd.0 wake_up_gc
```
