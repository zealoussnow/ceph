set (libcache_srcs
    ring.c
    init.c
    util.c
    btree.c
    bset.c
    extents.c
    alloc.c
    debug.c
    io.c
    journal.c
    libcache.c
    aio.c
    sync_io.c
    writeback.c
    movinggc.c
    )
set (spdk_libs_whole 
    spdk_bdev_malloc 
    spdk_bdev_null 
    spdk_bdev_nvme 
    spdk_nvme
    spdk_vbdev_error 
    spdk_vbdev_gpt 
    spdk_vbdev_lvol 
    spdk_vbdev_split
    spdk_blob 
    spdk_blob_bdev 
    spdk_lvol 
    spdk_bdev_aio 
    spdk_bdev_virtio
    spdk_virtio 
    )
    #aio 
set(spdk_libs
    spdk_util 
    spdk_bdev 
    spdk_conf 
    spdk_copy 
    spdk_rpc
    spdk_jsonrpc 
    spdk_json 
    spdk_log 
    spdk_env_dpdk 
   )
set(dpdk_libs_whole
    rte_eal 
    rte_mempool
    rte_ring 
    rte_mempool_ring 
    rte_pci 
    rte_bus_pci 
   )
    #numa 
    #dl 
    #rt 
    #uuid
    #)
#add_executable(go main.c alloc.c bset.c btree.c closure.c debug.c extents.c
    #io.c journal.c movinggc.c request.c super.c util.c writeback.c)
#add_executable(go ${libcache_srcs})
#target_link_libraries(go m pthread uuid blkid -Wl,--whole-archive

add_library(t2cache_objs OBJECT ${libcache_srcs})
#add_library(t2cache STATIC ${libcache_srcs})
#include_directories(/root/spdk/include)
#link_directories(/root/spdk/build/lib)
#link_directories(/root/spdk/dpdk/build/lib)
#target_link_libraries(go m pthread uuid blkid -Wl,--whole-archive
        #${spdk_libs_whole} -Wl,--no-whole-archive aio ${spdk_libs}
        #-Wl,--start-group -Wl,--whole-archive ${dpdk_libs_whole}
        #-Wl,--end-group -Wl,--no-whole-archive numa dl rt)
