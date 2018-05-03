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
        kfifo.c
    )

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
