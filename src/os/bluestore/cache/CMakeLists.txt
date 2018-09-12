
set(libcache_srcs
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
  libaio.c
  sync_io.c
  writeback.c
  movinggc.c
  log.c
  delayed_work.c
  rbtree.c
  rte_ring.c
)

if (CACHE_TEST)
  configure_file(
    ${CMAKE_SOURCE_DIR}/src/include/config-h.in.cmake
    ${CMAKE_SOURCE_DIR}/acconfig.h
  )

  list(APPEND libcache_srcs
    test.c
    )
  add_executable(go ${libcache_srcs})
  add_definitions("-Wall -g")

  target_link_libraries(go m pthread uuid blkid aio event numa dl rt zlog urcu)
endif (CACHE_TEST)

add_library(t2cache_objs OBJECT ${libcache_srcs})
