#!/bin/sh -x
git submodule update --init --recursive
if test -e build; then
    echo 'build dir already exists; rm -rf build and re-run'
    exit 1
fi

ARGS=""
if which ccache ; then
    echo "enabling ccache"
    ARGS="$ARGS -DWITH_CCACHE=ON"
fi

mkdir build
cd build

#cmake -DBOOST_J=$(nproc) $ARGS "$@" ..

# Use devel packages installed in system
cmake -DCMAKE_C_FLAGS="-O0 -g3 -gdwarf-4" \
      -DCMAKE_CXX_FLAGS="-O0 -g3 -gdwarf-4" \
      -DWITH_TESTS=OFF -DWITH_SYSTEM_BOOST=ON \
      -DWITH_SYSTEM_ROCKSDB=ON \
      -DALLOCATOR=tcmalloc_minimal \
      $ARGS "$@" ..

# Only build the specified target
#make ceph-osd ceph-mon ceph-mgr librados librbd rbd rados \
#     ceph-conf ceph-authtool monmaptool \
#     cython_rados cython_rbd

# minimal config to find plugins
cat <<EOF > ceph.conf
plugin dir = lib
erasure code dir = lib
EOF

# give vstart a (hopefully) unique mon port to start with
echo $(( RANDOM % 1000 + 40000 )) > .ceph_port

echo done.
