cmake_minimum_required(VERSION 3.10)
project(MemcachedLib C)

set(CMAKE_C_STANDARD 99)

set(SRC
        assoc.h
        assoc.c
        hash.h
        hash.c
        items.h
        items.c
        jenkins_hash.h
        jenkins_hash.c
        memcached.h
        memcached.c
        murmur3_hash.h
        murmur3_hash.c
        protocol_binary.h
        slabs.h
        slabs.c
        stats.h
        stats.c
        thread.c
        trace.h
        util.h
        util.c

        main.c
        )


ADD_EXECUTABLE(MemcachedLib ${SRC} )

if(UNIX)
    TARGET_LINK_LIBRARIES(MemcachedLib dl)
endif()



TARGET_LINK_LIBRARIES(MemcachedLib pthread)