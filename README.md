# MemcachedLib
Used memcached as lib (based on memcached 1.4.28)
1. you can add source files to your project directly.
2. main.c is a test file, test the function of memcache.


#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include "memcached.h"

void memcachedTest()
{
    printf("Memcached Test starting!\n");
    memcached_init();
    printf("Memcached Test started!\n");

    char *value = "Value start... value End.";
    item *it = NULL;
    it = item_data_get("hello", 5);
    int iRst = item_data_set("hello", 5, 0, 3600, value, strlen(value));
    it = item_data_get("hello", 5);
    item_data_delete("hello", 5);
    it = item_data_get("hello", 5);

    memcached_destory();
}

int main() {
    memcachedTest();
    return 0;
}
