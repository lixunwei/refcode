#ifndef __AUTO_FREE_H
#define __AUTO_FREE_H

#include <malloc.h>
#include <unistd.h>

#define autofree  __attribute__ ((cleanup(free_mem)))

static inline void free_mem(void* pmem)
{
    void** paddr = (void**) pmem;
    if (*paddr != NULL) {
        free(*paddr);
    }
}

#define autoclose __attribute__ ((cleanup(close_fd)))

static inline void close_fd(void* pfd)
{
    int *fd = (int *)pfd;

    if (*fd > 0) {
        close(*fd);
    }
}

#endif